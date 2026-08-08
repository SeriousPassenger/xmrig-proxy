# Cached daemon mining in simple mode

This branch keeps XMRig Proxy's downstream `simple` mode while sharing one
Monero daemon template source between all downstream miners. It is intended for
the following topology:

```text
miners -> XMRig Proxy -> monerod HTTP RPC
                         monerod ZMQ PUB
```

The shared source requests one base template when the first daemon-backed miner
connects and then refreshes it:

- after `daemon-poll-interval` milliseconds from the last successful refresh;
- through an immediate `/getheight`-gated refresh sequence when
  `json-minimal-chain_main` arrives on the configured ZMQ PUB socket; and
- after a short retry when the daemon RPC is temporarily unavailable.

Concurrent refresh triggers are coalesced. A pool identity, expanded wallet,
daemon address, TLS settings, ZMQ port, and timing settings form the cache key,
so unlike configurations never share a template source.

## Per-job entropy and submission correctness

Every `getblocktemplate` request reserves exactly 16 bytes in the miner
transaction's extra nonce. There is no ASCII marker or fixed prefix. For each
job sent to a downstream miner, the proxy:

1. obtains a fresh 16-byte value from libuv's operating-system CSPRNG;
2. replaces the complete reserved field without changing its length;
3. reparses the modified full block template and recomputes its coinbase hash,
   Merkle root, and hashing blob; and
4. assigns a separate random 16-byte job ID.

The exact modified full template is retained with its job ID. A block candidate
is reconstructed from that same template and the submitted header nonce, not
from the newest cached template. The current job and five prior jobs are kept,
with a 120-second maximum age for prior jobs, so an in-flight result can still
be submitted across a refresh.

Before submission, the proxy also computes and retains the candidate's
consensus block ID from the exact finalized full block. A well-formed
`submitblock` rejection is final and is never retried. A transport failure,
non-200 HTTP response, malformed JSON, mismatched RPC ID, or invalid/mismatched
returned block ID is indeterminate instead: the proxy immediately makes one
identical bounded retry, then queries `get_block_header_by_hash` for its locally
computed block ID if the outcome is still unclear. Finding that exact ID
converts a lost response (including an already-exists rejection from the
retry) into one accepted result. If the read-only lookup cannot establish
acceptance, an explicit retry rejection plus an authoritative not-found lookup
is reported as rejected. Every other unresolved case is explicitly
`ambiguous`, not falsely reported as a consensus rejection. The miner receives
exactly one final response while its route remains live; ambiguous daemon
transport does not count as a rejected-share strike or alter accepted/rejected
hash statistics.

This is deliberately not an unbounded delivery queue or a submission journal.
The finalized block exists in the live telemetry row for external diagnosis,
but pending state is process memory and is discarded on shutdown. An
unavailable reconciliation RPC after both submit attempts therefore remains
ambiguous and requires operator review.

If a live daemon client disconnects or a failover replaces it while a submit is
in flight, each accepted downstream request receives one final ambiguous
response before its weak HTTP callbacks are cancelled. If the client object
itself is already being destroyed with its listener graph, callback is unsafe;
the event stream still emits one final ambiguous `submit_block_result` before
dropping the in-memory state. Operators should treat that destruction-only row
as an explicit coverage boundary.

The bounded paths to exercise in a fault-injection test are:

| First submit | Retry | Block-ID lookup | Final result |
| --- | --- | --- | --- |
| explicit RPC/status rejection | not sent | not sent | rejected |
| transport/protocol ambiguity | accepted with expected ID | not sent | accepted |
| transport/protocol ambiguity | explicit rejection | expected ID found | accepted (reconciled) |
| transport/protocol ambiguity | explicit rejection | authoritative not found | rejected |
| transport/protocol ambiguity | ambiguous | unavailable/not found | ambiguous |

For Monero, the proxy also verifies that the daemon's original
`blockhashing_blob` matches the locally parsed template before deriving jobs.
An invalid reserve, failed CSPRNG call, inconsistent template, or unknown job ID
fails closed.

## Configuration

Use both a `daemon+http://` URL and `"daemon": true`; the URL supplies the
transport while the Boolean selects daemon client mode. Every enabled daemon
pool must provide a recognized primary CryptoNote payout address. Startup
performs a full Base58/checksum/prefix decode after environment expansion,
requires the address coin to match an explicitly configured pool coin, and
rejects integrated addresses, subaddresses, unknown prefixes, and malformed
checksums before any listener is opened. Each distinct validated public payout
is printed as `Solo Mining with Daemon to Address: ...` at startup.

```json
{
  "mode": "simple",
  "watch": false,
  "donate-level": 0,
  "reuse-timeout": 0,
  "event-stream": {
    "enabled": true,
    "path": "/run/xmrig-proxy/events.sock"
  },
  "randomx-verifier": {
    "enabled": true,
    "path": "/run/xmrig-randomx-verifier/verifier.sock",
    "timeout-ms": 5000,
    "max-queue": 256,
    "max-pending-per-miner": 8,
    "max-consecutive-rejections": 8,
    "candidate-max-per-minute": 12,
    "candidate-global-max-per-minute": 48,
    "candidate-emergency-max-per-minute": 4
  },
  "pools": [
    {
      "algo": null,
      "coin": "monero",
      "url": "daemon+http://10.110.0.3:18081",
      "user": "PRIMARY_MONERO_WALLET_ADDRESS",
      "enabled": true,
      "tls": false,
      "daemon": true,
      "daemon-poll-interval": 20000,
      "daemon-job-timeout": 15000,
      "daemon-zmq-port": 18083
    }
  ]
}
```

Runtime configuration reload is completely disabled in this proxy build.
`watch: true` is a startup error, filesystem watching is never installed, and
POST/PUT requests to the config API are rejected. Apply every configuration,
payout, verifier, or event-socket change with a clean proxy restart. When an
explicit `--config`/`-c` file fails validation, the process exits instead of
falling through to a different config file.

The summary API reports the stored startup-validated values without reparsing
configuration input:

```json
{
  "daemon_solo": {
    "enabled": true,
    "payouts": [
      {
        "address": "4...",
        "coin": "XMR",
        "network": "mainnet",
        "type": "primary",
        "validated": true
      }
    ]
  }
}
```

`daemon-poll-interval` is the successful-template cache interval in
milliseconds. ZMQ remains an accelerator rather than a dependency: the first
template and periodic refreshes use HTTP RPC even while ZMQ is unavailable.
`daemon-job-timeout` bounds individual daemon HTTP requests.

## RandomX share verifier

When `randomx-verifier.enabled` is true, locally handled RandomX shares are
accepted or rejected using a hash computed by the separate full-memory
verifier service. The proxy retains the exact hashing blob sent with every
job, inserts the submitted nonce into an owned copy, sends that blob together
with its exact seed hash over a framed Unix socket, compares all 32 computed
hash bytes with the miner's claim, and derives difficulty from the computed
hash. Only that verified result can update local share/hashrate statistics.

Verifier-enabled startup is intentionally restricted to `mode: "simple"`,
`donate-level: 0`, and enabled upstreams that are all Monero `rx/0` daemon
pools. Mixed, ordinary-pool, and donation configurations are rejected instead
of silently falling back to unverified local acceptance.

The service must advertise protocol v1, fast mode, no light-mode fallback, and
the `prepare_seed`, `release_seed`, and `verify` capabilities. The proxy asks it
to prepare both `seed_hash` and `next_seed_hash`. Current, next, and previous
seed contexts can therefore overlap, while seeds unused for 120 seconds are
released. The newest daemon snapshot is held until its current seed is ready;
miners are never given a job that cannot yet be verified.

`max-queue` bounds all outstanding verification requests and
`max-pending-per-miner` prevents one connection from consuming the complete
queue. A disconnected, unready, timed-out, malformed, full, or wrong-mode
verifier fails closed. `max-consecutive-rejections` closes only the offending
miner connection after that many consecutive rejected shares; `0` disables
that connection-local strike limit. It never bans an IP, and another
connection using the same username, rig ID, or address is unaffected.
Verifier transport, timeout, readiness, and queue-admission failures are
infrastructure failures: their rejected shares may be retried and do not add a
miner rejection strike or rejected-share statistic. To keep an unready
sidecar/daemon from becoming an unlimited public-port response loop, a separate
connection-local infrastructure streak closes that one socket after 16 such
failures; a successfully admitted verifier/daemon request or accepted share
resets it. This state is never keyed by or applied to an IP. Cryptographic
mismatches, low-difficulty results, duplicates, and the bounded candidate-abuse
rejections do add connection-local strikes.

`candidate-max-per-minute` is scoped to one miner connection and
`candidate-global-max-per-minute` bounds the process-wide direct-candidate
path without using miner IP addresses. The verifier reserves a few bounded
queue slots for over-budget candidate claims. If candidate verification cannot
be admitted or fails after admission, `candidate-emergency-max-per-minute`
bounds the process-wide last-resort direct submissions to monerod, with at most
one emergency submission per miner connection per minute; exhausted claims are
rejected and count toward that connection's rejection strikes.
Set all three candidate limits to `0` for unlimited regtest
candidates. A syntactically valid share whose claimed difficulty meets the
network target and is within both budgets is submitted to monerod immediately;
RandomX verification does not delay that normal `submitblock` path. An
over-budget claim is hashed by the verifier instead of being discarded, and a
computed network candidate is still submitted even if the miner's claimed
hash was wrong. If that protective verification cannot be admitted, the proxy
prefers a direct monerod submission while the bounded emergency budget has
capacity; after that budget is exhausted it rejects further claims instead of
allowing unbounded RPC growth. Monerod remains the consensus authority. Claims
below the network target always take the verifier path. The immediate
candidate path retains the miner-reported result hash and difficulty in
telemetry. Daemon acceptance proves the finalized block and nonce satisfy
consensus, but does not independently prove that separate claimed hash value;
credited work must use the assigned miner target.

When verification is enabled, a downstream `user+difficulty` suffix cannot
lower the configured `custom-diff`; harder suffixes remain supported. If no
custom difficulty is configured, suffix overrides are ignored in verifier
mode so the public Stratum endpoint cannot be used as a low-difficulty hashing
oracle.

Verifier configuration cannot be hot reloaded. Enabling, disabling, or changing
the verifier always requires a clean proxy restart, preventing an in-process
configuration transition from reopening claimed-hash local acceptance.

With daemon-derived jobs, connection reuse is disabled internally because a
new miner connection must receive independently generated entropy. Setting
`reuse-timeout` to zero is still recommended so the deployment's intent is
explicit.

## Unix CSV event stream

The optional event stream is a local Unix `SOCK_STREAM` socket. It never writes
an event log, retains no history, and performs no replay. A new reader receives
the CSV header and future events only. Up to five readers may be connected;
the sixth is closed. The socket is output-only, and a reader that writes to it
is disconnected.

The fixed schema is:

```csv
schema_version,event_seq,time_utc,event,miner_id,mapper_id,miner_ip,listen_port,worker,agent,source_id,template_id,template_age_ms,refresh_reason,height,prev_hash,seed_hash,algo,job_id,entropy_hex,miner_target_diff,network_target_diff,share_id,miner_request_id,daemon_request_id,nonce,result_hash,share_diff,status,error_code,error_message,latency_ms,connection_ms,rx_bytes,tx_bytes,stream_id,previous_seed_hash,next_seed_hash,hashing_blob,blocktemplate_blob,submitted_block_blob,miner_target_hex,nonce_offset,nonce_size,reserved_offset,reserved_size,extra_nonce_offset,extra_nonce,signature_hex,view_tag,block_id,miner_tx_hash,verifier_queue_ms,verifier_hash_ms,verifier_total_ms,verifier_prepare_ms,verifier_active,verifier_queued,verifier_queue_limit,verifier_seed_count,verifier_seed_capacity,verifier_seed_role,verifier_seed_status,verifier_vm_pool_size,verifier_stats_json
```

Events include:

- `worker_connected`, `worker_login`, and `worker_disconnected`;
- `template_refresh`, `template_cached`, `template_error`,
  `template_derived`, `daemon_height_check`, `daemon_height_error`, and
  `daemon_tip_changed`, and `zmq_new_block`;
- `verifier_seed_prepare`, `verifier_seed_ready`, `verifier_seed_error`, and
  `verifier_seed_release`, plus `verifier_seed_roles` and `verifier_status`;
- `job_sent`, `share_received`, `verify_requested`, `verify_result`,
  `verify_error`, `verify_mismatch`, `candidate_verify_fallback`, and
  `share_result`; and
- `submit_block`, `submit_block_attempt`, `submit_block_retry`,
  `submit_block_reconcile`, and `submit_block_result`.

Empty CSV fields mean not applicable. Schema v3 intentionally carries the
daemon's cached base template, the entropy and offsets needed to reconstruct
each derived private template, the exact hashing blob and target sent to a
miner, and the exact final block passed to `submitblock`. The initial
`submit_block` and final `submit_block_result` rows carry the submitted block
blob; interim attempt, retry, and reconciliation rows omit that redundant large
field. Byte offsets are relative to the decoded binary blob, not its
hexadecimal text. `submit_block.miner_tx_hash` identifies the finalized
coinbase transaction, and an accepted response supplies `block_id`.
`submit_block.block_id` is the locally computed expected consensus ID. Retry
and reconciliation events carry their own active daemon request IDs, while the
eventual `share_result` retains the original logical submission ID. Correlate
across that re-keying with `share_id`, `job_id`, `source_id`, and `block_id`.
The single final `submit_block_result` is `accepted`, `rejected`, or
`ambiguous`; a following `share_result` uses `ambiguous_upstream` for the last
case so uncertainty is not counted as a definite rejection. Reconciled
acceptance retains status `accepted` and explains the reconciliation in
`error_message` so persistent round tracking closes exactly once.

This reconstruction data contains public block/job material only. The stream
still omits the daemon wallet/config, passwords, RPC authentication, and all
secret spend, view, derived, and miner-signature keys. In particular, the
internal signature data used to construct signed miner transactions must never
be added to telemetry. The `worker` column uses the downstream rig ID or falls
back to that connection's login. `share_received.share_diff` describes the
miner's claim. With the verifier enabled, `verify_result.share_diff` and the
eventual accepted `share_result.share_diff` are derived from the independently
computed hash.

The `verifier_seed_*` rows describe process-global verifier context lifecycle,
not one miner or daemon-template-source instance. Their `source_id` may
therefore be empty; correlate those rows by the full `seed_hash` instead.
Ready and timeout rows include the observed control-request latency when it is
available. Per-share verifier rows also include the sidecar's queue, hash, and
total time. `verifier_status` is sampled every five seconds and includes a
compact `verifier_stats_json` object with service, scheduler, seed, counter,
timing, and engine state. Previous/current/next seed hashes and seed roles are
also emitted as ordinary columns for simple consumers.

Schema version 2 added `source_id`. It is a nonzero, process-unique identifier
for one shared daemon-template-source lifetime. Every miner using the same
live cache has the same `source_id`; if its last client disconnects and a new
source is later created, the new source receives a new ID. `template_id` and
`daemon_request_id` are counters local to a source and can restart at 1, so
use them together with `source_id`. Worker-only and ordinary pool rows leave
`source_id` empty.

Schema version 3 appends the reconstruction and verifier fields without
reordering any version-2 column. It also adds `stream_id`, a fresh random
128-bit process-lifetime identifier repeated on every row. The durable identity
of a v3 event is `(stream_id,event_seq)`; `event_seq` alone restarts with the
proxy. Sequence numbers advance for logical events even while no subscriber is
connected, allowing a reconnecting collector to detect lost coverage (there is
still no replay). The event stream refuses to start if secure stream-ID
generation fails.

`worker_login` is emitted before any warm-cache `job_sent` row for that miner.
Only the telemetry row is held until login dispatch completes; the actual
Stratum job is sent immediately.

Read the stream with either command:

```bash
socat - UNIX-CONNECT:/run/xmrig-proxy/events.sock
nc -U /run/xmrig-proxy/events.sock
```

To save it explicitly, redirect the reader yourself:

```bash
socat - UNIX-CONNECT:/run/xmrig-proxy/events.sock >shares.csv
```

### Local web dashboard

The separate dependency-free tool in `extras/event-dashboard/` consumes one
schema-v2 or schema-v3 socket connection and serves a read-only, scrollable
dashboard on `127.0.0.1`. It includes event filtering and structured details,
daemon-template and verifier health, persistent rounds and credited work,
large/top shares, successful block submissions, and historical effort:

```bash
python3 extras/event-dashboard/xmrig_events_web.py \
  /run/xmrig-proxy/events.sock \
  --port 8787 \
  --database /var/lib/xmrig-proxy/dashboard.sqlite3
```

It can also poll the loopback XMRig Proxy API for hashrate, results, resources,
upstreams, and worker statistics. The bearer token is read from an environment
variable or a protected file, stays in the Python backend, and is never sent
to the browser. The dashboard deliberately never calls `/1/miners`, because
that endpoint includes downstream passwords.

See `extras/event-dashboard/README.md` for API setup, SQLite retention and
round semantics, SSH local forwarding, coverage semantics, and tests. The
proxy socket itself still has no replay. The dashboard marks coverage gaps
instead of inventing missing work, while its SQLite store preserves accepted
work and configured round/share/block history across restarts. Use a separate
socket subscriber such as the `socat` command above when a complete raw CSV
capture is required.

The proxy serializes each row once and queues direct asynchronous libuv writes
to connected readers. Mining never waits for a reader. Each reader has an
independent 8 MiB pending-output ceiling; only a subscriber that exceeds it is
disconnected, and the condition is written to the normal proxy log.

### systemd runtime directory

The proxy does not create the socket's parent directory. For a systemd service,
add these settings to its `[Service]` section:

```ini
RuntimeDirectory=xmrig-proxy
RuntimeDirectoryMode=0750
```

The socket is created as mode `0660` and inherits the service process group.
Run the reader as that service user or add the reader account to that group.
The proxy refuses to replace a non-socket, symlink, or active socket at the
configured path and removes only the socket inode it created.

Changing `event-stream.enabled` or `event-stream.path` requires a service
restart, as does every other configuration change.

## Expected validation

When the first daemon-backed miner connects, one `template_refresh` with reason
`initial` should be followed by one `template_cached`. Connecting more miners
should create distinct `job_id` and `entropy_hex` values without additional
daemon template requests. After the configured interval, one timer refresh
should occur for the shared source. A new Monero block should produce
`zmq_new_block`, an immediate height check (with bounded 100 ms retries while
RPC catches up), and then a template refresh.

Staleness is intentionally a per-miner delivery rule with one exact predicate:
`latest_successfully_sent_height > submitted_job_height`. A ZMQ notification,
height check, cached template, or a job that failed to write to that miner does
not invalidate its retained work. A same-height timer refresh, transaction-set
change, or parent replacement therefore remains eligible; ordinary shares are
verified against their exact issued blob and a network candidate reaches the
bounded monerod submission path. Once that miner successfully receives a job
at a higher height, its retained lower-height jobs are classified as
`Stale share` before verifier or submit-block work. The strict greater-than
comparison also avoids falsely staling a retained higher-height job during a
downward reorganization.

Daemon-job duplicate detection is process-wide and connection-independent.
The canonical key is the job's private 16-byte template entropy followed by
the submitted 32-byte PoW result, decoded from hex so text casing cannot evade
comparison. The key lookup is global across every live connection and daemon
source; source and height only partition lifecycle cleanup. Verifier-backed
acceptance still requires the independently computed result to match the
submission. On a mismatch, the computed entropy-plus-result identity is also
retained, preventing the same actual work from being replayed with changing
false claims.

Same-height template changes preserve the bounded in-memory set. When an
installed source template advances height, miners that successfully received
the replacement rebuild their eligible bucket references from their retained
job history. A non-current bucket is retained only while at least one connected
miner can still submit a non-stale job at that height—normally a miner that has
not received the higher job, or the rare higher retained job after a downward
reorganization. The existing six-job/120-second bounds still apply. The bucket
is erased as soon as its final eligible miner advances or disconnects; expired
references are removed on the next successful job-history rebuild (normally
the next template poll). No duplicate state is keyed by IP, username, rig ID,
or connection lifetime.

Correlate a candidate through `share_id`, `job_id`, (`source_id`,
`template_id`), and (`source_id`, `daemon_request_id`): `share_received` ->
`submit_block` -> `submit_block_result` -> `share_result`.

Downstream usernames and rig IDs are labels, not routing keys. Multiple
connections may use the same values without sharing private jobs or entropy;
reports that group by `worker` will intentionally aggregate them. Use
different rig IDs only when you want separate worker rows in those reports.
