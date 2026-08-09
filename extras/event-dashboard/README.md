# XMRig Proxy event dashboard

This is a separate, dependency-free Python 3 observer. It does not modify or
control XMRig Proxy. It consumes one schema-v2 or schema-v3 Unix event-stream
connection, persists production statistics in SQLite, and serves a read-only,
scrollable dashboard on `127.0.0.1`.

The dashboard provides:

- an IndexedDB-backed event timeline with search, category filters,
  exact-connection tracing, an exact minimum-share-difficulty filter,
  connection UUIDs, full row details, and ordered multi-row JSON copying;
- daemon template-source height, age, refresh reason, error state, and
  process-global RandomX verifier seed lifecycle;
- worker connection, job, share, and block-submission events;
- the top five observed accepted shares with their exact event times and
  reported share difficulties (independently verifier-computed for the normal
  below-network local-share path when verification is enabled);
- optional XMRig Proxy HTTP API hashrate, result, resource, upstream, and
  per-worker statistics, with rates auto-scaled from H/s through TH/s and the
  exact raw API kH/s value preserved in tooltips/details, plus validated
  daemon-solo payout destinations exposed by the summary API;
- optional authenticated Monero wallet RPC polling that shows and durably
  records confirmed coinbase/block-reward transfers only;
- persistent rounds, exact credited work, difficulty-normalized effort,
  successful block submissions, every 20G+ share, and the top 1,000 shares in
  each round; and
- RandomX verifier request/error/mismatch totals, queue/hash/total latency,
  live capacity, and previous/current/next seed state.

Template-source age remains healthy through 40 seconds, becomes a warning after
40 seconds, and becomes an error only after 80 seconds (two missed 40-second
poll windows).

## Run it

Socket-only mode:

```bash
python3 extras/event-dashboard/xmrig_events_web.py \
  /run/xmrig-proxy/events.sock \
  --port 8787 \
  --database /var/lib/xmrig-proxy/dashboard.sqlite3
```

The database parent directory must already exist, be owned by root or the
dashboard service account, and must not be writable by group/others. The
database file is created or tightened to mode `0600`; symlinks, path replacement,
and non-regular files are rejected. If `--database` is
omitted, `xmrig-events.sqlite3` in the current working directory is used. Use
`--no-database` only for an intentionally non-persistent viewer.

The HTTP listener is hard-coded to `127.0.0.1`; there is no option to expose it
on a public interface.

This proxy build disables configuration hot reload. Restart the proxy to apply
mining/configuration changes; the dashboard remains a read-only observer and
cannot trigger a reload.

To include the XMRig Proxy API, keep that API on loopback and supply its bearer
token to the dashboard backend. Avoid putting the token directly in a command
line. For an interactive run:

```bash
read -rsp 'XMRig Proxy API token: ' XMRIG_PROXY_API_TOKEN
echo
export XMRIG_PROXY_API_TOKEN

python3 extras/event-dashboard/xmrig_events_web.py \
  /run/xmrig-proxy/events.sock \
  --port 8787 \
  --database /var/lib/xmrig-proxy/dashboard.sqlite3 \
  --api-url http://127.0.0.1:8080

unset XMRIG_PROXY_API_TOKEN
```

Alternatively, put only the token in a protected file and use
`--api-token-file`. The tool rejects symlinks and files accessible by group or
other users:

```bash
chmod 600 /etc/xmrig-proxy/dashboard-api-token

python3 extras/event-dashboard/xmrig_events_web.py \
  /run/xmrig-proxy/events.sock \
  --database /var/lib/xmrig-proxy/dashboard.sqlite3 \
  --api-url http://127.0.0.1:8080 \
  --api-token-file /etc/xmrig-proxy/dashboard-api-token
```

The default API interval is five seconds because the proxy's hashrate and
worker buckets update every four seconds. The dashboard requests only
`/1/summary` and `/1/workers`. It deliberately never requests `/1/miners`,
which exposes downstream login and password fields. Each workers sample is
bracketed by two summaries so a proxy restart during the sample is detected
instead of combining counters from different process epochs.

To include view-only wallet mining rewards, supply both the local wallet RPC
endpoint and its `--rpc-login` value. If either argument is absent, the
dashboard does not create a wallet RPC connection:

```bash
python3 extras/event-dashboard/xmrig_events_web.py \
  /run/xmrig-proxy/events.sock \
  --database /var/lib/xmrig-proxy/dashboard.sqlite3 \
  --wallet-rpc-url http://127.0.0.1:18082/json_rpc \
  --wallet-rpc-login 'USER:PASS'
```

The default wallet interval is 20 seconds. Every `get_transfers` poll creates
one fresh TCP connection, receives its Digest challenge, sends the authenticated
JSON-RPC request on that same connection, and then closes it. Challenge nonces
and authentication state are never reused between connections or polls. Only
incoming transfers whose wallet RPC `type` is `block` are allowlisted. Ordinary
incoming payments,
outgoing, pool, pending, and failed transfers are neither sent to the browser
nor stored. The sanitized transaction ID, atomic reward, height, block time,
confirmations, lock state, and account/subaddress indexes are upserted into the
`wallet_transfers` SQLite table. The login remains backend-only and is never
placed in HTML, SSE state, SQLite, or logs. See Monero's
[wallet RPC documentation](https://www.getmonero.org/resources/developer-guides/wallet-rpc.html#get_transfers)
for the upstream JSON-RPC fields.

## Open it through SSH

From the laptop that will display the dashboard, create a local port forward:

```bash
ssh -N -L 8787:127.0.0.1:8787 root@PROXY_HOST
```

Then open <http://127.0.0.1:8787/> on the laptop. This is SSH local forwarding
(`-L`): the dashboard remains bound to loopback on the proxy machine.

For local supervision, `GET /healthz` is a process-liveness check and always
returns HTTP 200 while the web process is running. `GET /readyz` returns HTTP
200 only while a clean supported Unix-socket session is connected; it returns
HTTP 503 while waiting, disconnected, or degraded.

## Persistent statistics and rounds

The first database launch establishes an explicit `tracking_since` boundary.
Existing proxy/API counters are a baseline only and are **not** imported as
historical work. This avoids presenting an unverifiable partial round as
complete. The initialization round is visibly marked partial and excluded from
average-round effort; the first accepted block establishes the first complete
round boundary.

For each independently accepted share the store keeps two different values:

- **credited hashes** add the assigned `miner_target_diff`, which is the normal
  statistical estimate of attempted hashes; and
- **observed share difficulty** records the verifier-computed hit difficulty
  for ranking and audit. It is not used as credited work.

Canonical round effort is the sum of
`miner_target_diff / network_target_diff` for every accepted share. This remains
correct when the network difficulty changes inside a round. The UI expresses
that sum as a percentage. Average effort is the arithmetic average of completed,
coverage-complete round percentages.

An accepted `submit_block_result` is saved immediately. The round closes only
after the correlated `share_result:accepted_upstream` has credited the winning
share; a fresh round then begins. Later orphan status does not reopen the round.
The initial submit and any ordered retry attempts are correlated by
stable stream/source/share/job/template identity rather than the changing daemon
RPC request ID. If the dashboard restarts after the accepted block result but
before the winning share is durably credited, that round is closed as incomplete
instead of leaking later work into it.
The dashboard keeps every share at or above `--big-share-diff` (20G by default)
and the highest `--round-top-shares` shares (1,000 by default) per round. Each
retained share keeps a normalized reference to its canonical `template_cached`
base template and freezes its small, miner-specific
`template_derived`/`job_sent` audit context at acceptance, including the safe
exact blobs and offsets needed for later manual reconstruction. Freezing the
job context prevents mapper reuse from rewriting a past share's issued target,
while still avoiding duplication of the large base template for every miner
job or retained share. Unreferenced template/job contexts are bounded by both
record count and 64 MiB byte budgets; contexts referenced by retained top/big
shares remain durable. No signature-data/private-key material is emitted or
stored.

SQLite runs in WAL mode behind a bounded single-writer queue (4,096 rows and
32 MiB). Socket ingestion
and HTTP rendering never perform a database write. Exact v3 event identity is
`(stream_id,event_seq)`, so reconnects and dashboard restarts do not double
credit work. A v2 capture remains viewable, but lacks the durable `stream_id`
needed to prove cross-process completeness and is marked incomplete.

`GET /api/round?id=N` returns a selected round with its retained top-share
summaries and complete successful block request/attempt/result audit records.
`GET /api/share?key=...` loads one retained share with its reconstruction
context. The browser calls these only on selection, avoiding repeated
transmission of large block/template blobs on the live SSE stream. The round-ID
lookup in the web UI can open any retained historical round, not only the 50
most recent rounds shown in the overview table.

## API interpretation

- The top-share and `observed_diff_sum` fields are audit/leaderboard values,
  not credited work. A normal `accepted_local` difficulty is computed by the
  RandomX verifier. A candidate whose miner-claimed result already meets the
  network target is deliberately sent straight to monerod; daemon acceptance
  proves the finalized block and nonce satisfy consensus, but does not prove
  the miner's separate claimed result hash or its exact reported difficulty.
  Credited hashes and round effort remain safe because they use the assigned
  miner target, never the reported share difficulty.
- XMRig Proxy API hashrate values arrive in **kH/s**. The dashboard converts
  once and automatically displays H/s, kH/s, MH/s, GH/s, or TH/s; hover a
  displayed rate (or inspect its JSON) for the exact raw kH/s value.
- With `custom-diff-stats=true`, local custom-difficulty accepts contribute to
  API and worker hashrate estimates.
- API `results.accepted` counts upstream outcomes, not locally accepted custom
  shares. The event-stream counters show local and upstream outcomes
  separately.
- Worker records are grouped by the configured worker mode. Equal usernames or
  rig IDs may intentionally appear as one worker group even though mining jobs
  remain isolated per connection. Names are shown only for the known-safe
  `rig_id`, `user`, `agent`, and `ip` modes. Password names are redacted, and
  unknown/disabled modes are treated as unavailable for persistent accounting
  rather than silently credited as zero.
- `/1/summary` `hashes_total` does not include the locally accepted custom-diff
  work needed here. With one of the known-safe worker modes, the persistent API
  cross-check therefore sums every `/1/workers` credited-hash counter (the
  browser table alone is capped at 10,000 rows). Its first
  sample is a zero-work baseline, and later samples add deltas across proxy
  restarts. Polling cannot recover work performed in the previous process after
  its final sample, so a detected restart or mixed-epoch summary/workers poll
  marks API coverage incomplete. The event-derived credited total remains
  separate so a coverage gap or reconciliation difference is visible rather
  than silently combined.

The API bearer token and wallet RPC login exist only in the Python backend's
memory. They are not included in browser responses, events, SQLite, logs, or
the dashboard page.

## Connection correlation and JSON copying

Every timeline event with a `miner_id` receives a dashboard-derived
`connection_uuid`. For schema v3, it is a deterministic UUIDv5 derived from the
proxy's random process-lifetime `stream_id` and that process's connection-local
`miner_id`. It therefore stays identical for every event from one miner
connection, including across dashboard socket reconnects or dashboard process
restarts, while a new proxy process or new miner connection receives a different
UUID. This is dashboard metadata, not an extra event-stream column. For legacy
schema v2 input, which has no durable stream identity, the fallback UUID is
deliberately limited to one observed dashboard socket session so reused miner
IDs are never silently merged.

The existing `miner_id`/`mapper_id` display is also materialized as a
`miner_label` such as `m13/p23`. This makes the exact composite shown in the
timeline searchable and includes it in copied JSON without changing the proxy
event schema.

Clicking a timeline row still opens that one row in the JSON inspector, whose
**Copy JSON** button copies a single JSON object. Use the row checkboxes (or the
header checkbox for all currently visible rows) and **Copy selected JSON** to
copy multiple complete rows as one valid JSON array. Selected rows are emitted
in timeline order, independent of the order in which their checkboxes were
clicked. Filtering and page reloads do not discard selections. **Follow
connection** filters the timeline by the selected row's exact
`connection_uuid`; it never uses a mutable mapper ID or potentially shared
worker label. The minimum share difficulty control compares decimal strings
with JavaScript `BigInt`, preserving exact values above the safe integer range.
The filtered renderer walks newest rows first and stops after 1,000 matches
instead of serializing every retained row into the DOM.

The browser retains approximately 50,000 ordinary compact event rows (subject
to a quota-derived byte budget) in IndexedDB and automatically prunes only the
oldest unselected ordinary rows in batches. Selected rows are pinned and are
never removed by automatic pruning. The cap applies to ordinary, unselected
history; explicit selections and error archives are exceptions.

A rejected share/result, an exact stale-share outcome, or a real error/fatal/
retryable-error event starts a permanent incident archive containing up to 100
first-seen rows before it, the trigger row, and the next 100 first-seen rows.
Thus a fully observed isolated incident contains 201 rows. Overlapping windows
deduplicate by stable event key. Periodic warning/degraded telemetry and
accepted rows that merely carry explanatory error text do not create archive
storms. The **Errors archive** category shows trigger and context rows, marked
with an amber edge. Ordinary pruning and **Clear normal history** cannot delete
them; only the separately confirmed **Clear errors** action does. A storage
quota failure is made visible rather than silently claiming the archive is
durable. **Clear errors** deliberately removes every archived context row and
any selection attached to one of those rows.

Schema-v3 browser-history keys use the exact `(stream_id,event_seq)` event
identity. Viewer-generated and legacy schema-v2 rows use the dashboard's random
process-lifetime `viewer_instance_id` plus `_viewer_seq`, preventing a dashboard
restart from attaching an old selection to an unrelated replacement row. The
browser-only ordering/search metadata is non-enumerable and is not included in
the JSON copied for debugging. Durable per-viewer and per-stream sequence
high-water marks prevent automatically pruned rows from being re-ingested on a
later snapshot. If a reconnect skips sequence numbers, an open incident window
is marked incomplete and stopped instead of filling its 100-row after-context
with unrelated later events.

A short IndexedDB writer lease prevents two tabs from racing selection,
archive, and clear transactions. Every mutation verifies the lease owner,
per-page token, and monotonic generation in the same transaction; a stale or
suspended page therefore cannot write after a new owner takes over. A normal
same-tab refresh can reclaim its lease immediately, while a second simultaneous
tab remains visibly memory-only. If IndexedDB is unavailable or reaches its
browser quota, the dashboard remains live in memory, disables persistent clear
actions, and reports the storage failure in the `history` badge. The SSE
connection opens before history hydration, so events received while retained
rows are loading are buffered and merged in arrival order.

## Coverage and memory bounds

The proxy stream has no replay. Live-memory counters cover only events observed
since this dashboard process attached. Persistent v3 statistics survive
dashboard and proxy restarts, but a dashboard restart conservatively marks the
active round/global event coverage incomplete because detached work cannot be
replayed. A first sequence above one, later event-sequence gap, parser error,
ingestion row/byte queue overflow, or ambiguous API counter decrease likewise
marks coverage incomplete instead of fabricating missing work.

The Python SSE snapshot defaults to at most 5,000 compact rows **and** a 16 MiB
byte budget. Each browser merges that snapshot into its IndexedDB-backed
50,000-row history and renders at most the latest 1,000 filtered rows. Full
hashing/template/submission blobs are replaced in the live ring/SSE with exact
omitted-size metadata and remain available from the
normalized retained-share/block audit views. Schema-v3 input records may be up
to 8 MiB, matching the producer's per-reader pending-write limit. Change the
backend row-count bound with `--max-events`. The
leaderboard retains only the configured number of top shares. A stalled browser
subscriber is disconnected rather than allowed to grow an unbounded queue, and
at most five browser event streams may be connected at once. SQLite retains
only the configured per-round top set plus threshold shares, rather than every
ordinary share forever. The pending submission audit is capped at 256 entries
and 64 MiB; its exact final block blob is normalized to one copy across ordered
submit attempt and retry rows. Rejected or ambiguous block outcomes are capped by
both count and a 64 MiB budget, while accepted block records remain durable.

## Test

```bash
python3 -m unittest -v \
  extras/event-dashboard/test_xmrig_events_web.py
```

The tests use fake socket chunks and do not need a running proxy or network
listener.
