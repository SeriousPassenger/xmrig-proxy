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

For Monero, the proxy also verifies that the daemon's original
`blockhashing_blob` matches the locally parsed template before deriving jobs.
An invalid reserve, failed CSPRNG call, inconsistent template, or unknown job ID
fails closed.

## Configuration

Use both a `daemon+http://` URL and `"daemon": true`; the URL supplies the
transport while the Boolean selects daemon client mode. The primary Monero
wallet address, rather than a subaddress, is recommended for
`getblocktemplate`.

```json
{
  "mode": "simple",
  "reuse-timeout": 0,
  "event-stream": {
    "enabled": true,
    "path": "/run/xmrig-proxy/events.sock"
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

`daemon-poll-interval` is the successful-template cache interval in
milliseconds. ZMQ remains an accelerator rather than a dependency: the first
template and periodic refreshes use HTTP RPC even while ZMQ is unavailable.
`daemon-job-timeout` bounds individual daemon HTTP requests.

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
schema_version,event_seq,time_utc,event,miner_id,mapper_id,miner_ip,listen_port,worker,agent,source_id,template_id,template_age_ms,refresh_reason,height,prev_hash,seed_hash,algo,job_id,entropy_hex,miner_target_diff,network_target_diff,share_id,miner_request_id,daemon_request_id,nonce,result_hash,share_diff,status,error_code,error_message,latency_ms,connection_ms,rx_bytes,tx_bytes
```

Events include:

- `worker_connected`, `worker_login`, and `worker_disconnected`;
- `template_refresh`, `template_cached`, `template_error`,
  `daemon_height_check`, `daemon_height_error`, and `zmq_new_block`;
- `job_sent`, `share_received`, and `share_result`; and
- `submit_block` and `submit_block_result`.

Empty CSV fields mean not applicable. Rows deliberately omit the upstream
daemon wallet/config, passwords, raw templates, secret keys, and full RPC
bodies. The `worker` column uses the downstream rig ID or falls back to that
downstream connection's login. `share_diff` is derived from the result hash
supplied by the miner; it is telemetry, not an independent RandomX
revalidation.

Schema version 2 adds `source_id`. It is a nonzero, process-unique identifier
for one shared daemon-template-source lifetime. Every miner using the same
live cache has the same `source_id`; if its last client disconnects and a new
source is later created, the new source receives a new ID. `template_id` and
`daemon_request_id` are counters local to a source and can restart at 1, so
use them together with `source_id`. Worker-only and ordinary pool rows leave
`source_id` empty.

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

The proxy serializes each row once and queues direct asynchronous libuv writes
to connected readers. There is intentionally no application-level queue limit
or drop policy. Therefore, do not leave a reader connected if it permanently
stops consuming data.

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
restart; config hot reload does not move the listening Unix socket.

## Expected validation

When the first daemon-backed miner connects, one `template_refresh` with reason
`initial` should be followed by one `template_cached`. Connecting more miners
should create distinct `job_id` and `entropy_hex` values without additional
daemon template requests. After the configured interval, one timer refresh
should occur for the shared source. A new Monero block should produce
`zmq_new_block`, an immediate height check (with bounded 100 ms retries while
RPC catches up), and then a template refresh.

Correlate a candidate through `share_id`, `job_id`, (`source_id`,
`template_id`), and (`source_id`, `daemon_request_id`): `share_received` ->
`submit_block` -> `submit_block_result` -> `share_result`.

Downstream usernames and rig IDs are labels, not routing keys. Multiple
connections may use the same values without sharing private jobs or entropy;
reports that group by `worker` will intentionally aggregate them. Use
different rig IDs only when you want separate worker rows in those reports.
