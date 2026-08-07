# XMRig Proxy event dashboard

This is a separate, dependency-free Python 3 observer. It does not modify or
control XMRig Proxy. It consumes one schema-v2 Unix event-stream connection and
serves a read-only, scrollable dashboard on `127.0.0.1`.

The dashboard provides:

- a bounded live event timeline with search, category filters, pause/follow,
  and full row details;
- daemon template-source height, age, refresh reason, and error state;
- worker connection, job, share, and block-submission events;
- the top five observed accepted shares with their exact event times and
  miner-reported difficulties;
- optional XMRig Proxy HTTP API hashrate, result, resource, upstream, and
  per-worker statistics.

## Run it

Socket-only mode:

```bash
python3 extras/event-dashboard/xmrig_events_web.py \
  /run/xmrig-proxy/events.sock \
  --port 8787
```

The HTTP listener is hard-coded to `127.0.0.1`; there is no option to expose it
on a public interface.

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
  --api-url http://127.0.0.1:8080 \
  --api-token-file /etc/xmrig-proxy/dashboard-api-token
```

The default API interval is five seconds because the proxy's hashrate and
worker buckets update every four seconds. The dashboard requests only
`/1/summary` and `/1/workers`. It deliberately never requests `/1/miners`,
which exposes downstream login and password fields.

## Open it through SSH

From the laptop that will display the dashboard, create a local port forward:

```bash
ssh -N -L 8787:127.0.0.1:8787 root@PROXY_HOST
```

Then open <http://127.0.0.1:8787/> on the laptop. This is SSH local forwarding
(`-L`): the dashboard remains bound to loopback on the proxy machine.

For local supervision, `GET /healthz` is a process-liveness check and always
returns HTTP 200 while the web process is running. `GET /readyz` returns HTTP
200 only while a clean schema-v2 Unix-socket session is connected; it returns
HTTP 503 while waiting, disconnected, or degraded.

## API interpretation

- API hashrate values are in **kH/s**.
- With `custom-diff-stats=true`, local custom-difficulty accepts contribute to
  API and worker hashrate estimates.
- API `results.accepted` counts upstream outcomes, not locally accepted custom
  shares. The event-stream counters show local and upstream outcomes
  separately.
- Worker records are grouped by the configured worker mode. Equal usernames or
  rig IDs may intentionally appear as one worker group even though mining jobs
  remain isolated per connection. If the worker mode is `password`, the
  dashboard replaces every worker name with `[password worker hidden]`.
- API `hashes_total` is credited difficulty, not a hardware hash counter.

The bearer token exists only in the Python backend's memory. It is not included
in browser responses, events, logs, or the dashboard page.

## Coverage and memory bounds

The proxy stream has no replay. The leaderboard and counters cover only events
observed since this dashboard process attached. A reconnect, event-sequence
gap, or proxy restart marks coverage as incomplete; process and share IDs are
session-qualified so reused IDs are not merged.

The Python timeline defaults to 5,000 rows and each browser renders at most the
latest 1,000 filtered rows. Change the backend bound with `--max-events`. The
leaderboard retains only the configured number of top shares. A stalled browser
subscriber is disconnected rather than allowed to grow an unbounded queue, and
at most five browser event streams may be connected at once.

## Test

```bash
python3 -m unittest -v \
  extras/event-dashboard/test_xmrig_events_web.py
```

The tests use fake socket chunks and do not need a running proxy or network
listener.
