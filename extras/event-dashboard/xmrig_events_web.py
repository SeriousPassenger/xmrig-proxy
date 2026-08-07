#!/usr/bin/env python3
"""Local-only web dashboard for the XMRig Proxy schema-v2 event socket."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import errno
import json
import math
import os
import queue
import signal
import socket
import stat
import sys
import threading
import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


DEFAULT_SOCKET = "/run/xmrig-proxy/events.sock"
DEFAULT_PORT = 8787
MAX_LINE_BYTES = 1024 * 1024
MAX_BROWSER_SUBSCRIBERS = 5

HEADER = (
    "schema_version", "event_seq", "time_utc", "event", "miner_id",
    "mapper_id", "miner_ip", "listen_port", "worker", "agent",
    "source_id", "template_id", "template_age_ms", "refresh_reason",
    "height", "prev_hash", "seed_hash", "algo", "job_id", "entropy_hex",
    "miner_target_diff", "network_target_diff", "share_id",
    "miner_request_id", "daemon_request_id", "nonce", "result_hash",
    "share_diff", "status", "error_code", "error_message", "latency_ms",
    "connection_ms", "rx_bytes", "tx_bytes",
)

NUMERIC_FIELDS = {
    "event_seq", "miner_id", "mapper_id", "listen_port", "source_id",
    "template_id", "template_age_ms", "height", "miner_target_diff",
    "network_target_diff", "share_id", "miner_request_id",
    "daemon_request_id", "share_diff", "error_code", "latency_ms",
    "connection_ms", "rx_bytes", "tx_bytes",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ProtocolError(RuntimeError):
    pass


class SubscriberLimitError(RuntimeError):
    pass


class FrameBuffer:
    """Split arbitrary stream chunks into physical CSV records."""

    def __init__(self, limit: int = MAX_LINE_BYTES) -> None:
        self._buffer = bytearray()
        self._limit = limit

    @property
    def has_partial(self) -> bool:
        return bool(self._buffer)

    def feed(self, chunk: bytes) -> List[bytes]:
        self._buffer.extend(chunk)
        records: List[bytes] = []

        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                break
            if newline > self._limit:
                self._buffer.clear()
                raise ProtocolError(f"CSV record exceeds {self._limit} bytes")

            record = bytes(self._buffer[:newline])
            del self._buffer[:newline + 1]
            if record.endswith(b"\r"):
                record = record[:-1]
            if record:
                records.append(record)

        if len(self._buffer) > self._limit:
            self._buffer.clear()
            raise ProtocolError(f"CSV record exceeds {self._limit} bytes")

        return records


class RowParser:
    """Strict parser for LiveEventStream schema v2."""

    def __init__(self) -> None:
        self.header_seen = False
        self.line_number = 0

    def parse(self, raw: bytes) -> Optional[Dict[str, str]]:
        self.line_number += 1
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError(f"line {self.line_number}: invalid UTF-8: {exc}") from exc

        try:
            values = next(csv.reader([text], strict=True))
        except csv.Error as exc:
            raise ProtocolError(f"line {self.line_number}: invalid CSV: {exc}") from exc

        if not self.header_seen:
            if tuple(values) != HEADER:
                raise ProtocolError(
                    f"line {self.line_number}: expected exact schema-v2 header "
                    f"({len(HEADER)} columns), received {len(values)}"
                )
            self.header_seen = True
            return None

        if tuple(values) == HEADER:
            return None
        if len(values) != len(HEADER):
            raise ProtocolError(
                f"line {self.line_number}: expected {len(HEADER)} columns, received {len(values)}"
            )

        row = dict(zip(HEADER, values))
        if row["schema_version"] != "2":
            raise ProtocolError(
                f"line {self.line_number}: unsupported schema_version={row['schema_version']!r}"
            )
        if not row["event_seq"] or not row["time_utc"] or not row["event"]:
            raise ProtocolError(
                f"line {self.line_number}: event_seq, time_utc, and event are required"
            )

        for name in NUMERIC_FIELDS:
            value = row[name]
            if not value:
                continue
            try:
                int(value, 10)
            except ValueError as exc:
                raise ProtocolError(
                    f"line {self.line_number}: {name} is not an integer: {value!r}"
                ) from exc

        if int(row["event_seq"], 10) <= 0:
            raise ProtocolError(f"line {self.line_number}: event_seq must be positive")
        if row["share_diff"] and int(row["share_diff"], 10) < 0:
            raise ProtocolError(f"line {self.line_number}: share_diff cannot be negative")

        return row


@dataclass(eq=False)
class Subscriber:
    messages: "queue.Queue[Dict[str, Any]]"
    closed: threading.Event


def _finite_number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        converted = float(value)
        if math.isfinite(converted):
            return converted
    return default


def _integer(value: Any, default: int = 0) -> int:
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else default


def sanitize_api_summary(document: Dict[str, Any]) -> Dict[str, Any]:
    """Copy only documented, non-credential summary fields."""
    hashrate = document.get("hashrate") if isinstance(document.get("hashrate"), dict) else {}
    totals = hashrate.get("total") if isinstance(hashrate.get("total"), list) else []
    miners = document.get("miners") if isinstance(document.get("miners"), dict) else {}
    upstreams = document.get("upstreams") if isinstance(document.get("upstreams"), dict) else {}
    results = document.get("results") if isinstance(document.get("results"), dict) else {}
    best = results.get("best") if isinstance(results.get("best"), list) else []
    resources = document.get("resources") if isinstance(document.get("resources"), dict) else {}
    memory = resources.get("memory") if isinstance(resources.get("memory"), dict) else {}
    loads = resources.get("load_average") if isinstance(resources.get("load_average"), list) else []

    return {
        "id": str(document.get("id", ""))[:128],
        "worker_id": str(document.get("worker_id", ""))[:128],
        "version": str(document.get("version", ""))[:64],
        "mode": str(document.get("mode", ""))[:32],
        "uptime": _integer(document.get("uptime")),
        "restricted": bool(document.get("restricted", False)),
        "donate_level": _integer(document.get("donate_level")),
        "hashrate": [_finite_number(value) for value in totals[:6]],
        "resources": {
            "memory": {
                "resident_set_memory": _integer(memory.get("resident_set_memory")),
                "free": _integer(memory.get("free")),
                "total": _integer(memory.get("total")),
            },
            "load_average": [_finite_number(value) for value in loads[:3]],
            "hardware_concurrency": _integer(resources.get("hardware_concurrency")),
        },
        "miners": {"now": _integer(miners.get("now")), "max": _integer(miners.get("max"))},
        "workers": _integer(document.get("workers")),
        "upstreams": {
            "active": _integer(upstreams.get("active")),
            "sleep": _integer(upstreams.get("sleep")),
            "error": _integer(upstreams.get("error")),
            "total": _integer(upstreams.get("total")),
            "ratio": _finite_number(upstreams.get("ratio")),
        },
        "results": {
            "accepted": _integer(results.get("accepted")),
            "rejected": _integer(results.get("rejected")),
            "invalid": _integer(results.get("invalid")),
            "expired": _integer(results.get("expired")),
            "avg_time": _finite_number(results.get("avg_time")),
            "latency": _finite_number(results.get("latency")),
            "hashes_total": str(results.get("hashes_total", "0")),
            "hashes_donate": str(results.get("hashes_donate", "0")),
            "best": [str(value) for value in best[:10] if isinstance(value, int)],
        },
    }


def sanitize_api_workers(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Decode /1/workers arrays without exposing unrelated API fields."""
    values = document.get("workers") if isinstance(document.get("workers"), list) else []
    mode = document.get("mode") if isinstance(document.get("mode"), str) else ""
    workers: List[Dict[str, Any]] = []
    for value in values[:10000]:
        if not isinstance(value, list) or len(value) < 13:
            continue
        name = value[0] if isinstance(value[0], str) else ""
        if mode == "password":
            name = "[password worker hidden]"
        workers.append({
            "name": name[:256],
            "connections": _integer(value[2]),
            "accepted": _integer(value[3]),
            "rejected": _integer(value[4]),
            "invalid": _integer(value[5]),
            "hashes": str(value[6]) if isinstance(value[6], int) else "0",
            "last_hash": _integer(value[7]),
            "hashrate": [_finite_number(item) for item in value[8:13]],
        })
    return workers


class DashboardState:
    """Thread-safe bounded state shared by the socket reader and HTTP clients."""

    def __init__(self, socket_path: str, max_events: int, top_limit: int,
                 api_enabled: bool = False, api_interval: float = 5.0) -> None:
        self.socket_path = socket_path
        self.max_events = max_events
        self.top_limit = top_limit
        self._lock = threading.RLock()
        self._events: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self._counters: Counter[str] = Counter()
        self._miners: Dict[str, Dict[str, str]] = {}
        self._sources: Dict[str, Dict[str, Any]] = {}
        self._shares: "OrderedDict[Tuple[int, str], Dict[str, str]]" = OrderedDict()
        self._top: List[Dict[str, Any]] = []
        self._seen_accepted: "OrderedDict[Tuple[int, str], None]" = OrderedDict()
        self._subscribers: Set[Subscriber] = set()
        self._viewer_sequence = 0
        self._source_sequence: Optional[int] = None
        self._session = 0
        self._connected = False
        self._coverage_complete = False
        self._reader_status = "starting"
        self._reader_message = "waiting for the event socket"
        self._started_utc = utc_now()
        self._last_event_utc = ""
        self._api: Dict[str, Any] = {
            "enabled": api_enabled,
            "status": "waiting" if api_enabled else "disabled",
            "message": "waiting for the proxy API" if api_enabled else "API polling is not configured",
            "last_update_utc": "",
            "interval_seconds": api_interval,
            "summary": {},
            "workers": [],
        }

    @staticmethod
    def _empty_row(event: str, status: str, message: str = "") -> Dict[str, str]:
        row = {name: "" for name in HEADER}
        row.update({
            "schema_version": "viewer",
            "time_utc": utc_now(),
            "event": event,
            "status": status,
            "error_message": message,
        })
        return row

    def _health_locked(self) -> Dict[str, Any]:
        return {
            "socket_connected": self._connected,
            "reader_status": self._reader_status,
            "reader_message": self._reader_message,
            "coverage_complete": self._coverage_complete,
            "session": self._session,
            "started_utc": self._started_utc,
            "last_event_utc": self._last_event_utc,
            "socket_path": self.socket_path,
        }

    def health(self) -> Dict[str, Any]:
        """Return health without copying the bounded event/API snapshot."""
        with self._lock:
            return self._health_locked()

    def _state_locked(self, include_api: bool = True) -> Dict[str, Any]:
        rejected = (
            self._counters["share_result:rejected_local"]
            + self._counters["share_result:rejected_upstream"]
        )
        result = {
            "top_limit": self.top_limit,
            "max_events": self.max_events,
            "health": self._health_locked(),
            "stats": {
                "events_observed": self._counters["events_observed"],
                "active_miners": sum(
                    1 for miner in self._miners.values()
                    if miner.get("status") in {"accepted", "active"}
                ),
                "sources_observed": len(self._sources),
                "templates": self._counters["template_cached"],
                "jobs": self._counters["job_sent"],
                "shares_received": self._counters["share_received"],
                "local_accepted": self._counters["share_result:accepted_local"],
                "upstream_accepted": self._counters["share_result:accepted_upstream"],
                "rejected": rejected,
                "blocks_accepted": self._counters["submit_block_result:accepted"],
                "blocks_rejected": self._counters["submit_block_result:rejected"],
            },
            "sources": self._sources_json_locked(),
            "top_shares": [
                {key: value for key, value in item.items() if not key.startswith("_")}
                for item in self._top
            ],
        }
        if include_api:
            result["api"] = dict(self._api)
        return result

    def _sources_json_locked(self) -> List[Dict[str, Any]]:
        now = time.monotonic()
        result: List[Dict[str, Any]] = []
        for source_id, source in sorted(self._sources.items(), key=lambda item: int(item[0])):
            item = {key: value for key, value in source.items() if not key.startswith("_")}
            cached_at = source.get("_cached_monotonic")
            item["age_ms"] = max(0, int((now - cached_at) * 1000)) if cached_at is not None else None
            result.append(item)
        return result

    def _snapshot_locked(self) -> Dict[str, Any]:
        snapshot = self._state_locked()
        snapshot.update({
            "kind": "snapshot",
            "viewer_seq": self._viewer_sequence,
            "events": [dict(row) for row in self._events],
        })
        return snapshot

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return self._snapshot_locked()

    def subscribe(self) -> Tuple[Subscriber, Dict[str, Any]]:
        subscriber = Subscriber(queue.Queue(maxsize=1024), threading.Event())
        with self._lock:
            if len(self._subscribers) >= MAX_BROWSER_SUBSCRIBERS:
                raise SubscriberLimitError(
                    f"dashboard supports at most {MAX_BROWSER_SUBSCRIBERS} browser streams"
                )
            self._subscribers.add(subscriber)
            snapshot = self._snapshot_locked()
        return subscriber, snapshot

    def unsubscribe(self, subscriber: Subscriber) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)
        subscriber.closed.set()

    def shutdown(self) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
            self._subscribers.clear()
        for subscriber in subscribers:
            subscriber.closed.set()

    def _broadcast_locked(self, payload: Dict[str, Any]) -> None:
        for subscriber in list(self._subscribers):
            try:
                subscriber.messages.put_nowait(payload)
            except queue.Full:
                subscriber.closed.set()
                self._subscribers.discard(subscriber)

    def _append_locked(self, row: Dict[str, Any], count: bool = True) -> None:
        self._viewer_sequence += 1
        row["_viewer_seq"] = self._viewer_sequence
        row["_session"] = self._session
        row["_received_utc"] = utc_now()
        self._last_event_utc = row.get("time_utc") or row["_received_utc"]
        self._events.append(row)
        if count:
            self._counters["events_observed"] += 1

        # API worker arrays can be large and change only on the API poller.
        # Do not copy/send/re-render them for every high-rate mining event.
        payload = self._state_locked(include_api=False)
        payload.update({"kind": "update", "viewer_seq": self._viewer_sequence, "row": dict(row)})
        self._broadcast_locked(payload)

    def _notice_locked(self, event: str, status: str, message: str) -> None:
        self._append_locked(self._empty_row(event, status, message), count=False)

    def begin_session(self) -> None:
        with self._lock:
            self._session += 1
            self._coverage_complete = self._session == 1
            self._connected = True
            self._reader_status = "connected"
            self._reader_message = "schema-v2 stream connected"

            # The stream has no replay and proxy process IDs may restart.
            self._miners.clear()
            self._sources.clear()
            self._shares.clear()
            self._notice_locked("viewer_connected", "connected", "event socket connected")

    def end_session(self, message: str) -> None:
        with self._lock:
            self._connected = False
            self._coverage_complete = False
            self._reader_status = "disconnected"
            self._reader_message = message
            self._notice_locked("viewer_disconnected", "degraded", message)

    def waiting(self, message: str) -> None:
        with self._lock:
            changed = self._reader_status != "waiting" or self._reader_message != message
            self._connected = False
            self._reader_status = "waiting"
            self._reader_message = message
            if changed:
                self._notice_locked("viewer_waiting", "warning", message)

    def protocol_error(self, message: str) -> None:
        with self._lock:
            self._coverage_complete = False
            self._reader_status = "degraded"
            self._reader_message = message
            self._notice_locked("viewer_error", "error", message)

    def fatal(self, message: str) -> None:
        with self._lock:
            self._connected = False
            self._coverage_complete = False
            self._reader_status = "fatal"
            self._reader_message = message
            self._notice_locked("viewer_error", "error", message)

    def update_api(self, summary: Dict[str, Any], workers: Dict[str, Any]) -> None:
        """Publish a credential-free, allowlisted API snapshot to browsers."""
        with self._lock:
            interval = self._api.get("interval_seconds", 5.0)
            self._api = {
                "enabled": True,
                "status": "connected",
                "message": "proxy HTTP API connected",
                "last_update_utc": utc_now(),
                "interval_seconds": interval,
                "summary": sanitize_api_summary(summary),
                "workers_mode": str(workers.get("mode", ""))[:32],
                "workers": sanitize_api_workers(workers),
            }
            payload = self._state_locked()
            payload.update({"kind": "state", "viewer_seq": self._viewer_sequence})
            self._broadcast_locked(payload)

    def api_error(self, message: str) -> None:
        with self._lock:
            if self._api.get("status") == "error" and self._api.get("message") == message:
                return
            self._api["enabled"] = True
            self._api["status"] = "error"
            self._api["message"] = message
            payload = self._state_locked()
            payload.update({"kind": "state", "viewer_seq": self._viewer_sequence})
            self._broadcast_locked(payload)

    def _resolve_identity_locked(self, row: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(row)
        share_id = result.get("share_id", "")
        if share_id:
            context = self._shares.get((self._session, share_id))
            if context:
                for name in (
                    "miner_id", "mapper_id", "worker", "source_id", "template_id",
                    "height", "job_id", "miner_target_diff", "network_target_diff",
                ):
                    if not result.get(name):
                        result[name] = context.get(name, "")
        return result

    def _remember_share_locked(self, row: Dict[str, Any]) -> None:
        share_id = row.get("share_id", "")
        if not share_id:
            return
        key = (self._session, share_id)
        self._shares[key] = {
            name: row.get(name, "")
            for name in (
                "miner_id", "mapper_id", "worker", "source_id", "template_id",
                "height", "job_id", "miner_target_diff", "network_target_diff",
            )
        }
        self._shares.move_to_end(key)
        while len(self._shares) > 8192:
            self._shares.popitem(last=False)

    def _update_miner_locked(self, row: Dict[str, Any]) -> None:
        event = row["event"]
        miner_id = row.get("miner_id", "")
        if not miner_id:
            return
        if event == "worker_disconnected":
            self._miners.pop(miner_id, None)
            return
        if event not in {"worker_connected", "worker_login", "job_sent", "share_received", "share_result"}:
            return

        miner = self._miners.setdefault(miner_id, {"miner_id": miner_id})
        for name in ("mapper_id", "worker", "miner_ip", "agent", "source_id"):
            if row.get(name):
                miner[name] = row[name]
        if event == "worker_login":
            miner["status"] = row.get("status", "")
        elif event in {"job_sent", "share_received", "share_result"}:
            miner["status"] = "active"
        miner["last_event_utc"] = row.get("time_utc", "")

    def _update_source_locked(self, row: Dict[str, Any], received_at: float) -> None:
        source_id = row.get("source_id", "")
        if not source_id:
            return
        source = self._sources.setdefault(source_id, {"source_id": source_id, "status": "observed"})
        event = row["event"]
        for name in (
            "template_id", "height", "network_target_diff", "refresh_reason",
            "prev_hash", "seed_hash", "latency_ms",
        ):
            if row.get(name):
                source[name] = row[name]

        if event == "template_cached":
            source.update({
                "status": "healthy",
                "last_cached_utc": row["time_utc"],
                "last_error": "",
                "_cached_monotonic": received_at,
            })
        elif event == "job_sent" and row.get("template_age_ms"):
            inferred = received_at - (int(row["template_age_ms"], 10) / 1000.0)
            current = source.get("_cached_monotonic")
            if current is None or inferred > current:
                source["_cached_monotonic"] = inferred
                source["last_cached_utc"] = row["time_utc"]
        elif event in {"template_error", "daemon_height_error"}:
            source["status"] = "error"
            source["last_error"] = row.get("error_message", "")
        elif event == "zmq_new_block":
            source["last_zmq_utc"] = row["time_utc"]

    def _consider_top_locked(self, row: Dict[str, Any]) -> None:
        if self.top_limit <= 0 or row["event"] != "share_result":
            return
        if row.get("status") not in {"accepted_local", "accepted_upstream"}:
            return
        if not row.get("share_diff"):
            return

        identity = row.get("share_id") or f"seq:{row['event_seq']}"
        key = (self._session, identity)
        if key in self._seen_accepted:
            return
        self._seen_accepted[key] = None
        while len(self._seen_accepted) > 100000:
            self._seen_accepted.popitem(last=False)

        item = {
            "share_diff": row["share_diff"],
            "time_utc": row["time_utc"],
            "share_id": row.get("share_id", ""),
            "miner_id": row.get("miner_id", ""),
            "mapper_id": row.get("mapper_id", ""),
            "worker": row.get("worker", ""),
            "height": row.get("height", ""),
            "status": row.get("status", ""),
            "source_id": row.get("source_id", ""),
            "template_id": row.get("template_id", ""),
            "job_id": row.get("job_id", ""),
            "session": self._session,
            "_difficulty": int(row["share_diff"], 10),
            "_viewer_seq": self._viewer_sequence + 1,
        }
        self._top.append(item)
        self._top.sort(key=lambda value: (-value["_difficulty"], value["_viewer_seq"]))
        del self._top[self.top_limit:]

    def ingest(self, row: Dict[str, str]) -> None:
        received_at = time.monotonic()
        with self._lock:
            sequence = int(row["event_seq"], 10)
            previous = self._source_sequence
            if previous is not None and sequence != previous + 1:
                self._coverage_complete = False
                direction = "reset" if sequence <= previous else "gap"
                self._notice_locked(
                    "viewer_sequence_gap",
                    "degraded",
                    f"event sequence {direction}: {previous} -> {sequence}",
                )
            self._source_sequence = sequence

            resolved = self._resolve_identity_locked(row)
            event = resolved["event"]
            status = resolved.get("status", "")
            self._counters[event] += 1
            if status:
                self._counters[f"{event}:{status}"] += 1

            if event == "share_received":
                self._remember_share_locked(resolved)
            self._update_miner_locked(resolved)
            self._update_source_locked(resolved, received_at)
            self._consider_top_locked(resolved)
            self._append_locked(resolved)


class UnixEventReader(threading.Thread):
    RETRYABLE = {
        errno.ENOENT, errno.ECONNREFUSED, errno.ECONNRESET, errno.EPIPE,
        errno.ENOTCONN, errno.ETIMEDOUT,
    }

    def __init__(self, path: str, state: DashboardState, stop_event: threading.Event, retry_cap: float) -> None:
        super().__init__(name="xmrig-event-socket-reader", daemon=True)
        self.path = path
        self.state = state
        self.stop_event = stop_event
        self.retry_cap = retry_cap
        self._socket: Optional[socket.socket] = None
        self._socket_lock = threading.Lock()

    def stop(self) -> None:
        self.stop_event.set()
        with self._socket_lock:
            current = self._socket
        if current is not None:
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current.close()
            except OSError:
                pass

    def _connect(self) -> socket.socket:
        try:
            mode = os.lstat(self.path).st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and not stat.S_ISSOCK(mode):
            raise OSError(errno.ENOTSOCK, "path exists but is not a Unix socket", self.path)

        current = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            current.settimeout(2.0)
            current.connect(self.path)
            current.settimeout(1.0)
        except OSError:
            current.close()
            raise
        with self._socket_lock:
            self._socket = current
        return current

    def _close(self, current: socket.socket) -> None:
        with self._socket_lock:
            if self._socket is current:
                self._socket = None
        try:
            current.close()
        except OSError:
            pass

    def _read(self, current: socket.socket) -> None:
        parser = RowParser()
        framer = FrameBuffer()
        session_started = False

        while not self.stop_event.is_set():
            try:
                chunk = current.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                if framer.has_partial:
                    self.state.protocol_error("socket closed with a partial CSV record")
                if session_started:
                    self.state.end_session("event socket disconnected; stream coverage has no replay")
                else:
                    self.state.waiting("socket closed before the schema-v2 header")
                return

            try:
                records = framer.feed(chunk)
            except ProtocolError as exc:
                self.state.protocol_error(str(exc))
                if session_started:
                    self.state.end_session("event socket protocol error; reconnecting")
                else:
                    self.state.waiting("invalid event socket stream; reconnecting")
                return

            for record in records:
                try:
                    row = parser.parse(record)
                except ProtocolError as exc:
                    self.state.protocol_error(str(exc))
                    if not parser.header_seen:
                        self.state.waiting("invalid schema-v2 event header; reconnecting")
                        return
                    continue
                if row is None:
                    if parser.header_seen and not session_started:
                        self.state.begin_session()
                        session_started = True
                    continue
                if not session_started:
                    self.state.protocol_error("received an event before the schema-v2 header")
                    self.state.waiting("invalid event socket stream; reconnecting")
                    return
                self.state.ingest(row)

    def run(self) -> None:
        delay = 0.5
        while not self.stop_event.is_set():
            try:
                current = self._connect()
            except OSError as exc:
                message = f"cannot connect to {self.path}: {exc.strerror or exc}"
                if (exc.errno or 0) not in self.RETRYABLE:
                    self.state.fatal(message)
                    return
                self.state.waiting(f"{message}; retrying")
                self.stop_event.wait(delay)
                delay = min(self.retry_cap, delay * 2)
                continue

            delay = 0.5
            try:
                self._read(current)
            except OSError as exc:
                if not self.stop_event.is_set():
                    self.state.end_session(f"socket read failed: {exc}")
            except Exception as exc:  # Defensive: surface reader failures in the dashboard.
                if not self.stop_event.is_set():
                    self.state.fatal(f"event reader stopped unexpectedly: {exc}")
                    return
            finally:
                self._close(current)

            if not self.stop_event.is_set():
                self.stop_event.wait(delay)


class NoRedirectHandler(HTTPRedirectHandler):
    """Never forward the API bearer token through an HTTP redirect."""

    def redirect_request(self, _req: Request, _fp: Any, _code: int, _msg: str,
                         _headers: Any, _newurl: str) -> Optional[Request]:
        return None


class ApiPoller(threading.Thread):
    MAX_RESPONSE_BYTES = 8 * 1024 * 1024

    def __init__(self, base_url: str, token: str, interval: float,
                 state: DashboardState, stop_event: threading.Event) -> None:
        super().__init__(name="xmrig-proxy-api-poller", daemon=True)
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.interval = interval
        self.state = state
        self.stop_event = stop_event
        self.opener = build_opener(ProxyHandler({}), NoRedirectHandler())

    def _fetch(self, path: str) -> Dict[str, Any]:
        request = Request(
            self.base_url + path,
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + self.token,
                "User-Agent": "xmrig-event-dashboard/1",
            },
            method="GET",
        )
        with self.opener.open(request, timeout=min(10.0, max(2.0, self.interval))) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} from {path}")
            body = response.read(self.MAX_RESPONSE_BYTES + 1)
            if len(body) > self.MAX_RESPONSE_BYTES:
                raise RuntimeError(f"response from {path} exceeds {self.MAX_RESPONSE_BYTES} bytes")
            try:
                document = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid JSON from {path}: {exc}") from exc
            if not isinstance(document, dict):
                raise RuntimeError(f"JSON from {path} is not an object")
            return document

    @staticmethod
    def _error_message(exc: BaseException) -> str:
        if isinstance(exc, HTTPError):
            if exc.code in (401, 403):
                return f"proxy API authentication failed (HTTP {exc.code})"
            return f"proxy API returned HTTP {exc.code}"
        if isinstance(exc, URLError):
            return f"proxy API connection failed: {exc.reason}"
        return f"proxy API poll failed: {exc}"

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                summary = self._fetch("/1/summary")
                workers = self._fetch("/1/workers")
                self.state.update_api(summary, workers)
            except (HTTPError, URLError, OSError, RuntimeError) as exc:
                self.state.api_error(self._error_message(exc))

            elapsed = time.monotonic() - started
            self.stop_event.wait(max(0.05, self.interval - elapsed))


HTML = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>XMRig Proxy Event Dashboard</title>
  <style>
    :root { color-scheme: dark; --bg:#0a0d10; --panel:#11161b; --panel2:#161d23; --line:#26313a; --muted:#8a99a5; --text:#e7edf1; --cyan:#58d7d3; --green:#63d391; --amber:#f3be62; --red:#ff716c; --violet:#b59aff; }
    * { box-sizing:border-box; }
    body { margin:0; background:radial-gradient(circle at 85% -10%,#193034 0,transparent 32rem),var(--bg); color:var(--text); font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
    button,input,select { font:inherit; color:inherit; }
    .shell { max-width:1800px; margin:auto; padding:22px; }
    header { display:flex; align-items:flex-start; justify-content:space-between; gap:20px; margin-bottom:18px; }
    h1,h2 { margin:0; font-weight:650; letter-spacing:-.03em; }
    h1 { font-size:25px; } h2 { font-size:16px; }
    .sub { color:var(--muted); margin-top:5px; }
    .badges { display:flex; flex-wrap:wrap; justify-content:flex-end; gap:8px; }
    .badge { border:1px solid var(--line); border-radius:999px; padding:6px 10px; background:#0d1216; color:var(--muted); }
    .badge.ok { color:var(--green); border-color:#28583e; } .badge.bad { color:var(--red); border-color:#60312f; } .badge.warn { color:var(--amber); border-color:#5b4726; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); gap:10px; margin-bottom:10px; }
    .card,.panel { background:linear-gradient(180deg,var(--panel2),var(--panel)); border:1px solid var(--line); border-radius:12px; box-shadow:0 12px 35px #0005; }
    .card { padding:13px 15px; min-height:82px; }
    .card .label { color:var(--muted); text-transform:uppercase; letter-spacing:.09em; font-size:10px; }
    .card .value { margin-top:7px; font-size:23px; font-weight:700; }
    .card .note { color:var(--muted); font-size:11px; margin-top:1px; }
    .panel { padding:15px; min-width:0; }
    .panel-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:12px; }
    .grid-two { display:grid; grid-template-columns:minmax(0,1.25fr) minmax(0,.75fr); gap:10px; margin:10px 0; }
    .workspace { display:grid; grid-template-columns:minmax(0,3fr) minmax(280px,1fr); gap:10px; }
    .scroll { overflow:auto; border:1px solid var(--line); border-radius:9px; background:#0b1014; }
    .top-scroll { max-height:285px; } .events-scroll { height:58vh; min-height:430px; }
    table { width:100%; border-collapse:collapse; white-space:nowrap; }
    th { position:sticky; top:0; z-index:1; text-align:left; color:var(--muted); background:#11181e; font-size:10px; letter-spacing:.08em; text-transform:uppercase; }
    th,td { padding:9px 10px; border-bottom:1px solid #202a32; }
    tbody tr { cursor:pointer; } tbody tr:hover { background:#172129; }
    .status-accepted,.status-updated,.status-healthy { color:var(--green); }
    .status-rejected,.status-error,.status-fatal { color:var(--red); }
    .status-requested,.status-warning,.status-degraded { color:var(--amber); }
    .event-template { color:var(--cyan); } .event-block { color:var(--amber); font-weight:700; } .event-worker { color:var(--violet); }
    .controls { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
    input,select,button { border:1px solid var(--line); background:#0d1318; border-radius:7px; padding:7px 9px; }
    input { min-width:210px; flex:1; } button { cursor:pointer; } button:hover { border-color:#536572; }
    label.check { color:var(--muted); display:flex; align-items:center; gap:5px; }
    label.check input { min-width:0; flex:none; }
    .details { height:calc(58vh + 54px); min-height:484px; overflow:auto; }
    .details pre { margin:0; color:#cbd5dc; white-space:pre-wrap; word-break:break-word; font:12px/1.55 inherit; }
    .empty { color:var(--muted); padding:24px; text-align:center; }
    .source-row { display:grid; grid-template-columns:80px 90px 1fr 110px 90px; gap:10px; padding:9px 2px; border-bottom:1px solid var(--line); }
    .source-row:last-child { border:0; }
    .api-metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin-bottom:12px; }
    .api-metric { background:#0c1216; border:1px solid var(--line); border-radius:8px; padding:10px; }
    .api-metric b { display:block; font-size:18px; color:var(--cyan); margin-top:3px; }
    .muted { color:var(--muted); }
    footer { color:var(--muted); font-size:11px; margin-top:12px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    @media (max-width:1100px) { .cards { grid-template-columns:repeat(3,1fr); } .workspace,.grid-two { grid-template-columns:1fr; } .details { height:320px; min-height:0; } }
    @media (max-width:650px) { .shell{padding:12px} header{display:block}.badges{justify-content:flex-start;margin-top:12px}.cards{grid-template-columns:repeat(2,1fr)} .events-scroll{height:55vh} }
  </style>
</head>
<body>
<div class="shell">
  <header>
    <div><h1>XMRig Proxy Event Dashboard</h1><div class="sub">Read-only schema-v2 observer · localhost only</div></div>
    <div class="badges"><span id="browserBadge" class="badge">dashboard: connecting</span><span id="socketBadge" class="badge">socket: starting</span><span id="apiBadge" class="badge">API: disabled</span><span id="coverageBadge" class="badge">coverage: observed</span><span id="sessionBadge" class="badge">session 0</span></div>
  </header>

  <section class="cards">
    <div class="card"><div class="label">Active miners</div><div id="activeMiners" class="value">0</div><div class="note">distinct miner IDs</div></div>
    <div class="card"><div class="label">Hashrate 1m</div><div id="hashrate1m" class="value">—</div><div class="note">proxy API · kH/s</div></div>
    <div class="card"><div class="label">Hashrate 10m</div><div id="hashrate10m" class="value">—</div><div class="note">proxy API · kH/s</div></div>
    <div class="card"><div class="label">Templates cached</div><div id="templates" class="value">0</div><div class="note">observed by viewer</div></div>
    <div class="card"><div class="label">Local accepts</div><div id="localAccepted" class="value">0</div><div class="note">custom-diff shares</div></div>
    <div class="card"><div class="label">API accepted</div><div id="apiAccepted" class="value">—</div><div class="note">proxy result counter</div></div>
    <div class="card"><div class="label">Rejected</div><div id="rejected" class="value">0</div><div class="note">socket outcomes</div></div>
    <div class="card"><div class="label">Blocks accepted</div><div id="blocksAccepted" class="value">0</div><div class="note">submitblock OK</div></div>
  </section>

  <section class="grid-two">
    <div class="panel"><div class="panel-head"><h2>Daemon template sources</h2><span id="sourceCount" class="muted">0 observed</span></div><div id="sources"><div class="empty">Waiting for daemon-backed jobs…</div></div></div>
    <div class="panel"><div class="panel-head"><h2>Reader state</h2></div><div id="readerState" class="muted">Starting…</div></div>
  </section>

  <section id="apiPanel" class="panel" style="margin-top:10px">
    <div class="panel-head"><div><h2>XMRig Proxy HTTP API</h2><div class="sub">Optional read-only summary and per-worker statistics</div></div><span id="apiUpdated" class="muted">not configured</span></div>
    <div class="api-metrics">
      <div class="api-metric"><span class="muted">1 hour hashrate</span><b id="hashrate1h">—</b></div>
      <div class="api-metric"><span class="muted">Miners now / max</span><b id="apiMiners">—</b></div>
      <div class="api-metric"><span class="muted">Upstreams active / total</span><b id="apiUpstreams">—</b></div>
      <div class="api-metric"><span class="muted">Accepted / rejected / invalid</span><b id="apiResults">—</b></div>
      <div class="api-metric"><span class="muted">Average latency</span><b id="apiLatency">—</b></div>
      <div class="api-metric"><span class="muted">Proxy uptime</span><b id="apiUptime">—</b></div>
      <div class="api-metric"><span class="muted">RSS / load 1m</span><b id="apiResources">—</b></div>
    </div>
    <div class="scroll top-scroll"><table><thead><tr><th>Worker</th><th>Connections</th><th>Hashrate 1m (kH/s)</th><th>Hashrate 10m (kH/s)</th><th>Accepted</th><th>Rejected</th><th>Invalid</th><th>Credited hashes</th></tr></thead><tbody id="apiWorkersBody"></tbody></table><div id="apiWorkersEmpty" class="empty">Supply --api-url and an API token to enable these statistics.</div></div>
  </section>

  <section class="panel">
    <div class="panel-head"><div><h2 id="topTitle">Top 5 observed accepted shares</h2><div class="sub">Ranked by accepted share difficulty; verifier-computed when enabled; times are exact event times</div></div><span id="topCompleteness" class="badge">observed window</span></div>
    <div class="scroll top-scroll"><table><thead><tr><th>#</th><th>Time (browser local)</th><th>Share difficulty</th><th>Miner</th><th>Worker</th><th>Height</th><th>Result</th></tr></thead><tbody id="topBody"></tbody></table><div id="topEmpty" class="empty">No accepted shares observed yet.</div></div>
  </section>

  <section class="workspace" style="margin-top:10px">
    <div class="panel">
      <div class="panel-head"><h2>Live event timeline</h2><span id="eventCount" class="muted">0 rows</span></div>
      <div class="controls" style="margin-bottom:10px">
        <select id="category"><option value="all">All events</option><option value="shares">Shares</option><option value="blocks">Blocks</option><option value="templates">Templates</option><option value="workers">Workers</option><option value="errors">Errors</option></select>
        <input id="search" type="search" placeholder="Filter miner, worker, event, status, ID…" autocomplete="off">
        <button id="pause">Pause view</button><button id="clear">Clear view</button>
        <label class="check"><input id="follow" type="checkbox" checked> follow</label>
      </div>
      <div id="eventsScroll" class="scroll events-scroll"><table><thead><tr><th>Time (local)</th><th>Event</th><th>Miner</th><th>Source/template</th><th>Height</th><th>Share diff</th><th>Status</th><th>Details</th></tr></thead><tbody id="eventsBody"></tbody></table></div>
    </div>
    <aside class="panel details"><div class="panel-head"><h2>Selected event</h2><button id="closeDetails">Clear</button></div><pre id="details">Select a timeline row to inspect every field.</pre></aside>
  </section>

  <footer><span id="lastEvent">No events received.</span><span>Only 127.0.0.1 is served; transport it with SSH local forwarding.</span></footer>
</div>
<script>
(() => {
  const model = { events: [], maxEvents: 5000, stats: {}, sources: [], top: [], topLimit: 5, health: {}, api: {}, lastViewerSeq: 0, paused: false, pending: 0, stateAt: Date.now() };
  const $ = id => document.getElementById(id);
  const nf = new Intl.NumberFormat('en-US');
  const groups = {
    shares: e => e.startsWith('share_') || e.startsWith('verify_'),
    blocks: e => e.startsWith('submit_block'),
    templates: e => e.includes('template') || e.startsWith('daemon_height') || e.startsWith('verifier_seed_') || e === 'zmq_new_block',
    workers: e => e.startsWith('worker_'),
    errors: (e, r) => e.includes('error') || e === 'verify_mismatch' || ['error','fatal','degraded','warning','mismatch','rejected','rejected_local','rejected_upstream'].includes(r.status)
  };
  const missing = value => value === null || value === undefined || value === '';
  const exact = value => { if (missing(value)) return '—'; try { return BigInt(value).toLocaleString('en-US'); } catch (_) { return String(value); } };
  const compact = value => { if (missing(value)) return '—'; const n = Number(value); if (!Number.isFinite(n)) return String(value); const units=['','K','M','G','T','P','E']; let x=n,i=0; while(Math.abs(x)>=1000&&i<units.length-1){x/=1000;i++;} return `${x>=100?x.toFixed(0):x>=10?x.toFixed(1):x.toFixed(2)}${units[i]}`; };
  const time = value => { if (!value) return '—'; const d=new Date(value); return Number.isNaN(d.valueOf())?value:d.toLocaleString(undefined,{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3,hour12:false}); };
  const short = value => value && value.length > 12 ? `${value.slice(0,8)}…` : (value || '—');
  const td = (tr, value, cls='') => { const cell=document.createElement('td'); cell.textContent=value; if(cls) cell.className=cls; tr.appendChild(cell); return cell; };
  const eventClass = event => event.startsWith('submit_block')?'event-block':event.startsWith('worker_')?'event-worker':(event.includes('template')||event.startsWith('verifier_seed_')||event==='zmq_new_block')?'event-template':'';
  const statusClass = status => `status-${status || 'none'}`;
  const detailText = row => {
    const parts=[];
    if(row.refresh_reason) parts.push(row.refresh_reason);
    if(row.template_age_ms) parts.push(`age ${row.template_age_ms}ms`);
    if(row.latency_ms) parts.push(`${row.latency_ms}ms`);
    if(row.daemon_request_id) parts.push(`req ${row.daemon_request_id}`);
    if(row.error_message) parts.push(row.error_message);
    if(row.job_id) parts.push(`job ${short(row.job_id)}`);
    return parts.join(' · ') || '—';
  };

  function applyState(data) {
    const apiChanged=Object.prototype.hasOwnProperty.call(data,'api');
    model.maxEvents=data.max_events??model.maxEvents; model.stats=data.stats||{}; model.sources=data.sources||[]; model.top=data.top_shares||[]; model.topLimit=data.top_limit??5; model.health=data.health||{}; if(apiChanged)model.api=data.api||{}; model.stateAt=Date.now();
    $('topTitle').textContent=`Top ${model.topLimit} observed accepted shares`;
    renderHeader(); renderCards(); renderSources(); if(apiChanged)renderApi(); renderTop();
  }
  function applySnapshot(data) {
    model.events=data.events||[]; model.lastViewerSeq=data.viewer_seq||0; applyState(data); scheduleTimeline(true);
  }
  function applyUpdate(data) {
    if((data.viewer_seq||0)<=model.lastViewerSeq) return;
    model.lastViewerSeq=data.viewer_seq; model.events.push(data.row); if(model.events.length>model.maxEvents) model.events.splice(0,model.events.length-model.maxEvents); applyState(data);
    if(model.paused){model.pending++; $('pause').textContent=`Resume (${model.pending})`;} else scheduleTimeline(false);
  }
  function renderHeader() {
    const h=model.health||{}, socket=$('socketBadge'), coverage=$('coverageBadge');
    const socketHealthy=h.socket_connected&&h.reader_status==='connected';
    socket.textContent=`socket: ${h.reader_status||'starting'}`; socket.className=`badge ${socketHealthy?'ok':h.reader_status==='fatal'?'bad':'warn'}`;
    coverage.textContent=h.coverage_complete?'coverage: observed window':'coverage: incomplete'; coverage.className=`badge ${h.coverage_complete?'ok':'warn'}`;
    $('sessionBadge').textContent=`session ${h.session||0}`;
    const api=$('apiBadge'), a=model.api||{}, apiAge=a.last_update_utc?Date.now()-new Date(a.last_update_utc).valueOf():0, apiStale=a.status==='connected'&&apiAge>(Number(a.interval_seconds||5)*2500), apiStatus=apiStale?'stale':(a.status||'disabled'); api.textContent=`API: ${apiStatus}`; api.className=`badge ${apiStatus==='connected'?'ok':apiStatus==='error'?'bad':'warn'}`;
    $('readerState').textContent=`${h.reader_message||'—'}\nSocket: ${h.socket_path||'—'}\nStarted: ${time(h.started_utc)}\nLast event: ${time(h.last_event_utc)}`;
    $('topCompleteness').textContent=h.coverage_complete?'observed window':'incomplete after gap/reconnect'; $('topCompleteness').className=`badge ${h.coverage_complete?'ok':'warn'}`;
    $('lastEvent').textContent=h.last_event_utc?`Last observed event: ${time(h.last_event_utc)}`:'No events received.';
  }
  function renderCards() {
    const s=model.stats||{}, summary=(model.api||{}).summary||{}, rates=summary.hashrate||[], results=summary.results||{}, miners=summary.miners||{};
    $('activeMiners').textContent=nf.format((model.api||{}).status==='connected'?(miners.now||0):(s.active_miners||0)); $('hashrate1m').textContent=rates.length?compact(rates[0]):'—'; $('hashrate10m').textContent=rates.length>1?compact(rates[1]):'—'; $('templates').textContent=nf.format(s.templates||0); $('localAccepted').textContent=nf.format(s.local_accepted||0); $('apiAccepted').textContent=(model.api||{}).status==='connected'?nf.format(results.accepted||0):'—'; $('rejected').textContent=nf.format(s.rejected||0); $('blocksAccepted').textContent=nf.format(s.blocks_accepted||0);
  }
  function renderSources() {
    const host=$('sources'); host.replaceChildren(); $('sourceCount').textContent=`${model.sources.length} observed`;
    if(!model.sources.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='Waiting for daemon-backed jobs…';host.appendChild(empty);return;}
    for(const source of model.sources){const row=document.createElement('div');row.className='source-row'; const elapsed=Date.now()-model.stateAt, ageMs=source.age_ms==null?null:source.age_ms+elapsed, age=ageMs==null?'—':`${(ageMs/1000).toFixed(1)}s`, values=[`S${source.source_id}`,`T${source.template_id||'—'}`,`height ${source.height||'—'} · net ${compact(source.network_target_diff)}`,age,source.status||'observed']; values.forEach((value,index)=>{const span=document.createElement('span');span.textContent=value;if(index===3&&ageMs!==null&&ageMs>45000)span.className='status-error';else if(index===3&&ageMs!==null&&ageMs>30000)span.className='status-warning';if(index===4)span.className=statusClass(source.status);row.appendChild(span);});host.appendChild(row);}
  }
  function renderApiAge() {
    const api=model.api||{}, updateAge=api.last_update_utc?Math.max(0,(Date.now()-new Date(api.last_update_utc).valueOf())/1000):null;
    $('apiUpdated').textContent=api.enabled?`${api.message||api.status} · ${time(api.last_update_utc)}${updateAge===null?'':` · ${updateAge.toFixed(1)}s ago`}`:'not configured';
  }
  function renderApi() {
    const api=model.api||{}, summary=api.summary||{}, rates=summary.hashrate||[], miners=summary.miners||{}, upstreams=summary.upstreams||{}, results=summary.results||{}, resources=summary.resources||{}, memory=resources.memory||{}, loads=resources.load_average||[], workers=api.workers||[];
    renderApiAge();
    $('hashrate1h').textContent=rates.length>2?`${compact(rates[2])} kH/s`:'—'; $('apiMiners').textContent=api.status==='connected'?`${miners.now||0} / ${miners.max||0}`:'—'; $('apiUpstreams').textContent=api.status==='connected'?`${upstreams.active||0} / ${upstreams.total||0}`:'—'; $('apiResults').textContent=api.status==='connected'?`${results.accepted||0} / ${results.rejected||0} / ${results.invalid||0}`:'—'; $('apiLatency').textContent=api.status==='connected'?`${Number(results.latency||0).toFixed(1)} ms`:'—'; $('apiUptime').textContent=api.status==='connected'?`${Math.floor((summary.uptime||0)/3600)}h ${Math.floor(((summary.uptime||0)%3600)/60)}m`:'—'; $('apiResources').textContent=api.status==='connected'?`${compact(memory.resident_set_memory||0)}B / ${Number(loads[0]||0).toFixed(2)}`:'—';
    const body=$('apiWorkersBody');body.replaceChildren();$('apiWorkersEmpty').style.display=workers.length?'none':'block';
    for(const worker of workers){const tr=document.createElement('tr');td(tr,worker.name||'—');td(tr,String(worker.connections||0));td(tr,compact((worker.hashrate||[])[0]));td(tr,compact((worker.hashrate||[])[1]));td(tr,String(worker.accepted||0),statusClass('accepted'));td(tr,String(worker.rejected||0),worker.rejected?'status-rejected':'');td(tr,String(worker.invalid||0),worker.invalid?'status-rejected':'');td(tr,exact(worker.hashes));tr.addEventListener('click',()=>showDetails(worker));body.appendChild(tr);}
  }
  function renderTop() {
    const body=$('topBody'); body.replaceChildren(); $('topEmpty').style.display=model.top.length?'none':'block';
    model.top.forEach((share,index)=>{const tr=document.createElement('tr');td(tr,String(index+1));td(tr,time(share.time_utc));const d=td(tr,exact(share.share_diff));d.title=`Reported difficulty ${share.share_diff}`;td(tr,share.miner_id?`m${share.miner_id}${share.mapper_id?`/p${share.mapper_id}`:''}`:'—');td(tr,share.worker||'—');td(tr,share.height||'—');td(tr,share.status==='accepted_upstream'?'upstream':'local',statusClass(share.status));tr.addEventListener('click',()=>showDetails(share));body.appendChild(tr);});
  }
  function filteredEvents() {
    const category=$('category').value, query=$('search').value.trim().toLowerCase(); let values=model.events;
    if(category!=='all'){const fn=groups[category];values=values.filter(row=>fn(row.event||'',row));}
    if(query) values=values.filter(row=>JSON.stringify(row).toLowerCase().includes(query));
    return values.slice(-1000);
  }
  let scheduled=false, forceFollow=false;
  function scheduleTimeline(force){forceFollow=forceFollow||force;if(scheduled)return;scheduled=true;setTimeout(()=>{scheduled=false;renderTimeline(forceFollow);forceFollow=false;},100);}
  function renderTimeline(force) {
    const values=filteredEvents(),body=$('eventsBody'),scroller=$('eventsScroll');body.replaceChildren();
    for(const row of values){const tr=document.createElement('tr');td(tr,time(row.time_utc));td(tr,row.event||'—',eventClass(row.event||''));td(tr,row.miner_id?`m${row.miner_id}${row.mapper_id?`/p${row.mapper_id}`:''}${row.worker?` · ${row.worker}`:''}`:'—');td(tr,row.source_id?`S${row.source_id}${row.template_id?`:T${row.template_id}`:''}`:'—');td(tr,row.height||'—');const diff=td(tr,compact(row.share_diff));if(row.share_diff)diff.title=exact(row.share_diff);td(tr,row.status||'—',statusClass(row.status));td(tr,detailText(row));tr.addEventListener('click',()=>showDetails(row));body.appendChild(tr);}
    $('eventCount').textContent=`${values.length} shown · ${model.events.length} buffered`;
    if((force||$('follow').checked)&&!model.paused) scroller.scrollTop=scroller.scrollHeight;
  }
  function showDetails(value){$('details').textContent=JSON.stringify(value,null,2);}

  $('category').addEventListener('change',()=>scheduleTimeline(false)); $('search').addEventListener('input',()=>scheduleTimeline(false));
  $('pause').addEventListener('click',()=>{model.paused=!model.paused;if(model.paused){$('pause').textContent='Resume';}else{model.pending=0;$('pause').textContent='Pause view';scheduleTimeline(true);}});
  $('clear').addEventListener('click',()=>{model.events=[];scheduleTimeline(false);}); $('closeDetails').addEventListener('click',()=>{$('details').textContent='Select a timeline row to inspect every field.';});

  const stream=new EventSource('/api/stream');
  stream.onopen=()=>{const badge=$('browserBadge');badge.textContent='dashboard: live';badge.className='badge ok';};
  stream.addEventListener('snapshot',event=>applySnapshot(JSON.parse(event.data)));
  stream.addEventListener('update',event=>applyUpdate(JSON.parse(event.data)));
  stream.addEventListener('state',event=>applyState(JSON.parse(event.data)));
  stream.onerror=()=>{const badge=$('browserBadge');badge.textContent='dashboard: reconnecting';badge.className='badge warn';};
  setInterval(()=>{renderHeader();renderSources();renderApiAge();},1000);
})();
</script>
</body>
</html>
'''


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], state: DashboardState) -> None:
        self.dashboard_state = state
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "XMRigEventDashboard/1"

    @property
    def state(self) -> DashboardState:
        return self.server.dashboard_state  # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10.0)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    @staticmethod
    def _loopback_authority(value: str, origin: bool) -> bool:
        try:
            parsed = urlsplit(value if origin else "http://" + value)
            return (
                parsed.scheme in {"http", "https"}
                and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                and not parsed.username
                and not parsed.password
            )
        except ValueError:
            return False

    def _request_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        if not host or not self._loopback_authority(host, False):
            return False
        origin = self.headers.get("Origin")
        return origin is None or self._loopback_authority(origin, True)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'unsafe-inline'; script-src 'unsafe-inline'; object-src 'none'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )

    def _send_bytes(self, status: int, content_type: str, body: bytes, head_only: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send_json(self, status: int, payload: Dict[str, Any], head_only: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", body, head_only)

    def _route(self, head_only: bool = False) -> None:
        if not self._request_allowed():
            self._send_json(421, {"error": "loopback Host/Origin required"}, head_only)
            return
        path = urlsplit(self.path).path
        if path == "/":
            self._send_bytes(200, "text/html; charset=utf-8", HTML.encode("utf-8"), head_only)
        elif path == "/api/snapshot":
            self._send_json(200, self.state.snapshot(), head_only)
        elif path == "/healthz":
            health = self.state.health()
            self._send_json(200, {"ok": True, "socket_connected": health["socket_connected"]}, head_only)
        elif path == "/readyz":
            health = self.state.health()
            ready = bool(health["socket_connected"] and health["reader_status"] == "connected")
            self._send_json(
                200 if ready else 503,
                {"ready": ready, "reader_status": health["reader_status"]},
                head_only,
            )
        elif path == "/api/stream" and not head_only:
            self._stream()
        else:
            self._send_json(404, {"error": "not found"}, head_only)

    def do_GET(self) -> None:  # noqa: N802
        self._route(False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._route(True)

    def do_POST(self) -> None:  # noqa: N802
        if not self._request_allowed():
            self._send_json(421, {"error": "loopback Host/Origin required"})
            return
        self._send_json(405, {"error": "read-only dashboard"})

    def _write_sse(self, event: str, payload: Dict[str, Any], event_id: Optional[int] = None) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if event_id is not None:
            self.wfile.write(f"id: {event_id}\n".encode("ascii"))
        self.wfile.write(f"event: {event}\n".encode("ascii"))
        self.wfile.write(f"data: {encoded}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _stream(self) -> None:
        try:
            subscriber, snapshot = self.state.subscribe()
        except SubscriberLimitError as exc:
            self._send_json(503, {"error": str(exc)})
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self._security_headers()
            self.end_headers()
            self.wfile.write(b"retry: 1000\n\n")
            self._write_sse("snapshot", snapshot, snapshot["viewer_seq"])

            while not subscriber.closed.is_set():
                try:
                    payload = subscriber.messages.get(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if subscriber.closed.is_set():
                    break
                self._write_sse(payload.get("kind", "update"), payload, payload.get("viewer_seq"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.close_connection = True
            self.state.unsubscribe(subscriber)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Serve a local web dashboard for the XMRig Proxy schema-v2 Unix event stream."
    )
    parser.add_argument("socket", nargs="?", default=DEFAULT_SOCKET, help=f"Unix socket path (default: {DEFAULT_SOCKET})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"localhost HTTP port (default: {DEFAULT_PORT})")
    parser.add_argument("--max-events", type=int, default=5000, metavar="N", help="bounded timeline rows kept in memory (default: 5000)")
    parser.add_argument("--top-shares", type=int, default=5, metavar="N", help="accepted shares ranked by share difficulty (verifier-computed when enabled; default: 5)")
    parser.add_argument("--retry-cap", type=float, default=5.0, metavar="SECONDS", help="maximum socket reconnect delay (default: 5)")
    parser.add_argument("--api-url", metavar="URL", help="optional loopback XMRig Proxy API base URL, for example http://127.0.0.1:8080")
    parser.add_argument("--api-token-env", default="XMRIG_PROXY_API_TOKEN", metavar="NAME", help="environment variable holding the API token (default: XMRIG_PROXY_API_TOKEN)")
    parser.add_argument("--api-token-file", metavar="FILE", help="alternative mode-0600 file containing the API token")
    parser.add_argument("--api-interval", type=float, default=5.0, metavar="SECONDS", help="API polling interval (default: 5; minimum: 1)")
    return parser


def normalize_api_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("--api-url must use http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--api-url cannot contain credentials, a query, or a fragment")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("--api-url must use a loopback host")
    if parsed.path not in {"", "/"}:
        raise ValueError("--api-url must be a base origin without a path")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid --api-url port: {exc}") from exc
    return value.rstrip("/")


def load_api_token(args: argparse.Namespace) -> str:
    if args.api_token_file:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ValueError("--api-token-file requires O_NOFOLLOW support on this platform")
        descriptor = os.open(args.api_token_file, flags | nofollow)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("--api-token-file must be a regular, non-symlink file")
            if info.st_mode & 0o077:
                raise ValueError(
                    "--api-token-file must not be readable or writable by group/others (use chmod 600)"
                )
            with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
                token = handle.read(4097)
        finally:
            os.close(descriptor)
        if len(token) > 4096:
            raise ValueError("--api-token-file is unexpectedly large")
        token = token.rstrip("\r\n")
    else:
        token = os.environ.get(args.api_token_env, "")
    if not token:
        source = args.api_token_file or f"environment variable {args.api_token_env}"
        raise ValueError(f"API token is empty or missing in {source}")
    if "\r" in token or "\n" in token:
        raise ValueError("API token cannot contain a newline")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in token):
        raise ValueError("API token must contain printable ASCII characters without spaces")
    return token


def validate_args(args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    if not 100 <= args.max_events <= 100000:
        raise ValueError("--max-events must be between 100 and 100000")
    if not 0 <= args.top_shares <= 100:
        raise ValueError("--top-shares must be between 0 and 100")
    if not math.isfinite(args.retry_cap) or args.retry_cap <= 0:
        raise ValueError("--retry-cap must be a finite number greater than zero")
    if not math.isfinite(args.api_interval) or not 1.0 <= args.api_interval <= 60.0:
        raise ValueError("--api-interval must be a finite number between 1 and 60 seconds")
    if args.api_token_file and not args.api_url:
        raise ValueError("--api-token-file requires --api-url")


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    api_url = normalize_api_url(args.api_url) if args.api_url else ""
    api_token = load_api_token(args) if api_url else ""
    stop_event = threading.Event()
    state = DashboardState(
        args.socket, args.max_events, args.top_shares,
        api_enabled=bool(api_url), api_interval=args.api_interval,
    )
    reader = UnixEventReader(args.socket, state, stop_event, args.retry_cap)
    api_poller = ApiPoller(api_url, api_token, args.api_interval, state, stop_event) if api_url else None
    server = DashboardHTTPServer(("127.0.0.1", args.port), state)

    print(f"XMRig event dashboard: http://127.0.0.1:{args.port}/", flush=True)
    print(f"Consuming Unix socket: {args.socket}", flush=True)
    if api_url:
        print(f"Polling proxy API: {api_url} every {args.api_interval:g}s", flush=True)
    print("The HTTP listener is restricted to 127.0.0.1.", flush=True)

    reader.start()
    if api_poller:
        api_poller.start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 130
    finally:
        stop_event.set()
        reader.stop()
        server.shutdown()
        server.server_close()
        reader.join(timeout=3.0)
        if api_poller:
            api_poller.join(timeout=3.0)
        state.shutdown()
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if threading.current_thread() is threading.main_thread():
            def terminate(_signum: int, _frame: object) -> None:
                raise KeyboardInterrupt

            signal.signal(signal.SIGTERM, terminate)
        return run(args)
    except (OSError, ValueError) as exc:
        print(f"xmrig-events-web: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0)
