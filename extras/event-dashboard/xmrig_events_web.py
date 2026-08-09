#!/usr/bin/env python3
"""Local-only web dashboard for the XMRig Proxy schema-v2/v3 event socket."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import errno
import hashlib
import http.client
import json
import math
import os
import queue
import signal
import socket
import sqlite3
import stat
import sys
import threading
import time
import uuid
from collections import Counter, OrderedDict, deque
from decimal import Decimal, InvalidOperation, localcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import (
    HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm,
    HTTPRedirectHandler, ProxyHandler, Request, build_opener,
    parse_http_list, parse_keqv_list,
)


DEFAULT_SOCKET = "/run/xmrig-proxy/events.sock"
DEFAULT_PORT = 8787
DEFAULT_DATABASE = "xmrig-events.sqlite3"
DEFAULT_BIG_SHARE_DIFFICULTY = 20_000_000_000
DEFAULT_ROUND_TOP_SHARES = 1000
DEFAULT_WALLET_RPC_INTERVAL = 20.0
MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_BROWSER_SUBSCRIBERS = 5
MAX_SSE_QUEUE_BYTES = 16 * 1024 * 1024
MAX_LIVE_RING_BYTES = 16 * 1024 * 1024
MAX_LIVE_ROW_BYTES = 64 * 1024
SQLITE_QUEUE_BYTES = 32 * 1024 * 1024
MAX_PENDING_SUBMISSIONS = 256
MAX_SUBMISSION_ATTEMPTS = 16
MAX_PENDING_SUBMISSION_BYTES = 64 * 1024 * 1024
MAX_NONACCEPTED_BLOCKS = 1000
MAX_NONACCEPTED_BLOCK_BYTES = 64 * 1024 * 1024
MAX_PENDING_JOB_CONTEXTS = 10_000
MAX_PENDING_JOB_CONTEXT_BYTES = 64 * 1024 * 1024
MAX_PENDING_TEMPLATE_CONTEXTS = 1024
MAX_PENDING_TEMPLATE_CONTEXT_BYTES = 64 * 1024 * 1024
UINT64_MAX = (1 << 64) - 1

HEAVY_LIVE_FIELDS = (
    "hashing_blob", "blocktemplate_blob", "submitted_block_blob",
)

HEADER_V2 = (
    "schema_version", "event_seq", "time_utc", "event", "miner_id",
    "mapper_id", "miner_ip", "listen_port", "worker", "agent",
    "source_id", "template_id", "template_age_ms", "refresh_reason",
    "height", "prev_hash", "seed_hash", "algo", "job_id", "entropy_hex",
    "miner_target_diff", "network_target_diff", "share_id",
    "miner_request_id", "daemon_request_id", "nonce", "result_hash",
    "share_diff", "status", "error_code", "error_message", "latency_ms",
    "connection_ms", "rx_bytes", "tx_bytes",
)

# Schema v3 is strictly append-only so old captures remain readable.  Keep this
# order synchronized with LiveEventStream.cpp.
HEADER_V3_EXTRA = (
    "stream_id", "previous_seed_hash", "next_seed_hash", "hashing_blob",
    "blocktemplate_blob", "submitted_block_blob", "miner_target_hex",
    "nonce_offset", "nonce_size", "reserved_offset", "reserved_size",
    "extra_nonce_offset", "extra_nonce", "signature_hex",
    "view_tag", "block_id", "miner_tx_hash", "verifier_queue_ms",
    "verifier_hash_ms", "verifier_total_ms", "verifier_prepare_ms",
    "verifier_active", "verifier_queued", "verifier_queue_limit",
    "verifier_seed_count", "verifier_seed_capacity", "verifier_seed_role",
    "verifier_seed_status", "verifier_vm_pool_size", "verifier_stats_json",
)
HEADER_V3 = HEADER_V2 + HEADER_V3_EXTRA
HEADER = HEADER_V3
SUPPORTED_HEADERS = {HEADER_V2: "2", HEADER_V3: "3"}

NUMERIC_FIELDS = {
    "event_seq", "miner_id", "mapper_id", "listen_port", "source_id",
    "template_id", "template_age_ms", "height", "miner_target_diff",
    "network_target_diff", "share_id", "miner_request_id",
    "daemon_request_id", "share_diff", "error_code", "latency_ms",
    "connection_ms", "rx_bytes", "tx_bytes",
    "nonce_offset", "nonce_size", "reserved_offset", "reserved_size",
    "extra_nonce_offset", "extra_nonce", "view_tag",
    "verifier_active", "verifier_queued", "verifier_queue_limit",
    "verifier_seed_count", "verifier_seed_capacity", "verifier_vm_pool_size",
}

FLOAT_FIELDS = {
    "verifier_queue_ms", "verifier_hash_ms", "verifier_total_ms",
    "verifier_prepare_ms",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _utf8_size(value: Any) -> int:
    return len(str(value).encode("utf-8", errors="replace"))


def compact_live_row(row: Dict[str, Any], limit: int = MAX_LIVE_ROW_BYTES) -> Tuple[Dict[str, Any], int]:
    """Return a byte-bounded browser copy while leaving durable audit data intact."""
    result = dict(row)
    omitted: Dict[str, Dict[str, int]] = {}
    for name in HEAVY_LIVE_FIELDS:
        value = result.get(name)
        if not value:
            continue
        text = str(value)
        omitted[name] = {
            "hex_chars": len(text),
            "decoded_bytes": len(text) // 2,
        }
        result[name] = ""

    truncated: Dict[str, int] = {}
    # A malicious/local producer must not turn one non-blob string into an
    # unbounded timeline row. Preserve a useful prefix and record exact size.
    for name, value in tuple(result.items()):
        if not isinstance(value, str) or _utf8_size(value) <= 4096:
            continue
        truncated[name] = _utf8_size(value)
        encoded = value.encode("utf-8", errors="replace")[:4096]
        result[name] = encoded.decode("utf-8", errors="ignore") + "…"

    if omitted:
        result["_omitted_live_fields"] = omitted
    if truncated:
        result["_truncated_live_fields"] = truncated

    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > limit:
        # Schema fields are already small after the targeted removals. Retain
        # identity/status fields if an unexpectedly wide future schema arrives.
        keep = {
            "schema_version", "event_seq", "time_utc", "event", "stream_id",
            "miner_id", "mapper_id", "miner_label", "connection_uuid", "worker", "source_id", "template_id",
            "height", "job_id", "share_id", "status", "error_code",
            "error_message", "share_diff", "miner_target_diff",
            "network_target_diff", "block_id", "seed_hash",
            "_omitted_live_fields", "_truncated_live_fields",
        }
        result = {name: value for name, value in result.items() if name in keep}
        result["_live_row_compacted"] = True
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    return result, len(encoded)


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
    """Strict parser for append-only LiveEventStream schemas v2 and v3."""

    def __init__(self) -> None:
        self.header_seen = False
        self.line_number = 0
        self.header: Tuple[str, ...] = ()
        self.schema_version = ""

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
            candidate = tuple(values)
            version = SUPPORTED_HEADERS.get(candidate)
            if version is None:
                raise ProtocolError(
                    f"line {self.line_number}: expected an exact schema-v2 or schema-v3 "
                    f"header, received {len(values)} columns"
                )
            self.header = candidate
            self.schema_version = version
            self.header_seen = True
            return None

        if tuple(values) == self.header:
            return None
        if len(values) != len(self.header):
            raise ProtocolError(
                f"line {self.line_number}: expected {len(self.header)} columns, received {len(values)}"
            )

        row = {name: "" for name in HEADER_V3}
        row.update(zip(self.header, values))
        if row["schema_version"] != self.schema_version:
            raise ProtocolError(
                f"line {self.line_number}: header is schema v{self.schema_version} but row "
                f"declares schema_version={row['schema_version']!r}"
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

        for name in FLOAT_FIELDS:
            value = row[name]
            if not value:
                continue
            try:
                converted = float(value)
            except ValueError as exc:
                raise ProtocolError(
                    f"line {self.line_number}: {name} is not numeric: {value!r}"
                ) from exc
            if not math.isfinite(converted) or converted < 0:
                raise ProtocolError(
                    f"line {self.line_number}: {name} must be finite and non-negative"
                )

        if int(row["event_seq"], 10) <= 0:
            raise ProtocolError(f"line {self.line_number}: event_seq must be positive")
        if row["share_diff"] and int(row["share_diff"], 10) < 0:
            raise ProtocolError(f"line {self.line_number}: share_diff cannot be negative")
        for name in ("miner_target_diff", "network_target_diff", "share_diff"):
            if row[name] and not 0 <= int(row[name], 10) <= UINT64_MAX:
                raise ProtocolError(
                    f"line {self.line_number}: {name} must fit an unsigned 64-bit integer"
                )
        if self.schema_version == "3":
            stream_id = row["stream_id"]
            if (
                len(stream_id) != 32
                or stream_id != stream_id.lower()
                or any(char not in "0123456789abcdef" for char in stream_id)
            ):
                raise ProtocolError(
                    f"line {self.line_number}: stream_id must be 128-bit lowercase hex"
                )
        for name in (
            "prev_hash", "seed_hash", "previous_seed_hash", "next_seed_hash",
            "result_hash", "block_id", "miner_tx_hash",
        ):
            value = row[name]
            if value and (
                len(value) != 64 or value != value.lower()
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise ProtocolError(
                    f"line {self.line_number}: {name} must be 256-bit lowercase hex"
                )
        for name in (
            "hashing_blob", "blocktemplate_blob", "submitted_block_blob",
            "miner_target_hex", "signature_hex",
        ):
            value = row[name]
            if value and (
                len(value) % 2 != 0 or value != value.lower()
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise ProtocolError(
                    f"line {self.line_number}: {name} must be lowercase even-length hex"
                )
        if row["verifier_stats_json"]:
            try:
                stats = json.loads(row["verifier_stats_json"])
            except json.JSONDecodeError as exc:
                raise ProtocolError(
                    f"line {self.line_number}: verifier_stats_json is invalid JSON"
                ) from exc
            if not isinstance(stats, dict):
                raise ProtocolError(
                    f"line {self.line_number}: verifier_stats_json must be a JSON object"
                )

        return row


class Subscriber:
    def __init__(self, messages: "queue.Queue[Tuple[str, Optional[int], bytes]]",
                 closed: threading.Event,
                 byte_limit: int = MAX_SSE_QUEUE_BYTES) -> None:
        self.messages = messages
        self.closed = closed
        self.byte_limit = byte_limit
        self.queued_bytes = 0
        self.budget_lock = threading.Lock()

    def put_nowait(self, event: str, event_id: Optional[int], encoded: bytes) -> bool:
        size = len(encoded)
        with self.budget_lock:
            if size > self.byte_limit - self.queued_bytes:
                return False
            try:
                self.messages.put_nowait((event, event_id, encoded))
            except queue.Full:
                return False
            self.queued_bytes += size
            return True

    def get_message(self, timeout: Optional[float] = None) -> Tuple[str, Optional[int], bytes]:
        event, event_id, encoded = self.messages.get(timeout=timeout)
        with self.budget_lock:
            self.queued_bytes = max(0, self.queued_bytes - len(encoded))
        return event, event_id, encoded

    def get(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        _event, _event_id, encoded = self.get_message(timeout)
        payload = json.loads(encoded)
        return payload if isinstance(payload, dict) else {}

    def get_nowait(self) -> Dict[str, Any]:
        return self.get(timeout=0)


def _finite_number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        converted = float(value)
        if math.isfinite(converted):
            return converted
    return default


def _hashrate_number(value: Any) -> Optional[Any]:
    """Preserve a valid API rate's raw JSON number; unknown/negative is absent."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        converted = float(value)
        if math.isfinite(converted) and converted >= 0:
            return value
    return None


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
    daemon_solo = document.get("daemon_solo") if isinstance(document.get("daemon_solo"), dict) else {}
    payout_values = daemon_solo.get("payouts") if isinstance(daemon_solo.get("payouts"), list) else []
    payouts: List[Dict[str, Any]] = []
    for payout in payout_values[:16]:
        if not isinstance(payout, dict) or not isinstance(payout.get("address"), str):
            continue
        payouts.append({
            "address": payout["address"][:256],
            "coin": payout.get("coin", "")[:16] if isinstance(payout.get("coin"), str) else "",
            "network": payout.get("network", "")[:32] if isinstance(payout.get("network"), str) else "",
            "type": payout.get("type", "")[:16] if isinstance(payout.get("type"), str) else "",
            "validated": payout.get("validated") is True,
        })

    return {
        "id": str(document.get("id", ""))[:128],
        "worker_id": str(document.get("worker_id", ""))[:128],
        "version": str(document.get("version", ""))[:64],
        "mode": str(document.get("mode", ""))[:32],
        "uptime": _integer(document.get("uptime")),
        "restricted": bool(document.get("restricted", False)),
        "donate_level": _integer(document.get("donate_level")),
        "daemon_solo": {
            "enabled": bool(daemon_solo.get("enabled", False)),
            "payouts": payouts,
        },
        "hashrate": [_hashrate_number(value) for value in totals[:6]],
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
        elif mode not in {"rig_id", "user", "agent", "ip"}:
            name = "[worker name hidden: unknown mode]"
        workers.append({
            "name": name[:256],
            "connections": _integer(value[2]),
            "accepted": _integer(value[3]),
            "rejected": _integer(value[4]),
            "invalid": _integer(value[5]),
            "hashes": str(value[6]) if isinstance(value[6], int) else "0",
            "last_hash": _integer(value[7]),
            "hashrate": [_hashrate_number(item) for item in value[8:13]],
        })
    return workers


def api_worker_hash_total(document: Dict[str, Any]) -> Tuple[Optional[int], str]:
    """Return an exact aggregate from every worker row, or a coverage error.

    Browser output is intentionally capped, but the persistent ledger must not
    inherit that presentation limit.  Unknown/disabled grouping modes and
    malformed rows are treated as unavailable instead of silently counting
    them as zero.
    """
    mode = document.get("mode") if isinstance(document.get("mode"), str) else ""
    if mode == "password":
        return None, "worker hashes are unavailable in password mode"
    if mode == "none":
        return None, "worker hash tracking is disabled (workers mode none)"
    if mode not in {"rig_id", "user", "agent", "ip"}:
        return None, f"unknown workers mode: {mode or '[missing]'}"
    values = document.get("workers")
    if not isinstance(values, list):
        return None, "workers response does not contain an array"
    total = 0
    for index, value in enumerate(values):
        if not isinstance(value, list) or len(value) < 13:
            return None, f"malformed worker row at index {index}"
        hashes = value[6]
        if type(hashes) is not int or hashes < 0:
            return None, f"invalid worker hash counter at index {index}"
        total += hashes
    return total, ""


def sanitize_wallet_transfers(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Allowlist confirmed coinbase rewards returned by ``get_transfers``.

    Current monero-wallet-rpc labels an incoming miner transaction ``block``.
    Ordinary incoming payments and every outgoing/pending/failed category are
    deliberately excluded from both browser state and SQLite persistence.
    """
    values = document.get("in") if isinstance(document.get("in"), list) else []
    transfers: List[Dict[str, Any]] = []
    for value in values[:10000]:
        if not isinstance(value, dict) or value.get("type") != "block":
            continue
        txid = value.get("txid")
        if (
            not isinstance(txid, str) or len(txid) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in txid)
        ):
            continue
        amount = value.get("amount")
        if type(amount) is not int or amount < 0:
            continue
        subaddress = value.get("subaddr_index")
        if not isinstance(subaddress, dict):
            subaddress = {}
        transfers.append({
            "txid": txid.lower(),
            "type": "block",
            "amount_atomic": str(amount),
            "height": max(0, _integer(value.get("height"))),
            "timestamp": max(0, _integer(value.get("timestamp"))),
            "confirmations": max(0, _integer(value.get("confirmations"))),
            "unlock_time": str(value.get("unlock_time", "0"))[:32],
            "locked": value.get("locked") is True,
            "account_index": max(0, _integer(subaddress.get("major"))),
            "subaddress_index": max(0, _integer(subaddress.get("minor"))),
        })
    transfers.sort(
        key=lambda item: (item["height"], item["timestamp"], item["txid"]),
        reverse=True,
    )
    return transfers


class SQLiteStore:
    """Single-writer durable statistics store.

    The socket and HTTP threads only enqueue immutable messages.  SQLite work
    happens on this thread in WAL transactions, so a slow checkpoint or query
    cannot stall share handling or the event reader.
    """

    SCHEMA_VERSION = 8

    def __init__(self, path: str, big_share_difficulty: int = DEFAULT_BIG_SHARE_DIFFICULTY,
                 round_top_limit: int = DEFAULT_ROUND_TOP_SHARES,
                 queue_limit: int = 4096,
                 queue_byte_limit: int = SQLITE_QUEUE_BYTES) -> None:
        self.path = os.path.abspath(os.path.expanduser(path))
        self.big_share_difficulty = big_share_difficulty
        self.round_top_limit = round_top_limit
        self._queue: "queue.Queue[Tuple[str, Any, int]]" = queue.Queue(maxsize=queue_limit)
        self._queue_byte_limit = max(MAX_LINE_BYTES, int(queue_byte_limit))
        self._queue_bytes = 0
        self._queue_budget_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="xmrig-dashboard-sqlite-writer", daemon=True,
        )
        self._cache_lock = threading.RLock()
        self._run_id = uuid.uuid4().hex
        self._dropped = 0
        self._drop_pending = False
        self._update_callback: Optional[Any] = None
        self._last_callback = 0.0
        self._db_identity: Optional[Tuple[int, int]] = None
        self._cache: Dict[str, Any] = {
            "enabled": True,
            "status": "starting",
            "message": "opening SQLite database",
            "path": self.path,
            "schema_version": self.SCHEMA_VERSION,
            "tracking_since": "",
            "queue_depth": 0,
            "queue_limit": queue_limit,
            "queue_bytes": 0,
            "queue_byte_limit": self._queue_byte_limit,
            "dropped_messages": 0,
            "coverage_complete": True,
            "current_round": {},
            "recent_rounds": [],
            "recent_blocks": [],
            "big_shares": [],
            "big_share_count": 0,
            "wallet_transfers": [],
            "cumulative": {},
            "verifier": {},
        }
        self._prepare_path()
        connection = self._connect()
        try:
            self._migrate(connection)
            self._initialize(connection)
            self._refresh_cache(connection, "ready", "SQLite persistence active")
        finally:
            connection.close()

    def _prepare_path(self) -> None:
        parent = os.path.dirname(self.path) or "."
        try:
            parent_info = os.stat(parent, follow_symlinks=False)
        except FileNotFoundError:
            raise ValueError(f"database parent directory does not exist: {parent}")
        if not stat.S_ISDIR(parent_info.st_mode):
            raise ValueError(f"database parent is not a directory: {parent}")
        if parent_info.st_mode & 0o022:
            raise ValueError(
                "database parent directory must not be writable by group/others"
            )
        if os.geteuid() != 0 and parent_info.st_uid not in {0, os.geteuid()}:
            raise ValueError(
                "database parent directory must be owned by root or the dashboard user"
            )
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ValueError("SQLite persistence requires O_NOFOLLOW support")
        descriptor = os.open(self.path, flags | nofollow, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("--database must be a regular, non-symlink file")
            if info.st_mode & 0o077:
                os.fchmod(descriptor, 0o600)
            self._db_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(descriptor)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        info = os.stat(self.path, follow_symlinks=False)
        if self._db_identity is None or (info.st_dev, info.st_ino) != self._db_identity:
            connection.close()
            raise ValueError("SQLite database path changed after validation")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def _read_connect(self) -> sqlite3.Connection:
        uri = "file:" + quote(self.path, safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        info = os.stat(self.path, follow_symlinks=False)
        if self._db_identity is None or (info.st_dev, info.st_ino) != self._db_identity:
            connection.close()
            raise ValueError("SQLite database path changed after validation")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @staticmethod
    def _apply_migration(db: sqlite3.Connection, script: str) -> None:
        """Apply one schema step atomically, including its user_version bump."""
        try:
            # sqlite3.Connection.executescript() otherwise commits any active
            # transaction before it starts. Put the transaction control in
            # the script itself so partial DDL cannot survive a failed step.
            db.executescript("BEGIN IMMEDIATE;\n" + script + "\nCOMMIT;")
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise

    def _migrate(self, db: sqlite3.Connection) -> None:
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if version > self.SCHEMA_VERSION:
            raise ValueError(
                f"database schema {version} is newer than supported schema {self.SCHEMA_VERSION}"
            )
        if version == 0:
            self._apply_migration(db, """
                    CREATE TABLE meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE stream_positions (
                        stream_id TEXT PRIMARY KEY,
                        last_event_seq INTEGER NOT NULL,
                        last_event_utc TEXT NOT NULL
                    );
                    CREATE TABLE rounds (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        started_utc TEXT NOT NULL,
                        ended_utc TEXT,
                        start_height TEXT NOT NULL DEFAULT '',
                        end_height TEXT NOT NULL DEFAULT '',
                        network_diff_start TEXT NOT NULL DEFAULT '0',
                        network_diff_end TEXT NOT NULL DEFAULT '0',
                        credited_hashes TEXT NOT NULL DEFAULT '0',
                        observed_diff_sum TEXT NOT NULL DEFAULT '0',
                        effort_units TEXT NOT NULL DEFAULT '0',
                        accepted_shares INTEGER NOT NULL DEFAULT 0,
                        coverage_complete INTEGER NOT NULL DEFAULT 1,
                        closing_block_id INTEGER,
                        status TEXT NOT NULL DEFAULT 'active'
                    );
                    CREATE TABLE shares (
                        event_key TEXT PRIMARY KEY,
                        round_id INTEGER NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
                        time_utc TEXT NOT NULL,
                        share_id TEXT NOT NULL DEFAULT '',
                        source_id TEXT NOT NULL DEFAULT '',
                        template_id TEXT NOT NULL DEFAULT '',
                        job_id TEXT NOT NULL DEFAULT '',
                        miner_id TEXT NOT NULL DEFAULT '',
                        mapper_id TEXT NOT NULL DEFAULT '',
                        worker TEXT NOT NULL DEFAULT '',
                        height TEXT NOT NULL DEFAULT '',
                        share_diff TEXT NOT NULL,
                        share_diff_sort TEXT NOT NULL,
                        credited_diff TEXT NOT NULL,
                        network_diff TEXT NOT NULL,
                        effort_units TEXT NOT NULL,
                        status TEXT NOT NULL,
                        is_big INTEGER NOT NULL,
                        is_top INTEGER NOT NULL DEFAULT 1,
                        job_context_key TEXT NOT NULL DEFAULT '',
                        template_context_key TEXT NOT NULL DEFAULT '',
                        row_json TEXT NOT NULL
                    );
                    CREATE INDEX shares_round_rank ON shares(round_id, share_diff_sort DESC);
                    CREATE INDEX shares_big_time ON shares(is_big, time_utc DESC);
                    CREATE TABLE job_contexts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        correlation_key TEXT UNIQUE NOT NULL,
                        updated_utc TEXT NOT NULL,
                        retained INTEGER NOT NULL DEFAULT 0,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        context_json TEXT NOT NULL
                    );
                    CREATE INDEX job_contexts_updated ON job_contexts(updated_utc);
                    CREATE INDEX IF NOT EXISTS job_contexts_retained_budget ON job_contexts(retained,id DESC,size_bytes);
                    CREATE INDEX shares_job_context ON shares(job_context_key);
                    CREATE INDEX shares_template_context ON shares(template_context_key);
                    CREATE TABLE template_contexts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        correlation_key TEXT UNIQUE NOT NULL,
                        updated_utc TEXT NOT NULL,
                        retained INTEGER NOT NULL DEFAULT 0,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        context_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS template_contexts_retained_budget ON template_contexts(retained,id DESC,size_bytes);
                    CREATE TABLE pending_submissions (
                        correlation_key TEXT PRIMARY KEY,
                        time_utc TEXT NOT NULL,
                        row_json TEXT NOT NULL
                    );
                    CREATE TABLE blocks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_key TEXT UNIQUE NOT NULL,
                        round_id INTEGER NOT NULL REFERENCES rounds(id),
                        time_utc TEXT NOT NULL,
                        height TEXT NOT NULL DEFAULT '',
                        block_id TEXT NOT NULL DEFAULT '',
                        share_id TEXT NOT NULL DEFAULT '',
                        source_id TEXT NOT NULL DEFAULT '',
                        template_id TEXT NOT NULL DEFAULT '',
                        job_id TEXT NOT NULL DEFAULT '',
                        share_diff TEXT NOT NULL DEFAULT '0',
                        network_diff TEXT NOT NULL DEFAULT '0',
                        latency_ms TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        correlation_key TEXT NOT NULL,
                        submit_json TEXT NOT NULL DEFAULT '{}',
                        result_json TEXT NOT NULL,
                        round_closed INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE INDEX blocks_time ON blocks(time_utc DESC);
                    CREATE TABLE verifier_totals (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        requests INTEGER NOT NULL DEFAULT 0,
                        results INTEGER NOT NULL DEFAULT 0,
                        mismatches INTEGER NOT NULL DEFAULT 0,
                        errors INTEGER NOT NULL DEFAULT 0,
                        queue_samples INTEGER NOT NULL DEFAULT 0,
                        hash_samples INTEGER NOT NULL DEFAULT 0,
                        total_samples INTEGER NOT NULL DEFAULT 0,
                        queue_ms TEXT NOT NULL DEFAULT '0',
                        hash_ms TEXT NOT NULL DEFAULT '0',
                        total_ms TEXT NOT NULL DEFAULT '0',
                        last_event_utc TEXT NOT NULL DEFAULT '',
                        last_status_json TEXT NOT NULL DEFAULT '{}'
                    );
                    INSERT INTO verifier_totals(id) VALUES(1);
                    CREATE TABLE verifier_seeds (
                        seed_hash TEXT PRIMARY KEY,
                        role TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL DEFAULT '',
                        prepare_ms TEXT NOT NULL DEFAULT '',
                        updated_utc TEXT NOT NULL,
                        active INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS wallet_transfers (
                        txid TEXT PRIMARY KEY,
                        amount_atomic TEXT NOT NULL,
                        height INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        confirmations INTEGER NOT NULL,
                        unlock_time TEXT NOT NULL,
                        locked INTEGER NOT NULL,
                        account_index INTEGER NOT NULL,
                        subaddress_index INTEGER NOT NULL,
                        first_seen_utc TEXT NOT NULL,
                        last_seen_utc TEXT NOT NULL,
                        row_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS wallet_transfers_height ON wallet_transfers(height DESC,timestamp DESC);
                    PRAGMA user_version=8;
                """)
            version = 8
        if version == 1:
            self._apply_migration(db, """
                    CREATE TABLE job_contexts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        correlation_key TEXT UNIQUE NOT NULL,
                        updated_utc TEXT NOT NULL,
                        context_json TEXT NOT NULL
                    );
                    CREATE INDEX job_contexts_updated ON job_contexts(updated_utc);
                    PRAGMA user_version=2;
                """)
            version = 2
        if version == 2:
            self._apply_migration(db, """
                    ALTER TABLE shares ADD COLUMN job_context_key TEXT NOT NULL DEFAULT '';
                    ALTER TABLE job_contexts ADD COLUMN retained INTEGER NOT NULL DEFAULT 0;
                    CREATE INDEX shares_job_context ON shares(job_context_key);
                    PRAGMA user_version=3;
                """)
            version = 3
        if version == 3:
            self._apply_migration(db, """
                    ALTER TABLE job_contexts ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0;
                    UPDATE job_contexts SET size_bytes=length(CAST(context_json AS BLOB));
                    PRAGMA user_version=4;
                """)
            version = 4
        if version == 4:
            self._apply_migration(db, """
                    ALTER TABLE shares ADD COLUMN template_context_key TEXT NOT NULL DEFAULT '';
                    CREATE INDEX shares_template_context ON shares(template_context_key);
                    CREATE TABLE template_contexts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        correlation_key TEXT UNIQUE NOT NULL,
                        updated_utc TEXT NOT NULL,
                        retained INTEGER NOT NULL DEFAULT 0,
                        size_bytes INTEGER NOT NULL DEFAULT 0,
                        context_json TEXT NOT NULL
                    );
                    PRAGMA user_version=5;
                """)
            version = 5
        if version == 5:
            self._apply_migration(db, """
                    ALTER TABLE verifier_totals ADD COLUMN queue_samples INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE verifier_totals ADD COLUMN hash_samples INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE verifier_totals ADD COLUMN total_samples INTEGER NOT NULL DEFAULT 0;
                    UPDATE verifier_totals SET
                        queue_samples=CASE WHEN CAST(queue_ms AS REAL)>0 THEN results ELSE 0 END,
                        hash_samples=CASE WHEN CAST(hash_ms AS REAL)>0 THEN results ELSE 0 END,
                        total_samples=CASE WHEN CAST(total_ms AS REAL)>0 THEN results ELSE 0 END;
                    PRAGMA user_version=6;
                """)
            version = 6
        if version == 6:
            self._apply_migration(db, """
                    CREATE INDEX IF NOT EXISTS job_contexts_retained_budget ON job_contexts(retained,id DESC,size_bytes);
                    CREATE INDEX IF NOT EXISTS template_contexts_retained_budget ON template_contexts(retained,id DESC,size_bytes);
                    PRAGMA user_version=7;
                """)
            version = 7
        if version == 7:
            self._apply_migration(db, """
                    CREATE TABLE IF NOT EXISTS wallet_transfers (
                        txid TEXT PRIMARY KEY,
                        amount_atomic TEXT NOT NULL,
                        height INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        confirmations INTEGER NOT NULL,
                        unlock_time TEXT NOT NULL,
                        locked INTEGER NOT NULL,
                        account_index INTEGER NOT NULL,
                        subaddress_index INTEGER NOT NULL,
                        first_seen_utc TEXT NOT NULL,
                        last_seen_utc TEXT NOT NULL,
                        row_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS wallet_transfers_height ON wallet_transfers(height DESC,timestamp DESC);
                    PRAGMA user_version=8;
                """)

    @staticmethod
    def _meta_get(db: sqlite3.Connection, key: str, default: str = "") -> str:
        item = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(item[0]) if item is not None else default

    @staticmethod
    def _meta_set(db: sqlite3.Connection, key: str, value: Any) -> None:
        db.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def _initialize(self, db: sqlite3.Connection) -> None:
        with db:
            tracking_since = self._meta_get(db, "tracking_since")
            initialization_boundary = not tracking_since
            if not tracking_since:
                tracking_since = utc_now()
                self._meta_set(db, "tracking_since", tracking_since)
                self._meta_set(db, "credited_hashes_total", "0")
                self._meta_set(db, "observed_diff_total", "0")
                self._meta_set(db, "api_worker_hashes_total", "0")
                self._meta_set(db, "api_baseline_set", "0")
                self._meta_set(db, "event_coverage_complete", "1")
                self._meta_set(db, "api_coverage_complete", "1")
            else:
                # SQLite survived a dashboard process restart, but the Unix
                # stream has no replay. Even if the next sequence happens to
                # be contiguous, work may have occurred while no reader was
                # attached (especially with an older schema-v2 producer).
                self._meta_set(db, "event_coverage_complete", "0")
                self._meta_set(
                    db, "last_incomplete_reason",
                    "dashboard process restarted; event socket has no replay",
                )
            current = db.execute(
                "SELECT id FROM rounds WHERE status='active' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if current is None:
                cursor = db.execute(
                    "INSERT INTO rounds(started_utc,coverage_complete) VALUES(?,?)",
                    (tracking_since, 0 if initialization_boundary else 1),
                )
                if initialization_boundary:
                    self._meta_set(
                        db, "last_round_incomplete_reason",
                        "initialization boundary; earlier work was intentionally not backfilled",
                    )
                self._meta_set(db, "current_round_id", cursor.lastrowid)
            else:
                if not initialization_boundary:
                    db.execute(
                        "UPDATE rounds SET coverage_complete=0 WHERE id=?",
                        (current[0],),
                    )
                self._meta_set(db, "current_round_id", current[0])
            if not initialization_boundary:
                self._recover_closing_round(
                    db,
                    "dashboard restarted after an accepted block result but before the winning share was durably credited",
                )

    def start(self) -> None:
        self._thread.start()

    def set_update_callback(self, callback: Any) -> None:
        self._update_callback = callback

    def close(self, timeout: float = 10.0) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(("stop", None, 0))
        except queue.Full:
            pass
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @staticmethod
    def _message_size(kind: str, payload: Any) -> int:
        if kind == "event" and isinstance(payload, tuple) and payload:
            value = payload[0]
        else:
            value = payload
        try:
            overhead = 256 + (len(value) * 96 if isinstance(value, dict) else 0)
            return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + overhead
        except (TypeError, ValueError):
            return MAX_LINE_BYTES

    def _queue_overflow(self, reason: str) -> bool:
        with self._cache_lock:
            self._dropped += 1
            self._drop_pending = True
            self._cache["dropped_messages"] = self._dropped
            self._cache["coverage_complete"] = False
            self._cache["status"] = "degraded"
            self._cache["message"] = reason
        return False

    def _enqueue(self, kind: str, payload: Any) -> bool:
        size = self._message_size(kind, payload)
        with self._queue_budget_lock:
            if size > self._queue_byte_limit or self._queue_bytes + size > self._queue_byte_limit:
                return self._queue_overflow("SQLite ingestion byte budget overflowed")
            try:
                self._queue.put_nowait((kind, payload, size))
            except queue.Full:
                return self._queue_overflow("SQLite ingestion row queue overflowed")
            self._queue_bytes += size
        return True

    def enqueue_event(self, row: Dict[str, Any], viewer_session: int) -> bool:
        return self._enqueue("event", (dict(row), viewer_session))

    def enqueue_api(self, summary: Dict[str, Any], workers: Dict[str, Any]) -> bool:
        return self._enqueue("api", (dict(summary), dict(workers), utc_now(), time.time()))

    def enqueue_wallet_transfers(self, transfers: Sequence[Dict[str, Any]]) -> bool:
        return self._enqueue(
            "wallet", ([dict(value) for value in transfers], utc_now()),
        )

    def mark_incomplete(self, reason: str) -> bool:
        return self._enqueue("incomplete", str(reason)[:512])

    def mark_api_incomplete(self, reason: str) -> bool:
        return self._enqueue("api_incomplete", str(reason)[:512])

    def snapshot(self) -> Dict[str, Any]:
        with self._cache_lock:
            result = json.loads(json.dumps(self._cache))
            result["queue_depth"] = self._queue.qsize()
            result["dropped_messages"] = self._dropped
        with self._queue_budget_lock:
            result["queue_bytes"] = self._queue_bytes
            return result

    @staticmethod
    def _row_dict(value: Optional[sqlite3.Row]) -> Dict[str, Any]:
        return dict(value) if value is not None else {}

    @staticmethod
    def _effort_percent(value: Any) -> float:
        try:
            return float(Decimal(str(value)) * 100)
        except (InvalidOperation, ValueError, OverflowError):
            return 0.0

    def _round_json(self, row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        result["effort_percent"] = self._effort_percent(result.get("effort_units", "0"))
        return result

    def _refresh_cache(self, db: sqlite3.Connection, status: str = "ready",
                       message: str = "SQLite persistence active") -> None:
        current_row = db.execute(
            "SELECT * FROM rounds WHERE status='active' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        completed_rows = db.execute(
            "SELECT * FROM rounds WHERE status='closed' ORDER BY id DESC LIMIT 50"
        ).fetchall()
        block_rows = db.execute(
            "SELECT id,round_id,time_utc,height,block_id,share_id,source_id,template_id,job_id,"
            "share_diff,network_diff,latency_ms,status,round_closed FROM blocks "
            "WHERE status='accepted' ORDER BY id DESC LIMIT 50"
        ).fetchall()
        big_rows = db.execute(
            "SELECT event_key,round_id,time_utc,share_id,source_id,template_id,job_id,miner_id,mapper_id,worker,height,"
            "share_diff,credited_diff,network_diff,effort_units,status,is_top FROM shares "
            "WHERE is_big=1 ORDER BY time_utc DESC LIMIT 100"
        ).fetchall()
        big_count = int(db.execute("SELECT count(*) FROM shares WHERE is_big=1").fetchone()[0])
        wallet_rows = [dict(value) for value in db.execute(
            "SELECT txid,amount_atomic,height,timestamp,confirmations,unlock_time,locked,"
            "account_index,subaddress_index,first_seen_utc,last_seen_utc "
            "FROM wallet_transfers ORDER BY height DESC,timestamp DESC LIMIT 500"
        ).fetchall()]
        for value in wallet_rows:
            value["locked"] = bool(value.get("locked"))
            value["type"] = "block"
        verifier = self._row_dict(db.execute("SELECT * FROM verifier_totals WHERE id=1").fetchone())
        seeds = [dict(value) for value in db.execute(
            "SELECT * FROM verifier_seeds WHERE active=1 ORDER BY "
            "CASE role WHEN 'current' THEN 0 WHEN 'next' THEN 1 WHEN 'previous' THEN 2 ELSE 3 END, updated_utc DESC"
        ).fetchall()]
        for prefix in ("queue", "hash", "total"):
            count = int(verifier.get(f"{prefix}_samples", 0) or 0)
            try:
                verifier[f"average_{prefix}_ms"] = float(Decimal(verifier.get(f"{prefix}_ms", "0")) / count) if count else 0.0
            except (InvalidOperation, ValueError):
                verifier[f"average_{prefix}_ms"] = 0.0
        verifier["seeds"] = seeds
        try:
            verifier["status"] = json.loads(verifier.pop("last_status_json", "{}"))
        except json.JSONDecodeError:
            verifier["status"] = {}
        effort_sum = Decimal(0)
        effort_count = 0
        for value in db.execute(
            "SELECT effort_units FROM rounds WHERE status='closed' AND coverage_complete=1"
        ):
            try:
                effort_sum += Decimal(value[0])
                effort_count += 1
            except (InvalidOperation, TypeError, ValueError):
                continue
        average_effort = float(effort_sum * 100 / effort_count) if effort_count else 0.0
        event_total = self._meta_get(db, "credited_hashes_total", "0")
        api_total = self._meta_get(db, "api_worker_hashes_total", "0")
        try:
            reconciliation = str(int(api_total) - int(event_total))
        except ValueError:
            reconciliation = "0"
        coverage = self._meta_get(db, "event_coverage_complete", "1") == "1"
        coverage_reason = self._meta_get(db, "last_incomplete_reason", "")
        with self._queue_budget_lock:
            queue_bytes = self._queue_bytes
        cache = {
            "enabled": True,
            "status": status if coverage else "degraded",
            "message": message if coverage else "persistent coverage is incomplete; see reader/database events",
            "path": self.path,
            "schema_version": self.SCHEMA_VERSION,
            "tracking_since": self._meta_get(db, "tracking_since"),
            "queue_depth": self._queue.qsize(),
            "queue_limit": self._queue.maxsize,
            "queue_bytes": queue_bytes,
            "queue_byte_limit": self._queue_byte_limit,
            "dropped_messages": self._dropped,
            "coverage_complete": coverage,
            "coverage_reason": coverage_reason,
            "current_round": self._round_json(current_row) if current_row else {},
            "recent_rounds": [self._round_json(value) for value in completed_rows],
            "average_round_effort_percent": average_effort,
            "recent_blocks": [dict(value) for value in block_rows],
            "big_shares": [dict(value) for value in big_rows],
            "big_share_count": big_count,
            "wallet_transfers": wallet_rows,
            "cumulative": {
                "credited_hashes_events": event_total,
                "observed_share_difficulty_sum": self._meta_get(db, "observed_diff_total", "0"),
                "api_worker_hashes": api_total,
                "api_minus_events": reconciliation,
                "api_baseline_set": self._meta_get(db, "api_baseline_set", "0") == "1",
                "event_coverage_complete": coverage,
                "api_coverage_complete": self._meta_get(db, "api_coverage_complete", "1") == "1",
                "api_coverage_reason": self._meta_get(db, "last_api_incomplete_reason", ""),
                "api_status": self._meta_get(db, "api_status", "waiting"),
            },
            "verifier": verifier,
        }
        with self._cache_lock:
            self._cache = cache
        callback = self._update_callback
        now = time.monotonic()
        if callback is not None and now - self._last_callback >= 1.0:
            self._last_callback = now
            try:
                callback()
            except Exception:
                # Persistence remains independent of browser delivery.
                pass

    @staticmethod
    def _stream_key(row: Dict[str, Any], viewer_session: int, run_id: str) -> str:
        stream_id = str(row.get("stream_id", ""))
        return stream_id if stream_id else f"v2-{run_id}-{viewer_session}"

    @staticmethod
    def _correlation_key(row: Dict[str, Any]) -> str:
        parts = (
            row.get("stream_id", ""), row.get("source_id", ""),
            row.get("share_id", ""), row.get("job_id", ""),
            row.get("template_id", ""),
        )
        return hashlib.sha256("\x1f".join(str(value) for value in parts).encode()).hexdigest()

    @staticmethod
    def _event_key(row: Dict[str, Any], stream_key: str) -> str:
        return f"{stream_key}:{row.get('event_seq', '')}"

    @staticmethod
    def _job_base_key(row: Dict[str, Any], stream_key: str) -> str:
        parts = (
            stream_key, row.get("source_id", ""), row.get("template_id", ""),
            row.get("job_id", ""),
        )
        return hashlib.sha256("\x1f".join(str(value) for value in parts).encode()).hexdigest()

    @classmethod
    def _job_key(cls, row: Dict[str, Any], stream_key: str) -> str:
        base = cls._job_base_key(row, stream_key)
        miner_id = str(row.get("miner_id", ""))
        mapper_id = str(row.get("mapper_id", ""))
        if not miner_id and not mapper_id:
            return base
        return hashlib.sha256(
            "\x1f".join((base, miner_id, mapper_id)).encode()
        ).hexdigest()

    @staticmethod
    def _template_key(row: Dict[str, Any], stream_key: str) -> str:
        parts = (stream_key, row.get("source_id", ""), row.get("template_id", ""))
        return hashlib.sha256("\x1f".join(str(value) for value in parts).encode()).hexdigest()

    @staticmethod
    def _positive_int(value: Any) -> int:
        try:
            return max(0, int(str(value), 10))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _nonnegative_decimal(value: Any) -> Decimal:
        try:
            converted = Decimal(str(value))
            return converted if converted.is_finite() and converted >= 0 else Decimal(0)
        except (InvalidOperation, TypeError, ValueError):
            return Decimal(0)

    def _current_round_id(self, db: sqlite3.Connection) -> int:
        return int(self._meta_get(db, "current_round_id", "0"))

    @staticmethod
    def _submission_matches(block: sqlite3.Row, row: Dict[str, Any]) -> bool:
        share_id = str(row.get("share_id", ""))
        if share_id and str(block["share_id"]) == share_id:
            return True
        job_id = str(row.get("job_id", ""))
        return bool(
            job_id and str(block["job_id"]) == job_id
            and str(block["source_id"]) == str(row.get("source_id", ""))
        )

    def _recover_closing_round(self, db: sqlite3.Connection, reason: str,
                               incoming: Optional[Dict[str, Any]] = None) -> bool:
        active = db.execute(
            "SELECT * FROM rounds WHERE status='active' AND closing_block_id IS NOT NULL "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if active is None:
            return False
        block = db.execute("SELECT * FROM blocks WHERE id=?", (active["closing_block_id"],)).fetchone()
        if block is None:
            db.execute("UPDATE rounds SET coverage_complete=0 WHERE id=?", (active["id"],))
            self._meta_set(db, "event_coverage_complete", "0")
            self._meta_set(db, "last_incomplete_reason", reason)
            return False
        if (
            incoming is not None
            and incoming.get("event") == "share_result"
            and incoming.get("status") == "accepted_upstream"
            and self._submission_matches(block, incoming)
        ):
            return False

        ended = str(block["time_utc"] or utc_now())
        height = str(block["height"] or "")
        network = str(block["network_diff"] or "0")
        db.execute(
            "UPDATE rounds SET ended_utc=?,end_height=?,network_diff_end=?,status='closed',"
            "coverage_complete=0 WHERE id=?",
            (ended, height, network, active["id"]),
        )
        db.execute("UPDATE blocks SET round_closed=1 WHERE id=?", (block["id"],))
        cursor = db.execute(
            "INSERT INTO rounds(started_utc,start_height,network_diff_start,coverage_complete) "
            "VALUES(?,?,?,0)",
            (ended, height, network),
        )
        self._meta_set(db, "current_round_id", cursor.lastrowid)
        self._meta_set(db, "event_coverage_complete", "0")
        self._meta_set(db, "last_incomplete_reason", reason)
        return True

    def _observe_position(self, db: sqlite3.Connection, row: Dict[str, Any],
                          viewer_session: int) -> Tuple[bool, str]:
        stream_key = self._stream_key(row, viewer_session, self._run_id)
        sequence = self._positive_int(row.get("event_seq"))
        previous = db.execute(
            "SELECT last_event_seq FROM stream_positions WHERE stream_id=?", (stream_key,)
        ).fetchone()
        if previous is not None and sequence <= int(previous[0]):
            return False, stream_key
        sequence_gap = (
            previous is None and bool(row.get("stream_id")) and sequence != 1
        ) or (
            previous is not None and sequence != int(previous[0]) + 1
        )
        if not row.get("stream_id") or sequence_gap:
            db.execute(
                "UPDATE rounds SET coverage_complete=0 WHERE id=?",
                (self._current_round_id(db),),
            )
            reason = (
                "schema v2 has no durable stream identity"
                if not row.get("stream_id")
                else (
                    f"event sequence gap for {stream_key}: first observed {sequence}"
                    if previous is None
                    else f"event sequence gap for {stream_key}: {int(previous[0])} -> {sequence}"
                )
            )
            self._meta_set(db, "last_incomplete_reason", reason)
            self._meta_set(db, "event_coverage_complete", "0")
            self._recover_closing_round(db, reason, row)
        db.execute(
            "INSERT INTO stream_positions(stream_id,last_event_seq,last_event_utc) VALUES(?,?,?) "
            "ON CONFLICT(stream_id) DO UPDATE SET last_event_seq=excluded.last_event_seq,last_event_utc=excluded.last_event_utc",
            (stream_key, sequence, str(row.get("time_utc", ""))),
        )
        return True, stream_key

    def _seed_event(self, db: sqlite3.Connection, row: Dict[str, Any]) -> None:
        event = str(row.get("event", ""))
        if event not in {
            "verifier_seed_roles", "verifier_seed_prepare", "verifier_seed_ready",
            "verifier_seed_error", "verifier_seed_release", "verifier_status",
        }:
            return
        if event in {"verifier_seed_roles", "verifier_status"}:
            db.execute("UPDATE verifier_seeds SET role='' WHERE active=1")
            for field, role in (("previous_seed_hash", "previous"), ("seed_hash", "current"), ("next_seed_hash", "next")):
                seed = str(row.get(field, ""))
                if seed:
                    db.execute(
                        "INSERT INTO verifier_seeds(seed_hash,role,status,updated_utc,active) VALUES(?,?,?,?,1) "
                        "ON CONFLICT(seed_hash) DO UPDATE SET role=excluded.role,"
                        "status=CASE WHEN verifier_seeds.status IN ('ready','error','preparing') "
                        "THEN verifier_seeds.status ELSE excluded.status END,"
                        "updated_utc=excluded.updated_utc,active=1",
                        (seed, role, "observed", row.get("time_utc", "")),
                    )
            return
        seed = str(row.get("seed_hash", ""))
        if not seed:
            return
        status = str(row.get("verifier_seed_status") or row.get("status", ""))
        role = str(row.get("verifier_seed_role", ""))
        active = 0 if event == "verifier_seed_release" and status == "released" else 1
        db.execute(
            "INSERT INTO verifier_seeds(seed_hash,role,status,prepare_ms,updated_utc,active) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(seed_hash) DO UPDATE SET "
            "role=CASE WHEN excluded.role='' THEN verifier_seeds.role ELSE excluded.role END,"
            "status=excluded.status,prepare_ms=excluded.prepare_ms,updated_utc=excluded.updated_utc,active=excluded.active",
            (seed, role, status, str(row.get("verifier_prepare_ms", "")), row.get("time_utc", ""), active),
        )

    def _verification_event(self, db: sqlite3.Connection, row: Dict[str, Any]) -> None:
        event = str(row.get("event", ""))
        if event not in {"verify_requested", "verify_result", "verify_mismatch", "verify_error", "verifier_status"}:
            return
        requests = 1 if event == "verify_requested" else 0
        results = 1 if event in {"verify_result", "verify_mismatch", "verify_error"} else 0
        mismatches = 1 if event == "verify_mismatch" else 0
        errors = 1 if event == "verify_error" else 0
        queue_ms = self._nonnegative_decimal(row.get("verifier_queue_ms")) if results else Decimal(0)
        hash_ms = self._nonnegative_decimal(row.get("verifier_hash_ms")) if results else Decimal(0)
        total_ms = self._nonnegative_decimal(
            row.get("verifier_total_ms") or row.get("latency_ms")
        ) if results else Decimal(0)
        queue_samples = int(bool(results and row.get("verifier_queue_ms") != ""))
        hash_samples = int(bool(results and row.get("verifier_hash_ms") != ""))
        total_samples = int(bool(results and (
            row.get("verifier_total_ms") != "" or row.get("latency_ms") != ""
        )))
        status_json = "{}"
        if event == "verifier_status":
            parsed: Dict[str, Any] = {}
            if row.get("verifier_stats_json"):
                try:
                    candidate = json.loads(str(row["verifier_stats_json"]))
                    if isinstance(candidate, dict):
                        parsed = candidate
                except json.JSONDecodeError:
                    pass
            parsed.update({
                "health": row.get("status", ""),
                "active": self._positive_int(row.get("verifier_active")),
                "queued": self._positive_int(row.get("verifier_queued")),
                "queue_limit": self._positive_int(row.get("verifier_queue_limit")),
                "seed_count": self._positive_int(row.get("verifier_seed_count")),
                "seed_capacity": self._positive_int(row.get("verifier_seed_capacity")),
                "vm_pool_size": self._positive_int(row.get("verifier_vm_pool_size")),
                "previous_seed_hash": row.get("previous_seed_hash", ""),
                "current_seed_hash": row.get("seed_hash", ""),
                "next_seed_hash": row.get("next_seed_hash", ""),
            })
            status_json = json.dumps(parsed, separators=(",", ":"), sort_keys=True)
        totals = db.execute(
            "SELECT queue_ms,hash_ms,total_ms FROM verifier_totals WHERE id=1"
        ).fetchone()
        next_queue = self._nonnegative_decimal(totals[0]) + queue_ms
        next_hash = self._nonnegative_decimal(totals[1]) + hash_ms
        next_total = self._nonnegative_decimal(totals[2]) + total_ms
        db.execute(
            "UPDATE verifier_totals SET requests=requests+?,results=results+?,mismatches=mismatches+?,errors=errors+?,"
            "queue_samples=queue_samples+?,hash_samples=hash_samples+?,total_samples=total_samples+?,"
            "queue_ms=?,hash_ms=?,total_ms=?,last_event_utc=?,"
            "last_status_json=CASE WHEN ?='{}' THEN last_status_json ELSE ? END WHERE id=1",
            (requests, results, mismatches, errors, queue_samples, hash_samples, total_samples,
             str(next_queue), str(next_hash),
             str(next_total), row.get("time_utc", ""), status_json, status_json),
        )

    def _accepted_share(self, db: sqlite3.Connection, row: Dict[str, Any],
                        event_key: str, stream_key: str) -> None:
        if row.get("event") != "share_result" or row.get("status") not in {"accepted_local", "accepted_upstream"}:
            return
        share_diff = self._positive_int(row.get("share_diff"))
        credited = self._positive_int(row.get("miner_target_diff"))
        network = self._positive_int(row.get("network_target_diff"))
        if not credited:
            reason = f"accepted share {row.get('share_id', '?')} lacks miner_target_diff"
            db.execute(
                "UPDATE rounds SET coverage_complete=0 WHERE id=?",
                (self._current_round_id(db),),
            )
            self._meta_set(db, "last_incomplete_reason", reason)
            self._meta_set(db, "event_coverage_complete", "0")
            return
        if not network:
            reason = f"accepted share {row.get('share_id', '?')} lacks network_target_diff"
            db.execute(
                "UPDATE rounds SET coverage_complete=0 WHERE id=?",
                (self._current_round_id(db),),
            )
            self._meta_set(db, "last_incomplete_reason", reason)
            self._meta_set(db, "event_coverage_complete", "0")
        with localcontext() as context:
            context.prec = 60
            effort = Decimal(credited) / Decimal(network) if network else Decimal(0)
        correlated_block: Optional[sqlite3.Row] = None
        if row.get("status") == "accepted_upstream":
            correlated_block = db.execute(
                "SELECT id,round_id,round_closed FROM blocks WHERE status='accepted' "
                "AND correlation_key=? ORDER BY id DESC LIMIT 1",
                (self._correlation_key(row),),
            ).fetchone()
        # A dashboard restart/gap may have conservatively closed a round after
        # seeing the accepted submit result but before this winning share. If
        # the proxy was still completing that request, credit the exact
        # correlated share to its original (incomplete) round, never the new
        # round opened by recovery.
        round_id = (
            int(correlated_block["round_id"])
            if correlated_block is not None
            else self._current_round_id(db)
        )
        current = db.execute("SELECT * FROM rounds WHERE id=?", (round_id,)).fetchone()
        if current is None:
            return
        new_credited = int(current["credited_hashes"]) + credited
        new_observed = int(current["observed_diff_sum"]) + share_diff
        new_effort = Decimal(current["effort_units"]) + effort
        job_context_key = self._job_key(row, stream_key)
        template_context_key = self._template_key(row, stream_key)
        db.execute(
            "UPDATE rounds SET credited_hashes=?,observed_diff_sum=?,effort_units=?,accepted_shares=accepted_shares+1,"
            "start_height=CASE WHEN start_height='' THEN ? ELSE start_height END,"
            "network_diff_start=CASE WHEN network_diff_start='0' THEN ? ELSE network_diff_start END WHERE id=?",
            (str(new_credited), str(new_observed), str(new_effort), row.get("height", ""),
             str(network), round_id),
        )
        total_credited = int(self._meta_get(db, "credited_hashes_total", "0")) + credited
        total_observed = int(self._meta_get(db, "observed_diff_total", "0")) + share_diff
        self._meta_set(db, "credited_hashes_total", total_credited)
        self._meta_set(db, "observed_diff_total", total_observed)
        is_big = int(share_diff >= self.big_share_difficulty)
        durable_row = dict(row)
        job_snapshot = db.execute(
            "SELECT context_json FROM job_contexts WHERE correlation_key=?",
            (job_context_key,),
        ).fetchone()
        if job_snapshot is not None:
            try:
                parsed_snapshot = json.loads(job_snapshot[0])
                if isinstance(parsed_snapshot, dict):
                    # A job can be re-sent during mapper reuse. Freeze the
                    # exact miner-specific context now so later sends cannot
                    # rewrite historical manual-reconstruction evidence.
                    durable_row["_job_context_snapshot"] = parsed_snapshot
            except json.JSONDecodeError:
                pass
        db.execute(
            "INSERT OR IGNORE INTO shares(event_key,round_id,time_utc,share_id,source_id,template_id,job_id,miner_id,mapper_id,worker,height,"
            "share_diff,share_diff_sort,credited_diff,network_diff,effort_units,status,is_big,is_top,"
            "job_context_key,template_context_key,row_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)",
            (event_key, round_id, row.get("time_utc", ""), row.get("share_id", ""),
             row.get("source_id", ""), row.get("template_id", ""), row.get("job_id", ""),
             row.get("miner_id", ""), row.get("mapper_id", ""), row.get("worker", ""),
             row.get("height", ""), str(share_diff), str(share_diff).zfill(20), str(credited),
             str(network), str(effort), row.get("status", ""), is_big, job_context_key,
             template_context_key,
             json.dumps(durable_row, separators=(",", ":"), ensure_ascii=False)),
        )
        ranked = [value[0] for value in db.execute(
            "SELECT event_key FROM shares WHERE round_id=? ORDER BY share_diff_sort DESC,time_utc ASC LIMIT ?",
            (round_id, self.round_top_limit),
        ).fetchall()]
        db.execute("UPDATE shares SET is_top=0 WHERE round_id=?", (round_id,))
        if ranked:
            placeholders = ",".join("?" for _ in ranked)
            db.execute(f"UPDATE shares SET is_top=1 WHERE event_key IN ({placeholders})", ranked)
        evicted_contexts = db.execute(
            "SELECT DISTINCT job_context_key,template_context_key FROM shares "
            "WHERE round_id=? AND is_top=0 AND is_big=0",
            (round_id,),
        ).fetchall()
        db.execute("DELETE FROM shares WHERE round_id=? AND is_top=0 AND is_big=0", (round_id,))
        job_context_keys = {job_context_key}
        template_context_keys = {template_context_key}
        job_context_keys.update(str(item[0]) for item in evicted_contexts if item[0])
        template_context_keys.update(str(item[1]) for item in evicted_contexts if item[1])
        for context_key in job_context_keys:
            if not context_key:
                continue
            db.execute(
                "UPDATE job_contexts SET retained=CASE WHEN EXISTS "
                "(SELECT 1 FROM shares WHERE shares.job_context_key=job_contexts.correlation_key) "
                "THEN 1 ELSE 0 END WHERE correlation_key=?",
                (context_key,),
            )
        self._prune_job_contexts(db)
        for context_key in template_context_keys:
            if not context_key:
                continue
            db.execute(
                "UPDATE template_contexts SET retained=CASE WHEN EXISTS "
                "(SELECT 1 FROM shares WHERE shares.template_context_key=template_contexts.correlation_key) "
                "THEN 1 ELSE 0 END WHERE correlation_key=?",
                (context_key,),
            )
        self._prune_template_contexts(db)

        # submitblock response is emitted immediately before the correlated
        # accepted_upstream share result.  Credit the winning share first, then
        # close the round so it cannot leak into the next round.
        if correlated_block is not None and not int(correlated_block["round_closed"]):
            self._close_round(db, round_id, int(correlated_block["id"]), row)

    @staticmethod
    def _prune_template_contexts(db: sqlite3.Connection) -> None:
        pending = db.execute(
            "SELECT count(*),coalesce(sum(size_bytes),0) FROM template_contexts WHERE retained=0"
        ).fetchone()
        if pending is not None and int(pending[0]) <= MAX_PENDING_TEMPLATE_CONTEXTS \
                and int(pending[1]) <= MAX_PENDING_TEMPLATE_CONTEXT_BYTES:
            return
        db.execute(
            "DELETE FROM template_contexts WHERE id IN ("
            "SELECT id FROM ("
            "SELECT id,row_number() OVER (ORDER BY id DESC) AS rn,"
            "sum(size_bytes) OVER (ORDER BY id DESC ROWS UNBOUNDED PRECEDING) AS newest_bytes "
            "FROM template_contexts WHERE retained=0"
            ") WHERE rn>? OR newest_bytes>?)",
            (MAX_PENDING_TEMPLATE_CONTEXTS, MAX_PENDING_TEMPLATE_CONTEXT_BYTES),
        )

    def _template_context_event(self, db: sqlite3.Connection, row: Dict[str, Any],
                                stream_key: str) -> None:
        if row.get("event") != "template_cached" or not row.get("template_id"):
            return
        key = self._template_key(row, stream_key)
        serialized = json.dumps(row, separators=(",", ":"), ensure_ascii=False)
        db.execute(
            "INSERT INTO template_contexts(correlation_key,updated_utc,size_bytes,context_json) "
            "VALUES(?,?,?,?) ON CONFLICT(correlation_key) DO UPDATE SET "
            "updated_utc=excluded.updated_utc,size_bytes=excluded.size_bytes,context_json=excluded.context_json",
            (key, row.get("time_utc", ""), len(serialized.encode("utf-8")), serialized),
        )
        self._prune_template_contexts(db)

    @staticmethod
    def _prune_job_contexts(db: sqlite3.Connection) -> None:
        pending = db.execute(
            "SELECT count(*),coalesce(sum(size_bytes),0) FROM job_contexts WHERE retained=0"
        ).fetchone()
        if pending is not None and int(pending[0]) <= MAX_PENDING_JOB_CONTEXTS \
                and int(pending[1]) <= MAX_PENDING_JOB_CONTEXT_BYTES:
            return
        db.execute(
            "DELETE FROM job_contexts WHERE id IN ("
            "SELECT id FROM ("
            "SELECT id,row_number() OVER (ORDER BY id DESC) AS rn,"
            "sum(size_bytes) OVER (ORDER BY id DESC ROWS UNBOUNDED PRECEDING) AS newest_bytes "
            "FROM job_contexts WHERE retained=0"
            ") WHERE rn>? OR newest_bytes>?)",
            (MAX_PENDING_JOB_CONTEXTS, MAX_PENDING_JOB_CONTEXT_BYTES),
        )

    def _job_context_event(self, db: sqlite3.Connection, row: Dict[str, Any],
                           stream_key: str) -> None:
        event = str(row.get("event", ""))
        if event not in {"template_derived", "job_sent"} or not row.get("job_id"):
            return
        key = self._job_key(row, stream_key)
        base_key = self._job_base_key(row, stream_key)
        context: Dict[str, Any] = {}
        if event == "job_sent" and key != base_key:
            base = db.execute(
                "SELECT context_json FROM job_contexts WHERE correlation_key=?", (base_key,)
            ).fetchone()
            if base is not None:
                try:
                    candidate = json.loads(base[0])
                    if isinstance(candidate, dict):
                        context = candidate
                except json.JSONDecodeError:
                    pass
        existing = db.execute(
            "SELECT context_json FROM job_contexts WHERE correlation_key=?", (key,)
        ).fetchone()
        if existing is not None:
            try:
                candidate = json.loads(existing[0])
                if isinstance(candidate, dict):
                    context = candidate
            except json.JSONDecodeError:
                pass
        context[event] = row
        serialized = json.dumps(context, separators=(",", ":"), ensure_ascii=False)
        db.execute(
            "INSERT INTO job_contexts(correlation_key,updated_utc,size_bytes,context_json) VALUES(?,?,?,?) "
            "ON CONFLICT(correlation_key) DO UPDATE SET updated_utc=excluded.updated_utc,"
            "size_bytes=excluded.size_bytes,context_json=excluded.context_json",
            (key, row.get("time_utc", ""), len(serialized.encode("utf-8")), serialized),
        )
        # Only the short in-flight job window is pending. Audit contexts linked
        # by retained top/big shares are exempt from these count/byte budgets.
        self._prune_job_contexts(db)

    def _submission_event(self, db: sqlite3.Connection, row: Dict[str, Any], event_key: str) -> None:
        event = str(row.get("event", ""))
        correlation = self._correlation_key(row)
        if event in {
            "submit_block", "submit_block_attempt", "submit_block_retry",
            "submit_block_reconcile",
        }:
            existing = db.execute(
                "SELECT row_json FROM pending_submissions WHERE correlation_key=?", (correlation,)
            ).fetchone()
            attempts: List[Dict[str, Any]] = []
            submitted_block_blob = ""
            if existing is not None:
                try:
                    parsed = json.loads(existing[0])
                    if isinstance(parsed, dict) and isinstance(parsed.get("attempts"), list):
                        attempts = [item for item in parsed["attempts"] if isinstance(item, dict)]
                        if isinstance(parsed.get("submitted_block_blob"), str):
                            submitted_block_blob = parsed["submitted_block_blob"]
                    elif isinstance(parsed, dict):
                        attempts = [parsed]
                except json.JSONDecodeError:
                    pass
            normalized_attempts: List[Dict[str, Any]] = []
            for attempt in attempts + [row]:
                normalized = dict(attempt)
                blob = normalized.get("submitted_block_blob")
                if isinstance(blob, str) and blob:
                    submitted_block_blob = submitted_block_blob or blob
                    normalized["submitted_block_blob"] = ""
                    normalized["_submitted_block_blob_ref"] = "submit_audit.submitted_block_blob"
                normalized_attempts.append(normalized)
            attempts = normalized_attempts
            attempts = attempts[-MAX_SUBMISSION_ATTEMPTS:]
            audit = json.dumps({
                "submitted_block_blob": submitted_block_blob,
                "attempts": attempts,
            }, separators=(",", ":"), ensure_ascii=False)
            db.execute(
                "INSERT INTO pending_submissions(correlation_key,time_utc,row_json) VALUES(?,?,?) "
                "ON CONFLICT(correlation_key) DO UPDATE SET time_utc=excluded.time_utc,row_json=excluded.row_json",
                (correlation, row.get("time_utc", ""), audit),
            )
            db.execute(
                "DELETE FROM pending_submissions WHERE rowid IN "
                "(SELECT rowid FROM (SELECT rowid,"
                "row_number() OVER (ORDER BY time_utc DESC,rowid DESC) AS rn,"
                "sum(length(CAST(row_json AS BLOB))) OVER "
                "(ORDER BY time_utc DESC,rowid DESC ROWS UNBOUNDED PRECEDING) AS newest_bytes "
                "FROM pending_submissions) WHERE rn>? OR newest_bytes>?)",
                (MAX_PENDING_SUBMISSIONS, MAX_PENDING_SUBMISSION_BYTES),
            )
            return
        if event != "submit_block_result":
            return
        pending = db.execute(
            "SELECT row_json FROM pending_submissions WHERE correlation_key=?", (correlation,)
        ).fetchone()
        audit: Dict[str, Any] = {"submitted_block_blob": "", "attempts": []}
        if pending is not None:
            try:
                parsed = json.loads(pending[0])
                if isinstance(parsed, dict):
                    audit.update(parsed)
            except json.JSONDecodeError:
                pass
        result_row = dict(row)
        result_blob = result_row.get("submitted_block_blob")
        if isinstance(result_blob, str) and result_blob:
            if not isinstance(audit.get("submitted_block_blob"), str) or not audit["submitted_block_blob"]:
                audit["submitted_block_blob"] = result_blob
            result_row["submitted_block_blob"] = ""
            result_row["_submitted_block_blob_ref"] = "submit_audit.submitted_block_blob"
        submit_json = json.dumps(audit, separators=(",", ":"), ensure_ascii=False)
        db.execute("DELETE FROM pending_submissions WHERE correlation_key=?", (correlation,))
        round_id = self._current_round_id(db)
        cursor = db.execute(
            "INSERT OR IGNORE INTO blocks(event_key,round_id,time_utc,height,block_id,share_id,source_id,template_id,job_id,"
            "share_diff,network_diff,latency_ms,status,correlation_key,submit_json,result_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_key, round_id, row.get("time_utc", ""), row.get("height", ""),
             row.get("block_id", ""), row.get("share_id", ""), row.get("source_id", ""),
             row.get("template_id", ""), row.get("job_id", ""), row.get("share_diff", "0") or "0",
             row.get("network_target_diff", "0") or "0", row.get("latency_ms", ""),
             row.get("status", ""), correlation, submit_json,
             json.dumps(result_row, separators=(",", ":"), ensure_ascii=False)),
        )
        if row.get("status") == "accepted" and cursor.rowcount:
            db.execute("UPDATE rounds SET closing_block_id=? WHERE id=?", (cursor.lastrowid, round_id))
        db.execute(
            "DELETE FROM blocks WHERE status!='accepted' AND id IN "
            "(SELECT id FROM (SELECT id,"
            "row_number() OVER (ORDER BY id DESC) AS rn,"
            "sum(length(CAST(submit_json AS BLOB))+length(CAST(result_json AS BLOB))) OVER "
            "(ORDER BY id DESC ROWS UNBOUNDED PRECEDING) AS newest_bytes "
            "FROM blocks WHERE status!='accepted') WHERE rn>? OR newest_bytes>?)",
            (MAX_NONACCEPTED_BLOCKS, MAX_NONACCEPTED_BLOCK_BYTES),
        )

    def _close_round(self, db: sqlite3.Connection, round_id: int, block_id: int,
                     row: Dict[str, Any]) -> None:
        db.execute(
            "UPDATE rounds SET ended_utc=?,end_height=?,network_diff_end=?,status='closed',closing_block_id=? WHERE id=?",
            (row.get("time_utc", ""), row.get("height", ""),
             row.get("network_target_diff", "0") or "0", block_id, round_id),
        )
        db.execute("UPDATE blocks SET round_closed=1 WHERE id=?", (block_id,))
        cursor = db.execute(
            "INSERT INTO rounds(started_utc,start_height,network_diff_start) VALUES(?,?,?)",
            (row.get("time_utc", ""), row.get("height", ""),
             row.get("network_target_diff", "0") or "0"),
        )
        self._meta_set(db, "current_round_id", cursor.lastrowid)

    def _handle_event(self, db: sqlite3.Connection, payload: Tuple[Dict[str, Any], int]) -> bool:
        row, viewer_session = payload
        accepted, stream_key = self._observe_position(db, row, viewer_session)
        if not accepted:
            return False
        event_key = self._event_key(row, stream_key)
        event = str(row.get("event", ""))
        self._template_context_event(db, row, stream_key)
        self._job_context_event(db, row, stream_key)
        self._seed_event(db, row)
        self._verification_event(db, row)
        self._submission_event(db, row, event_key)
        self._accepted_share(db, row, event_key, stream_key)
        if event in {"template_cached", "template_derived"}:
            network = str(row.get("network_target_diff") or "0")
            db.execute(
                "UPDATE rounds SET start_height=CASE WHEN start_height='' THEN ? ELSE start_height END,"
                "network_diff_start=CASE WHEN network_diff_start='0' THEN ? ELSE network_diff_start END WHERE id=?",
                (row.get("height", ""), network, self._current_round_id(db)),
            )
        return event.startswith("verify_") or event.startswith("verifier_") or event.startswith("submit_block") or event == "share_result" or event in {"template_cached", "template_derived"}

    def _handle_api(self, db: sqlite3.Connection, payload: Tuple[Dict[str, Any], Dict[str, Any], str, float]) -> bool:
        summary_raw, workers_raw, observed_utc, wall_time = payload
        sanitized_summary = sanitize_api_summary(summary_raw)
        raw, unavailable_reason = api_worker_hash_total(workers_raw)
        if raw is None:
            self._meta_set(db, "api_status", f"unavailable: {unavailable_reason}")
            self._meta_set(db, "api_coverage_complete", "0")
            self._meta_set(db, "last_api_incomplete_reason", unavailable_reason)
            return True
        uptime = self._positive_int(sanitized_summary.get("uptime"))
        epoch = int(wall_time - uptime) if uptime else 0
        if self._meta_get(db, "api_baseline_set", "0") != "1":
            self._meta_set(db, "api_last_raw", raw)
            self._meta_set(db, "api_last_uptime", uptime)
            self._meta_set(db, "api_last_epoch", epoch)
            self._meta_set(db, "api_baseline_set", "1")
            self._meta_set(db, "api_status", "baseline established; no historical backfill")
            self._meta_set(db, "api_last_utc", observed_utc)
            return True
        previous_raw = self._positive_int(self._meta_get(db, "api_last_raw", "0"))
        previous_uptime = self._positive_int(self._meta_get(db, "api_last_uptime", "0"))
        previous_epoch = self._positive_int(self._meta_get(db, "api_last_epoch", "0"))
        total = self._positive_int(self._meta_get(db, "api_worker_hashes_total", "0"))
        restarted = bool(uptime < previous_uptime or (epoch and previous_epoch and abs(epoch - previous_epoch) > 10))
        if restarted:
            delta = raw
            status = "proxy restart detected; new worker counters added"
            self._meta_set(db, "api_coverage_complete", "0")
            self._meta_set(
                db, "last_api_incomplete_reason",
                "proxy restart occurred between sampled worker counters; the previous epoch tail is unknowable",
            )
        elif raw >= previous_raw:
            delta = raw - previous_raw
            status = "tracking"
        else:
            # Worker aggregation can shrink independently of process uptime.
            # Establish a new baseline instead of silently double counting.
            delta = 0
            status = "worker counter decreased without proxy restart; baseline reset"
            self._meta_set(
                db, "last_api_incomplete_reason",
                "API worker counter decreased without a proxy restart",
            )
            self._meta_set(db, "api_coverage_complete", "0")
        self._meta_set(db, "api_worker_hashes_total", total + delta)
        self._meta_set(db, "api_last_raw", raw)
        self._meta_set(db, "api_last_uptime", uptime)
        self._meta_set(db, "api_last_epoch", epoch)
        self._meta_set(db, "api_last_utc", observed_utc)
        self._meta_set(db, "api_status", status)
        return True

    def _handle_wallet(self, db: sqlite3.Connection,
                       payload: Tuple[List[Dict[str, Any]], str]) -> bool:
        transfers, observed_utc = payload
        for transfer in transfers:
            db.execute(
                "INSERT INTO wallet_transfers("
                "txid,amount_atomic,height,timestamp,confirmations,unlock_time,locked,"
                "account_index,subaddress_index,first_seen_utc,last_seen_utc,row_json"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(txid) DO UPDATE SET "
                "amount_atomic=excluded.amount_atomic,height=excluded.height,"
                "timestamp=excluded.timestamp,confirmations=excluded.confirmations,"
                "unlock_time=excluded.unlock_time,locked=excluded.locked,"
                "account_index=excluded.account_index,subaddress_index=excluded.subaddress_index,"
                "last_seen_utc=excluded.last_seen_utc,row_json=excluded.row_json",
                (
                    transfer["txid"], transfer["amount_atomic"], transfer["height"],
                    transfer["timestamp"], transfer["confirmations"],
                    transfer["unlock_time"], int(transfer["locked"]),
                    transfer["account_index"], transfer["subaddress_index"],
                    observed_utc, observed_utc,
                    json.dumps(transfer, ensure_ascii=False, separators=(",", ":")),
                ),
            )
        self._meta_set(db, "wallet_rpc_last_utc", observed_utc)
        self._meta_set(db, "wallet_rpc_status", "tracking")
        return True

    def _run(self) -> None:
        db: Optional[sqlite3.Connection] = None
        failed = False
        try:
            db = self._connect()
            while not self._stop.is_set() or not self._queue.empty():
                try:
                    first = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                batch = [first]
                for _ in range(255):
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
                refresh = False
                with db:
                    with self._cache_lock:
                        drop_pending = self._drop_pending
                        self._drop_pending = False
                    if drop_pending:
                        db.execute(
                            "UPDATE rounds SET coverage_complete=0 WHERE id=?",
                            (self._current_round_id(db),),
                        )
                        self._meta_set(db, "last_incomplete_reason", "SQLite ingestion queue overflow")
                        self._meta_set(db, "event_coverage_complete", "0")
                        refresh = True
                    for kind, payload, _size in batch:
                        if kind == "stop":
                            continue
                        if kind == "event":
                            refresh = self._handle_event(db, payload) or refresh
                        elif kind == "api":
                            refresh = self._handle_api(db, payload) or refresh
                        elif kind == "wallet":
                            refresh = self._handle_wallet(db, payload) or refresh
                        elif kind == "incomplete":
                            db.execute(
                                "UPDATE rounds SET coverage_complete=0 WHERE id=?",
                                (self._current_round_id(db),),
                            )
                            self._meta_set(db, "last_incomplete_reason", payload)
                            self._meta_set(db, "event_coverage_complete", "0")
                            self._recover_closing_round(db, str(payload))
                            refresh = True
                        elif kind == "api_incomplete":
                            self._meta_set(db, "api_coverage_complete", "0")
                            self._meta_set(db, "last_api_incomplete_reason", payload)
                            refresh = True
                with self._queue_budget_lock:
                    self._queue_bytes = max(0, self._queue_bytes - sum(item[2] for item in batch))
                if refresh:
                    self._refresh_cache(db)
        except Exception as exc:
            failed = True
            with self._cache_lock:
                self._cache["status"] = "error"
                self._cache["message"] = f"SQLite writer stopped: {exc}"
                self._cache["coverage_complete"] = False
        finally:
            if db is not None:
                try:
                    if not failed:
                        self._refresh_cache(db, "stopped", "SQLite writer stopped")
                    db.close()
                except sqlite3.Error:
                    pass

    def round_detail(self, round_id: int) -> Optional[Dict[str, Any]]:
        db = self._read_connect()
        try:
            round_row = db.execute("SELECT * FROM rounds WHERE id=?", (round_id,)).fetchone()
            if round_row is None:
                return None
            shares = [dict(value) for value in db.execute(
                "SELECT event_key,round_id,time_utc,share_id,source_id,template_id,job_id,miner_id,mapper_id,worker,height,"
                "share_diff,credited_diff,network_diff,effort_units,status,is_big,is_top "
                "FROM shares WHERE round_id=? AND is_top=1 ORDER BY share_diff_sort DESC,time_utc ASC LIMIT ?",
                (round_id, self.round_top_limit),
            ).fetchall()]
            blocks = [dict(value) for value in db.execute(
                "SELECT * FROM blocks WHERE round_id=? ORDER BY id DESC", (round_id,)
            ).fetchall()]
            return {"round": self._round_json(round_row), "top_shares": shares, "blocks": blocks}
        finally:
            db.close()

    def share_detail(self, event_key: str) -> Optional[Dict[str, Any]]:
        db = self._read_connect()
        try:
            share = db.execute("SELECT * FROM shares WHERE event_key=?", (event_key,)).fetchone()
            if share is None:
                return None
            result = dict(share)
            try:
                result["share"] = json.loads(result.pop("row_json"))
            except json.JSONDecodeError:
                result["share"] = {}
            job_snapshot = (
                result["share"].pop("_job_context_snapshot", None)
                if isinstance(result["share"], dict)
                else None
            )
            context = db.execute(
                "SELECT context_json FROM job_contexts WHERE correlation_key=?",
                (result.pop("job_context_key", ""),),
            ).fetchone()
            if isinstance(job_snapshot, dict):
                result["job_context"] = job_snapshot
            else:
                try:
                    result["job_context"] = json.loads(context[0]) if context is not None else {}
                except json.JSONDecodeError:
                    result["job_context"] = {}
            template = db.execute(
                "SELECT context_json FROM template_contexts WHERE correlation_key=?",
                (result.pop("template_context_key", ""),),
            ).fetchone()
            try:
                result["template_context"] = json.loads(template[0]) if template is not None else {}
            except json.JSONDecodeError:
                result["template_context"] = {}
            missing: List[str] = []
            template_context = result["template_context"]
            job_context = result["job_context"]
            if not isinstance(template_context, dict) or template_context.get("event") != "template_cached":
                missing.append("template_cached")
            elif not template_context.get("blocktemplate_blob"):
                missing.append("template_cached.blocktemplate_blob")
            else:
                for name in ("reserved_offset", "reserved_size"):
                    if template_context.get(name, "") == "":
                        missing.append(f"template_cached.{name}")
            derived = job_context.get("template_derived") if isinstance(job_context, dict) else None
            sent = job_context.get("job_sent") if isinstance(job_context, dict) else None
            if not isinstance(derived, dict):
                missing.append("template_derived")
            elif not derived.get("hashing_blob"):
                missing.append("template_derived.hashing_blob")
            elif not derived.get("entropy_hex"):
                missing.append("template_derived.entropy_hex")
            if not isinstance(sent, dict):
                missing.append("job_sent")
            else:
                for name in ("hashing_blob", "miner_target_hex", "seed_hash", "algo"):
                    if not sent.get(name):
                        missing.append(f"job_sent.{name}")
                for name in ("nonce_offset", "nonce_size"):
                    if sent.get(name, "") == "":
                        missing.append(f"job_sent.{name}")
            share_context = result["share"] if isinstance(result["share"], dict) else {}
            if not share_context.get("nonce"):
                missing.append("share.nonce")
            if not share_context.get("result_hash"):
                missing.append("share.result_hash")
            if share_context.get("_difficulty_source") == "verifier_computed" \
                    and not share_context.get("_computed_result_hash"):
                missing.append("share.verifier_computed_result_hash")
            result["audit_context_complete"] = not missing
            result["audit_context_missing"] = missing
            return result
        finally:
            db.close()


class DashboardState:
    """Thread-safe bounded state shared by the socket reader and HTTP clients."""

    def __init__(self, socket_path: str, max_events: int, top_limit: int,
                 api_enabled: bool = False, api_interval: float = 5.0,
                 wallet_enabled: bool = False,
                 wallet_interval: float = DEFAULT_WALLET_RPC_INTERVAL,
                 store: Optional[SQLiteStore] = None,
                 live_byte_limit: int = MAX_LIVE_RING_BYTES) -> None:
        self.socket_path = socket_path
        self.max_events = max_events
        self.top_limit = top_limit
        self.store = store
        self._lock = threading.RLock()
        self._events: Deque[Dict[str, Any]] = deque()
        self._event_sizes: Deque[int] = deque()
        self._event_bytes = 0
        self._live_byte_limit = max(MAX_LIVE_ROW_BYTES, int(live_byte_limit))
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
        self._viewer_instance_id = uuid.uuid4().hex
        # Schema v3 can derive a stable connection identity from the proxy's
        # process-lifetime stream ID and its process-unique miner ID.  Schema v2
        # has no stream identity, so give each observed dashboard session a
        # separate namespace rather than accidentally merging reused miner IDs.
        self._connection_namespace = uuid.uuid4()
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
        self._wallet: Dict[str, Any] = {
            "enabled": wallet_enabled,
            "status": "waiting" if wallet_enabled else "disabled",
            "message": "waiting for monero-wallet-rpc" if wallet_enabled else "wallet RPC polling is not configured",
            "last_update_utc": "",
            "interval_seconds": wallet_interval,
            "transfers": [],
        }
        if self.store is not None:
            self.store.set_update_callback(self.persistence_updated)

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
            "viewer_instance_id": self._viewer_instance_id,
            "started_utc": self._started_utc,
            "last_event_utc": self._last_event_utc,
            "socket_path": self.socket_path,
        }

    def health(self) -> Dict[str, Any]:
        """Return health without copying the bounded event/API snapshot."""
        with self._lock:
            return self._health_locked()

    def round_detail(self, round_id: int) -> Optional[Dict[str, Any]]:
        return self.store.round_detail(round_id) if self.store is not None else None

    def share_detail(self, event_key: str) -> Optional[Dict[str, Any]]:
        return self.store.share_detail(event_key) if self.store is not None else None

    def _state_locked(self, include_api: bool = True,
                      include_persistence: bool = True,
                      include_wallet: bool = True) -> Dict[str, Any]:
        rejected = (
            self._counters["share_result:rejected_local"]
            + self._counters["share_result:rejected_upstream"]
        )
        result = {
            "top_limit": self.top_limit,
            "max_events": self.max_events,
            "live_event_bytes": self._event_bytes,
            "live_event_byte_limit": self._live_byte_limit,
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
        if include_persistence:
            result["persistence"] = (
                self.store.snapshot()
                if self.store is not None
                else {
                    "enabled": False,
                    "status": "disabled",
                    "message": "SQLite persistence disabled by configuration",
                }
            )
        if include_api:
            result["api"] = dict(self._api)
        if include_wallet:
            result["wallet"] = dict(self._wallet)
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
        if not self._subscribers:
            return
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        event = str(payload.get("kind", "update"))
        event_id = payload.get("viewer_seq")
        if not isinstance(event_id, int):
            event_id = None
        for subscriber in list(self._subscribers):
            if not subscriber.put_nowait(event, event_id, encoded):
                subscriber.closed.set()
                self._subscribers.discard(subscriber)

    def _append_locked(self, row: Dict[str, Any], count: bool = True,
                       storage_size: Optional[int] = None) -> None:
        self._viewer_sequence += 1
        row["_viewer_seq"] = self._viewer_sequence
        row["_session"] = self._session
        row["_received_utc"] = utc_now()
        self._last_event_utc = row.get("time_utc") or row["_received_utc"]
        # Include viewer metadata in the byte accounting. ``storage_size`` is
        # the pre-metadata size returned by compact_live_row and remains only
        # as a lower bound for callers that already serialized the row.
        actual_size = len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        size = max(storage_size or 0, actual_size)
        self._events.append(row)
        self._event_sizes.append(size)
        self._event_bytes += size
        while len(self._events) > self.max_events or self._event_bytes > self._live_byte_limit:
            self._events.popleft()
            self._event_bytes -= self._event_sizes.popleft()
        if count:
            self._counters["events_observed"] += 1

        # API worker arrays can be large and change only on the API poller.
        # Do not copy/send/re-render them for every high-rate mining event.
        payload = self._state_locked(
            include_api=False, include_persistence=False, include_wallet=False,
        )
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
            self._reader_message = "supported event stream connected"

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
            if self.store is not None:
                self.store.mark_incomplete(message)

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
            if self.store is not None:
                self.store.mark_incomplete(message)

    def fatal(self, message: str) -> None:
        with self._lock:
            self._connected = False
            self._coverage_complete = False
            self._reader_status = "fatal"
            self._reader_message = message
            self._notice_locked("viewer_error", "error", message)
            if self.store is not None:
                self.store.mark_incomplete(message)

    def update_api(self, summary: Dict[str, Any], workers: Dict[str, Any]) -> None:
        """Publish a credential-free, allowlisted API snapshot to browsers."""
        with self._lock:
            if self.store is not None:
                self.store.enqueue_api(summary, workers)
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

    def api_sample_incomplete(self, message: str) -> None:
        if self.store is not None:
            self.store.mark_api_incomplete(message)
        self.api_error(message)

    def update_wallet(self, transfers: Sequence[Dict[str, Any]]) -> None:
        """Publish only sanitized coinbase rewards; credentials never enter state."""
        sanitized = [dict(value) for value in transfers]
        with self._lock:
            if self.store is not None:
                self.store.enqueue_wallet_transfers(sanitized)
            interval = self._wallet.get("interval_seconds", DEFAULT_WALLET_RPC_INTERVAL)
            self._wallet = {
                "enabled": True,
                "status": "connected",
                "message": "authenticated monero-wallet-rpc poll complete",
                "last_update_utc": utc_now(),
                "interval_seconds": interval,
                "transfers": sanitized[:500],
            }
            payload = self._state_locked()
            payload.update({"kind": "state", "viewer_seq": self._viewer_sequence})
            self._broadcast_locked(payload)

    def wallet_error(self, message: str) -> None:
        with self._lock:
            if self._wallet.get("status") == "error" and self._wallet.get("message") == message:
                return
            self._wallet["enabled"] = True
            self._wallet["status"] = "error"
            self._wallet["message"] = str(message)[:512]
            payload = self._state_locked()
            payload.update({"kind": "state", "viewer_seq": self._viewer_sequence})
            self._broadcast_locked(payload)

    def persistence_updated(self) -> None:
        with self._lock:
            payload = self._state_locked(
                include_api=False, include_persistence=True, include_wallet=False,
            )
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
                    "nonce", "result_hash", "share_diff", "signature_hex", "algo",
                    "seed_hash", "prev_hash", "view_tag", "extra_nonce",
                    "_claimed_result_hash", "_claimed_share_diff",
                    "_computed_result_hash", "_computed_share_diff",
                    "_difficulty_source", "_share_received_utc",
                    "_verification_event", "_verification_status",
                    "_verification_utc", "_verifier_queue_ms",
                    "_verifier_hash_ms", "_verifier_total_ms",
                ):
                    if not result.get(name):
                        result[name] = context.get(name, "")
        return result

    def _connection_uuid_locked(self, row: Dict[str, Any]) -> str:
        miner_id = str(row.get("miner_id", ""))
        if not miner_id:
            return ""

        stream_id = str(row.get("stream_id", ""))
        if stream_id:
            try:
                namespace = uuid.UUID(hex=stream_id)
            except ValueError:
                # A parsed v3 row cannot reach this branch, but direct callers
                # and future schemas should still fail closed to session scope.
                namespace = self._connection_namespace
                name = f"xmrig-proxy/viewer-session/{self._session}/miner/{miner_id}"
            else:
                name = f"xmrig-proxy/miner/{miner_id}"
        else:
            namespace = self._connection_namespace
            name = f"xmrig-proxy/viewer-session/{self._session}/miner/{miner_id}"

        return str(uuid.uuid5(namespace, name))

    @staticmethod
    def _miner_label(row: Dict[str, Any]) -> str:
        """Return the dashboard's searchable rendering of one miner mapping."""
        miner_id = str(row.get("miner_id", ""))
        if not miner_id:
            return ""
        mapper_id = str(row.get("mapper_id", ""))
        return f"m{miner_id}" + (f"/p{mapper_id}" if mapper_id else "")

    def _remember_share_locked(self, row: Dict[str, Any]) -> None:
        share_id = row.get("share_id", "")
        if not share_id:
            return
        key = (self._session, share_id)
        context = self._shares.get(key, {})
        for name in (
            "miner_id", "mapper_id", "worker", "source_id", "template_id",
            "height", "job_id", "miner_target_diff", "network_target_diff",
            "nonce", "signature_hex", "algo", "seed_hash", "prev_hash",
            "view_tag", "extra_nonce",
        ):
            if row.get(name):
                context[name] = row[name]

        event = row.get("event", "")
        if event == "share_received":
            context["result_hash"] = row.get("result_hash", "")
            context["share_diff"] = row.get("share_diff", "")
            context["_claimed_result_hash"] = row.get("result_hash", "")
            context["_claimed_share_diff"] = row.get("share_diff", "")
            context["_difficulty_source"] = "miner_claimed"
            context["_share_received_utc"] = row.get("time_utc", "")
        elif event in {"verify_result", "verify_mismatch"}:
            if row.get("result_hash"):
                context["result_hash"] = row["result_hash"]
                context["_computed_result_hash"] = row["result_hash"]
            if row.get("share_diff"):
                context["share_diff"] = row["share_diff"]
                context["_computed_share_diff"] = row["share_diff"]
            context["_difficulty_source"] = "verifier_computed"
            context["_verification_event"] = event
            context["_verification_status"] = row.get("status", "")
            context["_verification_utc"] = row.get("time_utc", "")
            context["_verifier_queue_ms"] = row.get("verifier_queue_ms", "")
            context["_verifier_hash_ms"] = row.get("verifier_hash_ms", "")
            context["_verifier_total_ms"] = row.get("verifier_total_ms", "")
        elif event == "verify_error":
            context["_verification_event"] = event
            context["_verification_status"] = row.get("status", "")
            context["_verification_utc"] = row.get("time_utc", "")

        self._shares[key] = context
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
        for name in ("mapper_id", "miner_label", "connection_uuid", "worker", "miner_ip", "agent", "source_id"):
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
        elif event == "daemon_tip_changed":
            source["status"] = "refreshing"
            source["last_tip_change_utc"] = row["time_utc"]
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
            "miner_label": row.get("miner_label", ""),
            "connection_uuid": row.get("connection_uuid", ""),
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
            first_gap = previous is None and sequence != 1
            later_gap = previous is not None and sequence != previous + 1
            if first_gap or later_gap:
                self._coverage_complete = False
                if previous is None:
                    message = f"event sequence gap: first observed {sequence}"
                else:
                    direction = "reset" if sequence <= previous else "gap"
                    message = f"event sequence {direction}: {previous} -> {sequence}"
                self._notice_locked(
                    "viewer_sequence_gap",
                    "degraded",
                    message,
                )
                if self.store is not None:
                    self.store.mark_incomplete(message)
            self._source_sequence = sequence

            resolved = self._resolve_identity_locked(row)
            connection_uuid = self._connection_uuid_locked(resolved)
            if connection_uuid:
                resolved["connection_uuid"] = connection_uuid
                resolved["miner_label"] = self._miner_label(resolved)
            event = resolved["event"]
            status = resolved.get("status", "")
            self._counters[event] += 1
            if status:
                self._counters[f"{event}:{status}"] += 1

            if event in {"share_received", "verify_result", "verify_mismatch", "verify_error"}:
                self._remember_share_locked(resolved)
            self._update_miner_locked(resolved)
            self._update_source_locked(resolved, received_at)
            self._consider_top_locked(resolved)
            durable = dict(resolved)
            live_row, live_size = compact_live_row(resolved)
            self._append_locked(live_row, storage_size=live_size)
            if self.store is not None:
                self.store.enqueue_event(durable, self._session)


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
                    self.state.waiting("socket closed before the supported schema header")
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
                        self.state.waiting("invalid schema-v2/v3 event header; reconnecting")
                        return
                    continue
                if row is None:
                    if parser.header_seen and not session_started:
                        self.state.begin_session()
                        session_started = True
                    continue
                if not session_started:
                    self.state.protocol_error("received an event before the schema header")
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

    @staticmethod
    def _mixed_epoch(before: Dict[str, Any], before_wall: float,
                     after: Dict[str, Any], after_wall: float) -> bool:
        before_uptime = before.get("uptime")
        after_uptime = after.get("uptime")
        if (
            not isinstance(before_uptime, int) or isinstance(before_uptime, bool)
            or not isinstance(after_uptime, int) or isinstance(after_uptime, bool)
            or before_uptime < 0 or after_uptime < 0
        ):
            return True
        before_epoch = before_wall - before_uptime
        after_epoch = after_wall - after_uptime
        return abs(after_epoch - before_epoch) > 3.0

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                summary_before = self._fetch("/1/summary")
                before_wall = time.time()
                workers = self._fetch("/1/workers")
                summary_after = self._fetch("/1/summary")
                after_wall = time.time()
                if self._mixed_epoch(summary_before, before_wall, summary_after, after_wall):
                    self.state.api_sample_incomplete(
                        "proxy restarted or changed epoch during the API summary/workers sample"
                    )
                else:
                    self.state.update_api(summary_after, workers)
            except (HTTPError, URLError, OSError, RuntimeError) as exc:
                self.state.api_error(self._error_message(exc))

            elapsed = time.monotonic() - started
            self.stop_event.wait(max(0.05, self.interval - elapsed))


class WalletRpcPoller(threading.Thread):
    """Poll rewards with a complete Digest exchange on one fresh connection."""

    MAX_RESPONSE_BYTES = 16 * 1024 * 1024

    def __init__(self, endpoint: str, username: str, password: str,
                 interval: float, state: DashboardState,
                 stop_event: threading.Event) -> None:
        super().__init__(name="monero-wallet-rpc-poller", daemon=True)
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.interval = interval
        self.state = state
        self.stop_event = stop_event

    def _new_connection(self, timeout: float) -> http.client.HTTPConnection:
        parsed = urlsplit(self.endpoint)
        connection_type = (
            http.client.HTTPSConnection
            if parsed.scheme == "https" else http.client.HTTPConnection
        )
        return connection_type(parsed.hostname, parsed.port, timeout=timeout)

    def _authorization(self, request: Request,
                       challenges: Sequence[str]) -> str:
        # Monero advertises MD5 and MD5-sess in separate WWW-Authenticate
        # fields. Python's digest calculator supports MD5; use it only to
        # construct the header because urllib's transport always closes the
        # challenge connection before retrying.
        passwords = HTTPPasswordMgrWithDefaultRealm()
        passwords.add_password(None, self.endpoint, self.username, self.password)
        digest = HTTPDigestAuthHandler(passwords)
        for raw_value in challenges:
            scheme, separator, raw_challenge = raw_value.partition(" ")
            if not separator or scheme.lower() != "digest":
                continue
            try:
                challenge = parse_keqv_list(parse_http_list(raw_challenge))
            except ValueError:
                continue
            if str(challenge.get("algorithm", "MD5")).upper() != "MD5":
                continue
            qop = str(challenge.get("qop", ""))
            if qop and "auth" not in {
                value.strip().lower() for value in qop.split(",")
            }:
                continue
            try:
                value = digest.get_authorization(request, challenge)
            except (UnicodeError, ValueError, URLError):
                continue
            if value:
                return f"Digest {value}"
        raise RuntimeError(
            "wallet RPC did not provide a supported MD5 Digest challenge"
        )

    def _read_response(self, response: http.client.HTTPResponse) -> bytes:
        encoded = response.read(self.MAX_RESPONSE_BYTES + 1)
        if len(encoded) > self.MAX_RESPONSE_BYTES:
            raise RuntimeError(
                f"wallet RPC response exceeds {self.MAX_RESPONSE_BYTES} bytes"
            )
        return encoded

    def _result(self, encoded: bytes) -> Dict[str, Any]:
        try:
            document = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"wallet RPC returned invalid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise RuntimeError("wallet RPC JSON is not an object")
        error = document.get("error")
        if isinstance(error, dict):
            code = error.get("code", "unknown")
            message = str(error.get("message", "RPC error"))[:256]
            raise RuntimeError(f"wallet RPC error {code}: {message}")
        result = document.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("wallet RPC result is not an object")
        return result

    def _status_error(self, response: http.client.HTTPResponse) -> HTTPError:
        return HTTPError(
            self.endpoint, response.status, response.reason,
            response.headers, None,
        )

    def _call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps({
            "jsonrpc": "2.0", "id": "dashboard", "method": method,
            "params": params,
        }, separators=(",", ":")).encode("utf-8")
        request = Request(self.endpoint, data=body, method="POST")
        parsed = urlsplit(self.endpoint)
        request_target = parsed.path or "/"
        timeout = min(15.0, max(3.0, self.interval * 0.75))
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "xmrig-event-dashboard/1",
        }
        connection = self._new_connection(timeout)
        try:
            # http_server_auth is owned by Monero's per-connection handler.
            # Keep this socket alive long enough to answer its nonce challenge.
            connection.request(
                "POST", request_target, body=body,
                headers={**headers, "Connection": "keep-alive"},
            )
            challenge_response = connection.getresponse()
            encoded = self._read_response(challenge_response)
            if challenge_response.status == 200:
                return self._result(encoded)
            if challenge_response.status != 401:
                raise self._status_error(challenge_response)
            if challenge_response.will_close or connection.sock is None:
                raise RuntimeError(
                    "wallet RPC closed the connection after its Digest challenge"
                )
            authorization = self._authorization(
                request,
                challenge_response.headers.get_all("WWW-Authenticate") or (),
            )
            connection.request(
                "POST", request_target, body=body,
                headers={
                    **headers,
                    "Authorization": authorization,
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            encoded = self._read_response(response)
            if response.status != 200:
                raise self._status_error(response)
            return self._result(encoded)
        finally:
            connection.close()

    @staticmethod
    def _error_message(exc: BaseException) -> str:
        if isinstance(exc, HTTPError):
            if exc.code in (401, 403):
                return f"wallet RPC Digest authentication failed (HTTP {exc.code})"
            return f"wallet RPC returned HTTP {exc.code}"
        if isinstance(exc, URLError):
            return f"wallet RPC connection failed: {exc.reason}"
        return f"wallet RPC poll failed: {exc}"

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                result = self._call("get_transfers", {
                    "in": True,
                    "out": False,
                    "pending": False,
                    "failed": False,
                    "pool": False,
                    "all_accounts": True,
                })
                self.state.update_wallet(sanitize_wallet_transfers(result))
            except (HTTPError, URLError, OSError, RuntimeError) as exc:
                self.state.wallet_error(self._error_message(exc))
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
    tbody tr.event-archived { box-shadow:inset 3px 0 var(--amber); }
    tbody tr.event-selected { background:#173036; box-shadow:inset 3px 0 var(--cyan); }
    tbody tr.event-selected:hover { background:#1b3a41; }
    .status-accepted,.status-updated,.status-healthy { color:var(--green); }
    .status-rejected,.status-error,.status-fatal { color:var(--red); }
    .status-requested,.status-warning,.status-degraded { color:var(--amber); }
    .event-template { color:var(--cyan); } .event-block { color:var(--amber); font-weight:700; } .event-worker { color:var(--violet); }
    .controls { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
    input,select,button { border:1px solid var(--line); background:#0d1318; border-radius:7px; padding:7px 9px; }
    input { min-width:210px; flex:1; } button { cursor:pointer; } button:hover { border-color:#536572; }
    input[aria-invalid="true"] { border-color:var(--red); box-shadow:0 0 0 1px #ff716c44; }
    #minShareDiff { max-width:260px; } #traceState { max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    button:disabled { cursor:not-allowed; opacity:.5; border-color:var(--line); }
    label.check { color:var(--muted); display:flex; align-items:center; gap:5px; }
    label.check input { min-width:0; flex:none; }
    .selection-cell { width:34px; min-width:34px; padding-left:8px; padding-right:8px; text-align:center; }
    .row-select { width:14px; height:14px; min-width:0; padding:0; margin:0; vertical-align:middle; accent-color:var(--cyan); }
    .details { height:calc(58vh + 54px); min-height:484px; overflow:auto; }
    .details pre { margin:0; color:#cbd5dc; white-space:pre-wrap; word-break:break-word; font:12px/1.55 inherit; }
    .empty { color:var(--muted); padding:24px; text-align:center; }
    .source-row { display:grid; grid-template-columns:80px 90px 1fr 110px 90px; gap:10px; padding:9px 2px; border-bottom:1px solid var(--line); }
    .source-row:last-child { border:0; }
    .api-metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin-bottom:12px; }
    .api-metric { background:#0c1216; border:1px solid var(--line); border-radius:8px; padding:10px; }
    .api-metric b { display:block; font-size:18px; color:var(--cyan); margin-top:3px; }
    .history-grid { display:grid; grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr); gap:10px; margin:10px 0; }
    .metric-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:8px; margin-bottom:12px; }
    .metric { padding:10px; border:1px solid var(--line); border-radius:8px; background:#0c1216; min-width:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:.07em; }
    .metric b { display:block; color:var(--cyan); font-size:17px; margin-top:3px; overflow-wrap:anywhere; }
    .section-gap { margin-top:10px; }
    .seed-list { display:flex; flex-wrap:wrap; gap:7px; }
    .seed { border:1px solid var(--line); background:#0b1014; border-radius:8px; padding:7px 9px; min-width:210px; }
    .seed b { color:var(--violet); }
    .payout-address { margin:4px 0; overflow-wrap:anywhere; user-select:all; color:var(--text); }
    .json-code { margin:0; color:#cbd5dc; white-space:pre-wrap; word-break:break-word; font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; tab-size:2; }
    .json-key { color:#7dd3fc; } .json-string { color:#86efac; } .json-number { color:#fbbf24; } .json-literal { color:#c4b5fd; }
    .details-toolbar { display:flex; align-items:center; gap:7px; }
    .details-copy-state { color:var(--muted); font-size:10px; }
    .table-note { color:var(--muted); font-size:11px; margin-top:8px; }
    .muted { color:var(--muted); }
    footer { color:var(--muted); font-size:11px; margin-top:12px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    @media (max-width:1100px) { .cards { grid-template-columns:repeat(3,1fr); } .workspace,.grid-two,.history-grid { grid-template-columns:1fr; } .details { height:420px; min-height:0; } }
    @media (max-width:650px) { .shell{padding:12px} header{display:block}.badges{justify-content:flex-start;margin-top:12px}.cards{grid-template-columns:repeat(2,1fr)} .events-scroll{height:55vh} }
  </style>
</head>
<body>
<div class="shell">
  <header>
    <div><h1>XMRig Proxy Event Dashboard</h1><div class="sub">Read-only schema-v2/v3 observer · localhost only</div></div>
    <div class="badges"><span id="browserBadge" class="badge">dashboard: connecting</span><span id="historyBadge" class="badge">history: opening</span><span id="socketBadge" class="badge">socket: starting</span><span id="apiBadge" class="badge">API: disabled</span><span id="walletBadge" class="badge">wallet: disabled</span><span id="dbBadge" class="badge">database: starting</span><span id="verifierBadge" class="badge">verifier: waiting</span><span id="coverageBadge" class="badge">coverage: observed</span><span id="sessionBadge" class="badge">session 0</span></div>
  </header>

  <section class="cards">
    <div class="card"><div class="label">Active miners</div><div id="activeMiners" class="value">0</div><div class="note">distinct miner IDs</div></div>
    <div class="card"><div class="label">Hashrate 1m</div><div id="hashrate1m" class="value">—</div><div class="note">proxy API · auto-scaled</div></div>
    <div class="card"><div class="label">Hashrate 10m</div><div id="hashrate10m" class="value">—</div><div class="note">proxy API · auto-scaled</div></div>
    <div class="card"><div class="label">Templates cached</div><div id="templates" class="value">0</div><div class="note">observed by viewer</div></div>
    <div class="card"><div class="label">Local accepts</div><div id="localAccepted" class="value">0</div><div class="note">custom-diff shares</div></div>
    <div class="card"><div class="label">API accepted</div><div id="apiAccepted" class="value">—</div><div class="note">proxy result counter</div></div>
    <div class="card"><div class="label">Rejected</div><div id="rejected" class="value">0</div><div class="note">socket outcomes</div></div>
    <div class="card"><div class="label">Blocks accepted</div><div id="blocksAccepted" class="value">0</div><div class="note">submitblock OK</div></div>
    <div class="card"><div class="label">Durable credited hashes</div><div id="durableHashes" class="value">—</div><div class="note">assigned target work since tracking</div></div>
    <div class="card"><div class="label">Current effort</div><div id="currentEffort" class="value">—</div><div class="note">difficulty-normalized round effort</div></div>
    <div class="card"><div class="label">Average round effort</div><div id="averageEffort" class="value">—</div><div class="note">completed rounds</div></div>
    <div class="card"><div class="label">20G+ shares</div><div id="bigShareCount" class="value">0</div><div class="note">durably retained</div></div>
  </section>

  <section class="panel section-gap">
    <div class="panel-head"><div><h2>Persistent mining rounds</h2><div class="sub">Starts at the first database launch; no historical counter backfill</div></div><span id="trackingSince" class="muted">not initialized</span></div>
    <div class="metric-grid">
      <div class="metric"><span>Current round</span><b id="roundId">—</b></div>
      <div class="metric"><span>Credited hashes</span><b id="roundHashes">—</b></div>
      <div class="metric"><span>Accepted shares</span><b id="roundShares">—</b></div>
      <div class="metric"><span>Effort</span><b id="roundEffort">—</b></div>
      <div class="metric"><span>API worker work</span><b id="apiWorkerHashes">—</b></div>
      <div class="metric"><span>API − event work</span><b id="workReconciliation">—</b></div>
    </div>
    <div class="scroll top-scroll"><table><thead><tr><th>Round</th><th>Started</th><th>Ended</th><th>Height</th><th>Shares</th><th>Credited hashes</th><th>Effort</th><th>Coverage</th></tr></thead><tbody id="roundsBody"></tbody></table><div id="roundsEmpty" class="empty">No completed rounds yet.</div></div>
    <div class="table-note">Click a round to load its retained top 1,000 shares below and its complete block audit records into the JSON inspector.</div>
    <div class="controls section-gap"><input id="roundLookup" type="number" min="1" step="1" placeholder="Load any past round ID…"><button id="loadRoundButton">Load round</button></div>
  </section>

  <section id="selectedRoundPanel" class="panel section-gap" style="display:none">
    <div class="panel-head"><div><h2 id="selectedRoundTitle">Selected round top shares</h2><div class="sub">Click a share to load its exact share row and correlated reconstruction context</div></div><button id="closeRound">Close round view</button></div>
    <div class="scroll top-scroll"><table><thead><tr><th>#</th><th>Time</th><th>Difficulty</th><th>Credited</th><th>Worker</th><th>Height</th><th>Status</th></tr></thead><tbody id="selectedRoundShares"></tbody></table><div id="selectedRoundEmpty" class="empty">No retained shares.</div></div>
  </section>

  <section class="history-grid">
    <div class="panel"><div class="panel-head"><div><h2>Recent successful block submissions</h2><div class="sub">Accepted submitblock responses end rounds after the winning share is credited</div></div></div><div class="scroll top-scroll"><table><thead><tr><th>Time</th><th>Round</th><th>Height</th><th>Block ID</th><th>Share diff</th><th>RPC latency</th></tr></thead><tbody id="blocksBody"></tbody></table><div id="blocksEmpty" class="empty">No accepted submitblock responses tracked.</div></div></div>
    <div class="panel"><div class="panel-head"><div><h2>Durable 20G+ shares</h2><div class="sub">Retained regardless of round rank</div></div></div><div class="scroll top-scroll"><table><thead><tr><th>Time</th><th>Round</th><th>Difficulty</th><th>Worker</th><th>Height</th></tr></thead><tbody id="bigSharesBody"></tbody></table><div id="bigSharesEmpty" class="empty">No share has reached the persistence threshold.</div></div></div>
  </section>

  <section class="panel section-gap">
    <div class="panel-head"><div><h2>RandomX verifier</h2><div class="sub">Independent hashing health, latency, queue state, and seed lifecycle</div></div><div class="details-toolbar"><span id="verifierUpdated" class="muted">waiting for verifier telemetry</span><button id="inspectVerifier">Inspect JSON</button></div></div>
    <div class="metric-grid">
      <div class="metric"><span>Requests / results</span><b id="verifyCounts">0 / 0</b></div>
      <div class="metric"><span>Mismatches / errors</span><b id="verifyFailures">0 / 0</b></div>
      <div class="metric"><span>Average queue</span><b id="verifyQueue">—</b></div>
      <div class="metric"><span>Average RandomX hash</span><b id="verifyHash">—</b></div>
      <div class="metric"><span>Average total</span><b id="verifyTotal">—</b></div>
      <div class="metric"><span>Active / queued / limit</span><b id="verifyLoad">—</b></div>
      <div class="metric"><span>Seeds / capacity</span><b id="verifySeedCount">—</b></div>
      <div class="metric"><span>VM pool</span><b id="verifyVms">—</b></div>
    </div>
    <div id="verifierSeeds" class="seed-list"><span class="muted">No seed lifecycle events observed.</span></div>
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
    <div class="table-note">Validated daemon-solo payout destinations</div>
    <div id="soloPayouts" class="seed-list section-gap"><span class="muted">No daemon-solo payout exposed by the API.</span></div>
    <div class="scroll top-scroll"><table><thead><tr><th>Worker</th><th>Connections</th><th>Hashrate 1m</th><th>Hashrate 10m</th><th>Accepted</th><th>Rejected</th><th>Invalid</th><th>Credited hashes</th></tr></thead><tbody id="apiWorkersBody"></tbody></table><div id="apiWorkersEmpty" class="empty">Supply --api-url and an API token to enable these statistics.</div></div>
  </section>

  <section id="walletPanel" class="panel" style="margin-top:10px">
    <div class="panel-head"><div><h2>Monero mining wallet rewards</h2><div class="sub">Optional authenticated view-only wallet RPC · confirmed coinbase transfers only · durably recorded in SQLite</div></div><span id="walletUpdated" class="muted">not configured</span></div>
    <div class="scroll top-scroll"><table><thead><tr><th>Block time</th><th>Height</th><th>Reward</th><th>Confirmations</th><th>State</th><th>Account / subaddress</th><th>Transaction ID</th></tr></thead><tbody id="walletTransfersBody"></tbody></table><div id="walletTransfersEmpty" class="empty">Supply --wallet-rpc-url and --wallet-rpc-login to poll mining rewards.</div></div>
  </section>

  <section class="panel">
    <div class="panel-head"><div><h2 id="topTitle">Top 5 observed accepted shares</h2><div class="sub">Ranked by accepted share difficulty; verifier-computed when enabled; times are exact event times</div></div><span id="topCompleteness" class="badge">observed window</span></div>
    <div class="scroll top-scroll"><table><thead><tr><th>#</th><th>Time (browser local)</th><th>Share difficulty</th><th>Miner</th><th>Worker</th><th>Height</th><th>Result</th></tr></thead><tbody id="topBody"></tbody></table><div id="topEmpty" class="empty">No accepted shares observed yet.</div></div>
  </section>

  <section class="workspace" style="margin-top:10px">
    <div class="panel">
      <div class="panel-head"><h2>Live event timeline</h2><span id="eventCount" class="muted">0 rows</span></div>
      <div class="controls" style="margin-bottom:10px">
        <select id="category"><option value="all">All events</option><option value="shares">Shares</option><option value="blocks">Blocks</option><option value="templates">Templates</option><option value="workers">Workers</option><option value="errors">Errors archive</option></select>
        <input id="search" type="search" placeholder="Filter miner, connection UUID, worker, event, status, ID…" autocomplete="off">
        <input id="minShareDiff" type="text" inputmode="numeric" pattern="[0-9]*" autocomplete="off" spellcheck="false" placeholder="Minimum share difficulty…">
        <span id="minDiffState" class="details-copy-state"></span><span id="traceState" class="badge" hidden></span><button id="clearTrace" disabled>Clear trace</button>
        <button id="pause">Pause view</button><button id="clear" disabled>Clear normal history</button><button id="clearErrors" disabled>Clear errors</button>
        <button id="copySelected" disabled>Copy selected JSON (0)</button><button id="clearSelected" disabled>Clear selection</button><span id="selectionState" class="details-copy-state"></span>
        <label class="check"><input id="follow" type="checkbox" checked> follow</label>
      </div>
      <div id="eventsScroll" class="scroll events-scroll"><table><thead><tr><th class="selection-cell"><input id="selectVisible" class="row-select" type="checkbox" aria-label="Select all visible events"></th><th>Time (local)</th><th>Event</th><th>Connection UUID</th><th>Miner</th><th>Source/template</th><th>Height</th><th>Share diff</th><th>Status</th><th>Details</th></tr></thead><tbody id="eventsBody"></tbody></table></div>
    </div>
    <aside class="panel details"><div class="panel-head"><h2>JSON inspector</h2><div class="details-toolbar"><span id="copyState" class="details-copy-state"></span><button id="followConnection" disabled>Follow connection</button><button id="copyDetails">Copy JSON</button><button id="closeDetails">Clear</button></div></div><pre id="details" class="json-code">Select a timeline, share, block, seed, worker, or round row to inspect every field.</pre></aside>
  </section>

  <footer><span id="lastEvent">No events received.</span><span>Only 127.0.0.1 is served; transport it with SSH local forwarding.</span></footer>
</div>
<script>
(() => {
  const BROWSER_EVENT_LIMIT = 50000;
  const BROWSER_PRUNE_BATCH = 500;
  const BROWSER_EVENT_BYTE_LIMIT = 256*1024*1024;
  const BROWSER_BYTE_PRUNE_BATCH = 8*1024*1024;
  const INCIDENT_CONTEXT_ROWS = 100;
  const STORAGE_LEASE_MS = 15000;
  const STORAGE_LEASE_HEARTBEAT_MS = 5000;
  const BROWSER_DB_NAME = 'xmrig-proxy-event-dashboard-v1';
  const BROWSER_DB_VERSION = 2;
  const randomBrowserId = () => globalThis.crypto&&crypto.randomUUID?crypto.randomUUID():`${Date.now()}-${Math.random()}`;
  const storageOwnerId = (() => {try{const key='xmrig-dashboard-tab-id',existing=sessionStorage.getItem(key);if(existing)return existing;const created=randomBrowserId();sessionStorage.setItem(key,created);return created;}catch(_){return randomBrowserId();}})();
  const model = { events: [], eventKeys: new Set(), eventRows: new Map(), eventBytes: 0, protectedEventKeys: new Set(), incidentTriggerKeys: new Set(), incidentTailOrder: 0, incidentIncomplete: false, selectedEventKeys: new Set(), unpinnedCount: 0, unpinnedBytes: 0, viewerInstanceId: '', nextEventOrder: 0, maxEvents: BROWSER_EVENT_LIMIT, maxEventBytes: BROWSER_EVENT_BYTE_LIMIT, stats: {}, sources: [], top: [], topLimit: 5, health: {}, api: {}, wallet: {}, persistence: {}, lastViewerSeq: 0, paused: false, pending: 0, stateAt: Date.now(), detailsText: '', detailValue: null, traceConnectionUuid: '', traceConnectionLabel: '', minShareDiff: null, browserDb: null, browserStorageStatus: 'opening', browserStorageMessage: 'Opening IndexedDB event history', storageOwnerId, storageLeaseToken: randomBrowserId(), storageLeaseGeneration: 0, storageGeneration: 0, storageSuspended: false, clearWatermarks: {}, seenPositions: {current_viewer:'',viewers:{},streams:{}}, historyIncomplete: false };
  const $ = id => document.getElementById(id);
  const nf = new Intl.NumberFormat('en-US');
  const utf8Encoder = new TextEncoder();
  const templateAgeClass = ageMs => ageMs>80000?'status-error':ageMs>40000?'status-warning':'status-healthy';
  const groups = {
    shares: e => e.startsWith('share_') || e.startsWith('verify_') || e === 'candidate_verify_fallback',
    blocks: e => e.startsWith('submit_block') || e === 'candidate_verify_fallback',
    templates: e => e.includes('template') || e.startsWith('daemon_height') || e === 'daemon_tip_changed' || e.startsWith('verifier_seed_') || e === 'zmq_new_block',
    workers: e => e.startsWith('worker_'),
    errors: (_e, r) => model.protectedEventKeys.has(eventKey(r))
  };
  const missing = value => value === null || value === undefined || value === '';
  const exact = value => { if (missing(value)) return '—'; try { return BigInt(value).toLocaleString('en-US'); } catch (_) { return String(value); } };
  const xmrAmount = value => {try{const atomic=BigInt(String(value)),whole=atomic/1000000000000n,fraction=(atomic%1000000000000n).toString().padStart(12,'0').replace(/0+$/,'');return `${whole.toLocaleString('en-US')}${fraction?`.${fraction}`:''} XMR`;}catch(_){return '—';}};
  const compact = value => { if (missing(value)) return '—'; const n = Number(value); if (!Number.isFinite(n)) return String(value); const units=['','K','M','G','T','P','E']; let x=n,i=0; while(Math.abs(x)>=1000&&i<units.length-1){x/=1000;i++;} return `${x>=100?x.toFixed(0):x>=10?x.toFixed(1):x.toFixed(2)}${units[i]}`; };
  const hashrate = (value, inputUnit='H/s') => { if(missing(value))return '—';const n=Number(value),factors={'H/s':1,'kH/s':1e3,'MH/s':1e6,'GH/s':1e9,'TH/s':1e12};if(!Number.isFinite(n)||n<0||!Object.prototype.hasOwnProperty.call(factors,inputUnit))return '—';let x=n*factors[inputUnit],i=0;const units=['H/s','kH/s','MH/s','GH/s','TH/s'];while(x>=1000&&i<units.length-1){x/=1000;i++;}const shown=x>=100?x.toFixed(0):x>=10?x.toFixed(1):x.toFixed(2);return `${shown} ${units[i]}`; };
  const rateTitle = value => missing(value)||!Number.isFinite(Number(value))||Number(value)<0?'':`raw API: ${String(value)} kH/s`;
  const setRate = (element,value) => {element.textContent=hashrate(value,'kH/s');element.title=rateTitle(value);};
  const time = value => { if (!value) return '—'; const d=new Date(value); return Number.isNaN(d.valueOf())?value:d.toLocaleString(undefined,{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3,hour12:false}); };
  const short = value => value && value.length > 12 ? `${value.slice(0,8)}…` : (value || '—');
  const td = (tr, value, cls='') => { const cell=document.createElement('td'); cell.textContent=value; if(cls) cell.className=cls; tr.appendChild(cell); return cell; };
  const eventClass = event => (event.startsWith('submit_block')||event==='candidate_verify_fallback')?'event-block':event.startsWith('worker_')?'event-worker':(event.includes('template')||event.startsWith('verifier_seed_')||event==='daemon_tip_changed'||event==='zmq_new_block')?'event-template':'';
  const statusClass = status => `status-${status || 'none'}`;
  const percent = value => missing(value)?'—':`${Number(value).toFixed(3)}%`;
  const jsonReady = value => {
    if(Array.isArray(value)) return value.map(jsonReady);
    if(value && typeof value==='object'){const out={};for(const [key,item] of Object.entries(value)){if(key.endsWith('_json')&&typeof item==='string'){try{out[key]=jsonReady(JSON.parse(item));continue;}catch(_){}}out[key]=jsonReady(item);}return out;}
    return value;
  };
  const deriveEventKey = (row,viewerInstanceId='') => {if(!row||typeof row!=='object')return '';if(row.stream_id&&!missing(row.event_seq))return `stream:${row.stream_id}:${row.event_seq}`;const sequence=!missing(row._viewer_seq)?row._viewer_seq:row.event_seq;return viewerInstanceId&&!missing(sequence)?`viewer:${viewerInstanceId}:${sequence}`:'';};
  const attachEventMeta = (row,key,order,storedBytes=null) => {const serialized=JSON.stringify(row),bytes=storedBytes===null?utf8Encoder.encode(serialized).length:Number(storedBytes);Object.defineProperty(row,'__event_key',{value:key,writable:true,configurable:true});Object.defineProperty(row,'__event_order',{value:order,writable:true,configurable:true});Object.defineProperty(row,'__event_bytes',{value:Number.isFinite(bytes)&&bytes>=0?bytes:0,configurable:true});Object.defineProperty(row,'__search_text',{value:serialized.toLowerCase(),configurable:true});return row;};
  const eventKey = row => row&&row.__event_key?row.__event_key:deriveEventKey(row,model.viewerInstanceId);
  const selectedRows = (rows, selected) => rows.filter(row => {const key=eventKey(row);return key&&selected.has(key);});
  const jsonText = value => JSON.stringify(jsonReady(value),null,2);
  const selectedJson = (rows, selected) => jsonText(selectedRows(rows,selected));
  const escapeHtml = value => value.replace(/[&<>"]/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[char]));
  const jsonHtml = value => JSON.stringify(jsonReady(value),null,2).replace(/("(?:\\u[0-9a-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?/g,(token,isString,isKey,literal)=>{if(isString)return `<span class="${isKey?'json-key':'json-string'}">${escapeHtml(isString)}</span>${isKey||''}`;if(literal)return `<span class="json-literal">${literal}</span>`;return `<span class="json-number">${token}</span>`;});
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
  const INCIDENT_REJECTED = new Set(['rejected','rejected_local','rejected_upstream']);
  const INCIDENT_ERRORS = new Set(['error','fatal','retryable_error']);
  const normalizedText = value => String(value??'').trim().toLowerCase();
  const incidentKind = row => {const event=normalizedText((row||{}).event),status=normalizedText((row||{}).status),code=String((row||{}).error_code??'').trim(),message=normalizedText((row||{}).error_message);if(event==='share_result'&&(status==='stale'||status==='stale_share'||(status==='rejected_local'&&(code==='15'||message==='stale share'))))return 'stale';if(INCIDENT_REJECTED.has(status))return 'rejected';if(INCIDENT_ERRORS.has(status)||event.endsWith('_error'))return 'error';return '';};
  const isIncidentTrigger = row => incidentKind(row)!=='';
  const incidentPriorRows = rows => rows.slice(Math.max(0,rows.length-(INCIDENT_CONTEXT_ROWS+1)));
  const incidentTailEnd = triggerOrder => Number(triggerOrder)+INCIDENT_CONTEXT_ROWS;
  const parseMinimumDifficulty = value => {const text=String(value??'').trim();if(!text)return null;if(!/^\d+$/.test(text))return undefined;try{return BigInt(text);}catch(_){return undefined;}};
  const matchesMinimumDifficulty = (row,minimum) => {if(minimum===null)return true;if(!row||missing(row.share_diff))return false;try{return BigInt(String(row.share_diff))>=minimum;}catch(_){return false;}};
  const newestMatchingEvents = (rows,{categoryFn=null,query='',connectionUuid='',minimumDifficulty=null,limit=1000}={}) => {const result=[],needle=query.trim().toLowerCase();for(let index=rows.length-1;index>=0&&result.length<limit;index--){const row=rows[index];if(categoryFn&&!categoryFn(row.event||'',row))continue;if(connectionUuid&&String(row.connection_uuid||'')!==connectionUuid)continue;if(!matchesMinimumDifficulty(row,minimumDifficulty))continue;if(needle&&!(row.__search_text||'').includes(needle))continue;result.push(row);}result.reverse();return result;};
  const oldestUnselectedKeys = (rows,selected,protectedKeys,count,bytes=0) => {const result=[];let freed=0;for(const row of rows){const key=eventKey(row);if(key&&!selected.has(key)&&!protectedKeys.has(key)){result.push(key);freed+=Number(row.__event_bytes||0);if(result.length>=count&&freed>=bytes)break;}}return result;};
  const sequenceBigInt = value => {const text=String(value??'');if(!/^\d+$/.test(text))return null;try{return BigInt(text);}catch(_){return null;}};
  const positionMap = value => {const result={};if(!value||typeof value!=='object')return result;for(const [key,sequence] of Object.entries(value)){const parsed=sequenceBigInt(sequence);if(parsed!==null)result[String(key)]=parsed.toString();}return result;};
  const normalizeSeenPositions = value => ({current_viewer:String((value||{}).current_viewer||''),viewers:positionMap((value||{}).viewers),streams:positionMap((value||{}).streams)});
  const cloneSeenPositions = value => ({current_viewer:String(value.current_viewer||''),viewers:{...value.viewers},streams:{...value.streams}});
  const setPositionMax = (map,key,value) => {const next=sequenceBigInt(value);if(!key||next===null)return false;const current=sequenceBigInt(map[key])||0n;if(next<=current)return false;map[key]=next.toString();return true;};
  const rowStreamPosition = row => row&&row.stream_id&&sequenceBigInt(row.event_seq)!==null?[String(row.stream_id),String(row.event_seq)]:['',''];
  const rowAlreadySeen = (row,instance='') => {const [stream,streamSequence]=rowStreamPosition(row);if(stream&&sequenceBigInt(model.seenPositions.streams[stream])>=sequenceBigInt(streamSequence))return true;const viewerSequence=sequenceBigInt((row||{})._viewer_seq),seenViewer=sequenceBigInt(model.seenPositions.viewers[instance]);return Boolean(instance&&viewerSequence!==null&&seenViewer!==null&&viewerSequence<=seenViewer);};
  const snapshotHasSequenceGap = (instance,incomingSequence,rows) => {const previous=sequenceBigInt(model.seenPositions.viewers[instance]),incoming=sequenceBigInt(incomingSequence);if(previous!==null&&previous>0n&&incoming!==null&&incoming>previous){const unseen=rows.map(row=>sequenceBigInt(row._viewer_seq)).filter(value=>value!==null&&value>previous);if(!unseen.length||unseen.reduce((a,b)=>a<b?a:b)>previous+1n)return true;}const firstByStream={};for(const row of rows){const [stream,raw]=rowStreamPosition(row),sequence=sequenceBigInt(raw),seen=sequenceBigInt(model.seenPositions.streams[stream]);if(!stream||sequence===null||seen===null||sequence<=seen)continue;if(firstByStream[stream]===undefined||sequence<firstByStream[stream])firstByStream[stream]=sequence;}for(const [stream,first] of Object.entries(firstByStream)){const seen=sequenceBigInt(model.seenPositions.streams[stream]);if(seen!==null&&seen>0n&&first>seen+1n)return true;}return false;};
  const pendingEventWrites=new Map(),pendingEventDeletes=new Set(),pendingSelectionWrites=new Map();
  let storageFlushTimer=null,storageFlushing=false,storageClearing=false,storageUrgent=false,storageQuotaRetries=0,storageLeaseTimer=null,heartbeatPending=false,positionsDirty=false,incidentStateDirty=false,storageIdleWaiters=[];

  function renderStorageBadge(){const badge=$('historyBadge');if(!badge)return;const status=model.browserStorageStatus,archive=model.protectedEventKeys.size;badge.textContent=`history: ${status} · ${nf.format(model.events.length)} · errors ${nf.format(archive)}`;badge.title=`${model.browserStorageMessage||''} · ${compact(model.eventBytes)}B stored${model.historyIncomplete?' · a reconnect gap was detected':''}${model.incidentIncomplete?' · an error archive has incomplete after-context':''}`;badge.className=`badge ${status==='ready'&&!model.historyIncomplete?'ok':status==='error'?'bad':'warn'}`;}
  function setBrowserStorageStatus(status,message){model.browserStorageStatus=status;model.browserStorageMessage=String(message||'');const writable=status==='ready';if($('clear'))$('clear').disabled=!writable;if($('clearErrors'))$('clearErrors').disabled=!writable;renderStorageBadge();}
  const idbRequest = request => new Promise((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error||new Error('IndexedDB request failed'));});
  const idbTransaction = transaction => new Promise((resolve,reject)=>{transaction.oncomplete=()=>resolve();transaction.onerror=()=>reject(transaction.error||new Error('IndexedDB transaction failed'));transaction.onabort=()=>reject(transaction.error||new Error('IndexedDB transaction aborted'));});
  function openBrowserDb(){return new Promise((resolve,reject)=>{if(typeof indexedDB==='undefined'){reject(new Error('IndexedDB is unavailable'));return;}const request=indexedDB.open(BROWSER_DB_NAME,BROWSER_DB_VERSION);request.onupgradeneeded=()=>{const db=request.result;if(!db.objectStoreNames.contains('events')){const events=db.createObjectStore('events',{keyPath:'key'});events.createIndex('order','order');}if(!db.objectStoreNames.contains('selections'))db.createObjectStore('selections',{keyPath:'key'});if(!db.objectStoreNames.contains('meta'))db.createObjectStore('meta',{keyPath:'key'});};request.onsuccess=()=>{const db=request.result;db.onversionchange=()=>db.close();resolve(db);};request.onerror=()=>reject(request.error||new Error('Could not open IndexedDB'));request.onblocked=()=>reject(new Error('IndexedDB upgrade is blocked by another dashboard tab'));});}
  function acquireBrowserLease(db){return new Promise((resolve,reject)=>{const transaction=db.transaction('meta','readwrite'),store=transaction.objectStore('meta'),request=store.get('writer_lease');let denied='',generation=0;request.onsuccess=()=>{const lease=request.result,now=Date.now();if(lease&&lease.owner!==model.storageOwnerId&&Number(lease.expires||0)>now){denied='another dashboard tab owns persistent browser history';transaction.abort();return;}generation=Math.max(0,Number((lease||{}).generation)||0)+1;store.put({key:'writer_lease',owner:model.storageOwnerId,token:model.storageLeaseToken,generation,expires:now+STORAGE_LEASE_MS});};request.onerror=()=>{denied='could not read the browser-history lease';transaction.abort();};transaction.oncomplete=()=>{model.storageLeaseGeneration=generation;resolve();};transaction.onabort=()=>reject(new Error(denied||'could not acquire the browser-history lease'));transaction.onerror=()=>{};});}
  function fencedMutation(storeNames,mutate){const db=model.browserDb;if(!db)return Promise.reject(new Error('IndexedDB is unavailable'));return new Promise((resolve,reject)=>{const names=[...new Set([...storeNames,'meta'])],transaction=db.transaction(names,'readwrite'),meta=transaction.objectStore('meta'),request=meta.get('writer_lease');let failure=null;request.onsuccess=()=>{const lease=request.result,valid=lease&&lease.owner===model.storageOwnerId&&lease.token===model.storageLeaseToken&&Number(lease.generation)===model.storageLeaseGeneration;if(!valid){failure=new Error('persistent browser-history lease is stale');transaction.abort();return;}try{meta.put({...lease,expires:Date.now()+STORAGE_LEASE_MS});mutate(transaction,meta,lease);}catch(error){failure=error;transaction.abort();}};request.onerror=()=>{failure=request.error||new Error('could not validate browser-history lease');transaction.abort();};transaction.oncomplete=()=>resolve();transaction.onabort=()=>reject(failure||transaction.error||new Error('IndexedDB mutation aborted'));transaction.onerror=()=>{};});}
  async function heartbeatBrowserLease(){if(heartbeatPending||!model.browserDb||model.browserStorageStatus!=='ready'||model.storageSuspended)return;heartbeatPending=true;try{await fencedMutation([],()=>{});}catch(error){storageFailed(error);}finally{heartbeatPending=false;}}
  function releaseBrowserLease(){if(!model.browserDb)return Promise.resolve();return fencedMutation([],(_transaction,meta,lease)=>meta.put({...lease,expires:0}));}
  function storageFailed(error){if(storageFlushTimer!==null){clearTimeout(storageFlushTimer);storageFlushTimer=null;}if(storageLeaseTimer!==null){clearInterval(storageLeaseTimer);storageLeaseTimer=null;}pendingEventWrites.clear();pendingEventDeletes.clear();pendingSelectionWrites.clear();if(model.browserDb){try{model.browserDb.close();}catch(_){}model.browserDb=null;}setBrowserStorageStatus('error',`Browser history is memory-only: ${String(error)}`);}
  function scheduleStorageFlush(delay=250){if(model.browserStorageStatus!=='ready'||!model.browserDb||storageClearing)return;if(storageFlushing){if(delay===0)storageUrgent=true;return;}if(delay===0&&storageFlushTimer!==null){clearTimeout(storageFlushTimer);storageFlushTimer=null;}if(storageFlushTimer!==null)return;storageFlushTimer=setTimeout(()=>{storageFlushTimer=null;flushBrowserStorage();},delay);}
  function requestUrgentStorageFlush(){storageUrgent=true;if(!storageFlushing&&!storageClearing){storageUrgent=false;if(storageFlushTimer!==null){clearTimeout(storageFlushTimer);storageFlushTimer=null;}flushBrowserStorage();}}
  async function flushBrowserStorage(){if(storageFlushing||storageClearing||model.browserStorageStatus!=='ready'||!model.browserDb)return;const writes=[...pendingEventWrites.values()],deletes=[...pendingEventDeletes],selections=[...pendingSelectionWrites.entries()],writePositions=positionsDirty,writeIncident=incidentStateDirty,seenPositions=cloneSeenPositions(model.seenPositions),incidentState={tail_order:model.incidentTailOrder,incomplete:model.incidentIncomplete},generation=model.storageGeneration;pendingEventWrites.clear();pendingEventDeletes.clear();pendingSelectionWrites.clear();positionsDirty=false;incidentStateDirty=false;if(!writes.length&&!deletes.length&&!selections.length&&!writePositions&&!writeIncident)return;storageFlushing=true;try{await fencedMutation(['events','selections'],(transaction,meta)=>{const eventStore=transaction.objectStore('events'),selectionStore=transaction.objectStore('selections'),selectionUpdates=new Map(selections);for(const key of deletes){if(selectionUpdates.get(key)===true)continue;eventStore.delete(key);selectionStore.delete(key);}for(const value of writes)eventStore.put(value);for(const [key,selected] of selections){if(selected)selectionStore.put({key});else selectionStore.delete(key);}if(writePositions)meta.put({key:'seen_positions',value:seenPositions});if(writeIncident)meta.put({key:'incident_state',value:incidentState});});storageQuotaRetries=0;}catch(error){if(generation===model.storageGeneration&&error&&error.name==='QuotaExceededError'&&storageQuotaRetries<2){storageQuotaRetries++;model.maxEventBytes=Math.max(4*1024*1024,Math.floor(model.maxEventBytes*.75));pruneBrowserEvents(true);for(const value of writes){if(model.eventKeys.has(value.key)&&!pendingEventWrites.has(value.key))pendingEventWrites.set(value.key,value);}for(const key of deletes){if(!model.eventKeys.has(key)&&!pendingEventWrites.has(key))pendingEventDeletes.add(key);}for(const [key,selected] of selections){if(!pendingSelectionWrites.has(key))pendingSelectionWrites.set(key,selected);}positionsDirty=positionsDirty||writePositions;incidentStateDirty=incidentStateDirty||writeIncident;setBrowserStorageStatus('ready',`IndexedDB quota pressure; retrying with a ${compact(model.maxEventBytes)}B ordinary-history budget`);}else if(generation===model.storageGeneration)storageFailed(error);}finally{storageFlushing=false;const urgent=storageUrgent,waiters=storageIdleWaiters;storageUrgent=false;storageIdleWaiters=[];for(const resolve of waiters)resolve();if(pendingEventWrites.size||pendingEventDeletes.size||pendingSelectionWrites.size||positionsDirty||incidentStateDirty)scheduleStorageFlush(urgent?0:250);}}
  function queueEventWrite(row){if(model.browserStorageStatus!=='ready')return;const key=eventKey(row);if(!key)return;pendingEventDeletes.delete(key);pendingEventWrites.set(key,{key,order:row.__event_order,bytes:row.__event_bytes,protected:model.protectedEventKeys.has(key),incident_trigger:model.incidentTriggerKeys.has(key),row:Object.fromEntries(Object.entries(row))});scheduleStorageFlush();}
  function queueEventDelete(key){if(!key||model.browserStorageStatus!=='ready')return;pendingEventWrites.delete(key);pendingEventDeletes.add(key);scheduleStorageFlush();}
  function markEventSeen(row,instance=''){let changed=false;const [stream,sequence]=rowStreamPosition(row);if(stream)changed=setPositionMax(model.seenPositions.streams,stream,sequence)||changed;if(instance&&!missing((row||{})._viewer_seq))changed=setPositionMax(model.seenPositions.viewers,instance,row._viewer_seq)||changed;if(changed)positionsDirty=true;return changed;}
  function restoreSeenFromRecord(row,key){markEventSeen(row);if(key&&key.startsWith('viewer:')){const split=key.lastIndexOf(':'),instance=key.slice(7,split),sequence=key.slice(split+1);if(setPositionMax(model.seenPositions.viewers,instance,sequence))positionsDirty=true;}}
  function markViewerSeen(instance,sequence){let changed=false;if(instance&&model.seenPositions.current_viewer!==instance){model.seenPositions.current_viewer=instance;changed=true;}if(instance)changed=setPositionMax(model.seenPositions.viewers,instance,sequence)||changed;if(changed)positionsDirty=true;model.viewerInstanceId=instance||model.viewerInstanceId;model.lastViewerSeq=Number(model.seenPositions.viewers[instance]||0);}
  function markHistoryGap(message){const openIncident=model.incidentTailOrder>0;model.historyIncomplete=true;model.browserStorageMessage=message;if(openIncident){model.incidentTailOrder=0;model.incidentIncomplete=true;incidentStateDirty=true;requestUrgentStorageFlush();}renderStorageBadge();}
  function recomputeRetentionCounters(){let count=0,bytes=0;for(const row of model.events){const key=eventKey(row);if(key&&!model.selectedEventKeys.has(key)&&!model.protectedEventKeys.has(key)){count++;bytes+=Number(row.__event_bytes||0);}}model.unpinnedCount=count;model.unpinnedBytes=bytes;}
  function protectEvent(row){const key=eventKey(row);if(!key||model.protectedEventKeys.has(key))return;model.protectedEventKeys.add(key);if(!model.selectedEventKeys.has(key)){model.unpinnedCount=Math.max(0,model.unpinnedCount-1);model.unpinnedBytes=Math.max(0,model.unpinnedBytes-Number(row.__event_bytes||0));}queueEventWrite(row);}
  function updateSelections(keys,selected){const normalized=keys.filter(Boolean);for(const key of normalized){const wasSelected=model.selectedEventKeys.has(key);if(wasSelected===Boolean(selected))continue;const row=model.eventRows.get(key),isProtected=model.protectedEventKeys.has(key);if(selected){model.selectedEventKeys.add(key);if(row&&!isProtected){model.unpinnedCount=Math.max(0,model.unpinnedCount-1);model.unpinnedBytes=Math.max(0,model.unpinnedBytes-Number(row.__event_bytes||0));}if(row)queueEventWrite(row);}else{model.selectedEventKeys.delete(key);if(row&&!isProtected){model.unpinnedCount++;model.unpinnedBytes+=Number(row.__event_bytes||0);}}if(model.browserStorageStatus==='ready')pendingSelectionWrites.set(key,Boolean(selected));}if(model.browserStorageStatus==='ready'&&normalized.length)scheduleStorageFlush(0);if(!selected)pruneBrowserEvents(true);}
  function watermarkScope(row,key=eventKey(row)){if(row&&row.stream_id&&!missing(row.event_seq))return [`stream:${row.stream_id}`,String(row.event_seq)];if(key&&key.startsWith('viewer:')){const split=key.lastIndexOf(':');return [key.slice(0,split),key.slice(split+1)];}return ['',''];}
  function extendClearWatermarks(rows){for(const row of rows){const [scope,sequence]=watermarkScope(row);if(!scope||!/^\d+$/.test(sequence))continue;try{const next=BigInt(sequence),current=BigInt(String(model.clearWatermarks[scope]||'0'));if(next>current)model.clearWatermarks[scope]=next.toString();}catch(_){}}}
  function shouldSkipCleared(row){const key=deriveEventKey(row,model.viewerInstanceId),[scope,sequence]=watermarkScope(row,key);if(!scope||!/^\d+$/.test(sequence))return false;try{return BigInt(sequence)<=BigInt(String(model.clearWatermarks[scope]||'0'));}catch(_){return false;}}
  function addBrowserEvent(row,{persist=true,key='',order=null,bytes=null,protectedRow=false,incidentTrigger=false}={}){if(persist&&shouldSkipCleared(row))return false;const resolvedKey=key||deriveEventKey(row,model.viewerInstanceId);if(!resolvedKey||model.eventKeys.has(resolvedKey))return false;const resolvedOrder=order===null?++model.nextEventOrder:Number(order);model.nextEventOrder=Math.max(model.nextEventOrder,Number.isFinite(resolvedOrder)?resolvedOrder:0);attachEventMeta(row,resolvedKey,resolvedOrder,bytes);model.events.push(row);model.eventKeys.add(resolvedKey);model.eventRows.set(resolvedKey,row);model.eventBytes+=Number(row.__event_bytes||0);if(protectedRow)model.protectedEventKeys.add(resolvedKey);if(incidentTrigger)model.incidentTriggerKeys.add(resolvedKey);if(!model.protectedEventKeys.has(resolvedKey)&&!model.selectedEventKeys.has(resolvedKey)){model.unpinnedCount++;model.unpinnedBytes+=Number(row.__event_bytes||0);}if(persist){let urgent=false;const trigger=isIncidentTrigger(row);if(trigger){model.incidentTriggerKeys.add(resolvedKey);model.incidentTailOrder=Math.max(model.incidentTailOrder,incidentTailEnd(resolvedOrder));incidentStateDirty=true;for(const incidentRow of incidentPriorRows(model.events))protectEvent(incidentRow);urgent=true;}else if(model.incidentTailOrder>0&&resolvedOrder<=model.incidentTailOrder){protectEvent(row);urgent=true;if(resolvedOrder>=model.incidentTailOrder){model.incidentTailOrder=0;incidentStateDirty=true;}}queueEventWrite(row);if(urgent)requestUrgentStorageFlush();}return true;}
  function removeEventKeys(keys,{persist=true}={}){const removed=new Set(keys),kept=[];for(const row of model.events){const key=eventKey(row);if(!removed.has(key)){kept.push(row);continue;}const selected=model.selectedEventKeys.has(key),protectedRow=model.protectedEventKeys.has(key);if(!selected&&!protectedRow){model.unpinnedCount=Math.max(0,model.unpinnedCount-1);model.unpinnedBytes=Math.max(0,model.unpinnedBytes-Number(row.__event_bytes||0));}model.eventBytes=Math.max(0,model.eventBytes-Number(row.__event_bytes||0));model.eventKeys.delete(key);model.eventRows.delete(key);model.selectedEventKeys.delete(key);model.protectedEventKeys.delete(key);model.incidentTriggerKeys.delete(key);if(persist)queueEventDelete(key);}model.events=kept;return removed.size;}
  function pruneBrowserEvents(force=false){const countThreshold=force?model.maxEvents:model.maxEvents+BROWSER_PRUNE_BATCH,byteThreshold=force?model.maxEventBytes:model.maxEventBytes+BROWSER_BYTE_PRUNE_BATCH;if(model.unpinnedCount<=countThreshold&&model.unpinnedBytes<=byteThreshold)return 0;const countOver=Math.max(0,model.unpinnedCount-model.maxEvents),bytesOver=Math.max(0,model.unpinnedBytes-model.maxEventBytes),keys=oldestUnselectedKeys(model.events,model.selectedEventKeys,model.protectedEventKeys,countOver,bytesOver);return keys.length?removeEventKeys(keys):0;}
  async function clearStoredHistory(keys){if(model.browserStorageStatus!=='ready'||!model.browserDb)return;storageClearing=true;if(storageFlushTimer!==null){clearTimeout(storageFlushTimer);storageFlushTimer=null;}if(storageFlushing)await new Promise(resolve=>storageIdleWaiters.push(resolve));if(model.browserStorageStatus!=='ready'||!model.browserDb){storageClearing=false;return;}const deleting=new Set(keys),carriedWrites=[...pendingEventWrites].filter(([key])=>!deleting.has(key)),carriedDeletes=[...pendingEventDeletes].filter(key=>!deleting.has(key)),carriedSelections=[...pendingSelectionWrites].filter(([key])=>!deleting.has(key)),seenPositions=cloneSeenPositions(model.seenPositions),incidentState={tail_order:model.incidentTailOrder,incomplete:model.incidentIncomplete};model.storageGeneration++;pendingEventWrites.clear();pendingEventDeletes.clear();pendingSelectionWrites.clear();positionsDirty=false;incidentStateDirty=false;try{await fencedMutation(['events','selections'],(transaction,meta)=>{const eventStore=transaction.objectStore('events'),selectionStore=transaction.objectStore('selections');for(const key of carriedDeletes){eventStore.delete(key);selectionStore.delete(key);}for(const [,value] of carriedWrites)eventStore.put(value);for(const [key,selected] of carriedSelections){if(selected)selectionStore.put({key});else selectionStore.delete(key);}for(const key of keys){eventStore.delete(key);selectionStore.delete(key);}meta.put({key:'clear_watermarks',value:model.clearWatermarks});meta.put({key:'seen_positions',value:seenPositions});meta.put({key:'incident_state',value:incidentState});});}catch(error){storageFailed(error);}finally{storageClearing=false;if(model.browserStorageStatus==='ready'&&(pendingEventWrites.size||pendingEventDeletes.size||pendingSelectionWrites.size||positionsDirty||incidentStateDirty))scheduleStorageFlush();}}
  async function restoreBrowserHistory(){let db=null;try{db=await openBrowserDb();await acquireBrowserLease(db);model.browserDb=db;if(navigator.storage&&navigator.storage.estimate){const estimate=await navigator.storage.estimate(),quota=Number(estimate.quota);if(Number.isFinite(quota)&&quota>0)model.maxEventBytes=Math.min(BROWSER_EVENT_BYTE_LIMIT,Math.max(4*1024*1024,Math.floor(quota/2)));}const transaction=db.transaction(['events','selections','meta'],'readonly'),done=idbTransaction(transaction),meta=transaction.objectStore('meta'),recordsPromise=idbRequest(transaction.objectStore('events').index('order').getAll()),selectionsPromise=idbRequest(transaction.objectStore('selections').getAllKeys()),watermarksPromise=idbRequest(meta.get('clear_watermarks')),seenPromise=idbRequest(meta.get('seen_positions')),incidentPromise=idbRequest(meta.get('incident_state')),[records,selections,watermarks,seen,incident]=await Promise.all([recordsPromise,selectionsPromise,watermarksPromise,seenPromise,incidentPromise]);await done;model.clearWatermarks=watermarks&&watermarks.value&&typeof watermarks.value==='object'?watermarks.value:{};model.seenPositions=normalizeSeenPositions(seen&&seen.value);for(const record of records){if(record&&record.key&&record.row&&typeof record.row==='object'){addBrowserEvent(record.row,{persist:false,key:String(record.key),order:Number(record.order)||0,bytes:Number(record.bytes)||null,protectedRow:Boolean(record.protected),incidentTrigger:Boolean(record.incident_trigger)});restoreSeenFromRecord(record.row,String(record.key));}}const inferredTail=[...model.incidentTriggerKeys].reduce((tail,key)=>Math.max(tail,incidentTailEnd((model.eventRows.get(key)||{}).__event_order||0)),0),savedIncident=incident&&incident.value&&typeof incident.value==='object'?incident.value:null;model.incidentTailOrder=savedIncident?Math.max(0,Number(savedIncident.tail_order)||0):(inferredTail>model.nextEventOrder?inferredTail:0);model.incidentIncomplete=Boolean(savedIncident&&savedIncident.incomplete);model.historyIncomplete=model.historyIncomplete||model.incidentIncomplete;model.viewerInstanceId=model.seenPositions.current_viewer||'';model.lastViewerSeq=Number(model.seenPositions.viewers[model.viewerInstanceId]||0);model.selectedEventKeys=new Set(selections.map(String).filter(key=>model.eventKeys.has(key)));recomputeRetentionCounters();await fencedMutation([],()=>{});model.storageSuspended=false;setBrowserStorageStatus('ready',`IndexedDB keeps about ${nf.format(BROWSER_EVENT_LIMIT)} ordinary rows or ${compact(model.maxEventBytes)}B; selections and 201-row error windows are pinned`);storageLeaseTimer=setInterval(heartbeatBrowserLease,STORAGE_LEASE_HEARTBEAT_MS);pruneBrowserEvents(true);if(positionsDirty||incidentStateDirty)scheduleStorageFlush(0);scheduleTimeline(false);}catch(error){if(db){try{db.close();}catch(_){}}model.browserDb=null;setBrowserStorageStatus('error',`Browser history is memory-only: ${String(error)}`);}}

  let stateRenderTimer=null,stateApiChanged=false,stateWalletChanged=false;
  function renderStateNow(){if(stateRenderTimer!==null){clearTimeout(stateRenderTimer);stateRenderTimer=null;}const apiChanged=stateApiChanged,walletChanged=stateWalletChanged;stateApiChanged=false;stateWalletChanged=false;$('topTitle').textContent=`Top ${model.topLimit} observed accepted shares`;renderHeader();renderCards();renderSources();if(apiChanged)renderApi();if(walletChanged)renderWallet();renderTop();renderPersistence();renderVerifier();}
  function scheduleStateRender(immediate=false){if(immediate){renderStateNow();return;}if(stateRenderTimer!==null)return;stateRenderTimer=setTimeout(renderStateNow,100);}
  function applyState(data,immediate=false) {
    const apiChanged=Object.prototype.hasOwnProperty.call(data,'api'),walletChanged=Object.prototype.hasOwnProperty.call(data,'wallet');
    model.stats=data.stats||{};model.sources=data.sources||[];model.top=data.top_shares||[];model.topLimit=data.top_limit??5;model.health=data.health||{};model.persistence=data.persistence||model.persistence||{};if(apiChanged)model.api=data.api||{};if(walletChanged)model.wallet=data.wallet||{};model.stateAt=Date.now();stateApiChanged=stateApiChanged||apiChanged;stateWalletChanged=stateWalletChanged||walletChanged;scheduleStateRender(immediate);
  }
  function applySnapshot(data) {
    const instance=String(((data||{}).health||{}).viewer_instance_id||''),incomingSequence=String(data.viewer_seq||0),rows=Array.isArray(data.events)?data.events:[],previousInstance=model.seenPositions.current_viewer,openIncident=model.incidentTailOrder>0;let gap=snapshotHasSequenceGap(instance,incomingSequence,rows);if(instance&&previousInstance&&instance!==previousInstance&&openIncident){const connects=rows.some(row=>{const [stream,raw]=rowStreamPosition(row),previous=sequenceBigInt(model.seenPositions.streams[stream]),sequence=sequenceBigInt(raw);return stream&&previous!==null&&previous>0n&&sequence===previous+1n;});if(!connects)gap=true;}if(gap)markHistoryGap('Browser history has a reconnect gap; an open error window was stopped instead of counting unrelated later rows');model.viewerInstanceId=instance||model.viewerInstanceId;for(const row of rows){const seen=rowAlreadySeen(row,instance);markEventSeen(row,instance);if(!seen)addBrowserEvent(row);}markViewerSeen(instance,incomingSequence);if(positionsDirty)scheduleStorageFlush();applyState(data,true);pruneBrowserEvents(false);scheduleTimeline(true);
  }
  function applyUpdate(data) {
    const instance=String((((data||{}).health)||{}).viewer_instance_id||model.viewerInstanceId||''),incoming=sequenceBigInt(data.viewer_seq),previous=sequenceBigInt(model.seenPositions.viewers[instance]),row=data.row||{},[stream,rawStreamSequence]=rowStreamPosition(row),streamSequence=sequenceBigInt(rawStreamSequence),previousStream=sequenceBigInt(model.seenPositions.streams[stream]);if(previous!==null&&incoming!==null&&incoming<=previous)return;let gap=previous!==null&&previous>0n&&incoming!==null&&incoming>previous+1n;if(stream&&previousStream!==null&&previousStream>0n&&streamSequence!==null&&streamSequence>previousStream+1n)gap=true;if(instance&&model.seenPositions.current_viewer&&instance!==model.seenPositions.current_viewer&&model.incidentTailOrder>0&&!(stream&&previousStream!==null&&streamSequence===previousStream+1n))gap=true;if(gap)markHistoryGap('Browser history has a live sequence gap; an open error window was stopped instead of counting unrelated later rows');const seen=rowAlreadySeen(row,instance);markEventSeen(row,instance);markViewerSeen(instance,String(data.viewer_seq||0));if(!seen)addBrowserEvent(row);if(positionsDirty)scheduleStorageFlush();applyState(data);pruneBrowserEvents(false);
    if(model.paused){model.pending++;$('pause').textContent=`Resume (${model.pending})`;}else scheduleTimeline(false);
  }
  function renderHeader() {
    const h=model.health||{}, socket=$('socketBadge'), coverage=$('coverageBadge');
    const socketHealthy=h.socket_connected&&h.reader_status==='connected';
    socket.textContent=`socket: ${h.reader_status||'starting'}`; socket.className=`badge ${socketHealthy?'ok':h.reader_status==='fatal'?'bad':'warn'}`;
    coverage.textContent=h.coverage_complete?'coverage: observed window':'coverage: incomplete'; coverage.className=`badge ${h.coverage_complete?'ok':'warn'}`;
    $('sessionBadge').textContent=`session ${h.session||0}`;
    renderStorageBadge();
    const api=$('apiBadge'), a=model.api||{}, apiAge=a.last_update_utc?Date.now()-new Date(a.last_update_utc).valueOf():0, apiStale=a.status==='connected'&&apiAge>(Number(a.interval_seconds||5)*2500), apiStatus=apiStale?'stale':(a.status||'disabled'); api.textContent=`API: ${apiStatus}`; api.className=`badge ${apiStatus==='connected'?'ok':apiStatus==='error'?'bad':'warn'}`;
    const wallet=$('walletBadge'),w=model.wallet||{},walletAge=w.last_update_utc?Date.now()-new Date(w.last_update_utc).valueOf():0,walletStale=w.status==='connected'&&walletAge>(Number(w.interval_seconds||20)*2500),walletStatus=walletStale?'stale':(w.status||'disabled');wallet.textContent=`wallet: ${walletStatus}`;wallet.className=`badge ${walletStatus==='connected'?'ok':walletStatus==='error'?'bad':'warn'}`;
    const persistence=model.persistence||{},db=$('dbBadge'),dbStatus=persistence.enabled===false?'disabled':(persistence.status||'starting');db.textContent=`database: ${dbStatus}`;db.className=`badge ${dbStatus==='ready'?'ok':dbStatus==='error'?'bad':'warn'}`;
    const verifier=(persistence.verifier||{}),verifierStatus=(verifier.status||{}),vb=$('verifierBadge'),verifierHealth=verifierStatus.health||((Number(verifier.results||0)>0)?'observed':'waiting'),verifierGood=['healthy','ready','observed'].includes(verifierHealth);vb.textContent=`verifier: ${verifierHealth}`;vb.className=`badge ${verifierGood?'ok':verifierHealth==='waiting'?'warn':'bad'}`;
    $('readerState').textContent=`${h.reader_message||'—'}\nSocket: ${h.socket_path||'—'}\nStarted: ${time(h.started_utc)}\nLast event: ${time(h.last_event_utc)}`;
    $('topCompleteness').textContent=h.coverage_complete?'observed window':'incomplete after gap/reconnect'; $('topCompleteness').className=`badge ${h.coverage_complete?'ok':'warn'}`;
    $('lastEvent').textContent=h.last_event_utc?`Last observed event: ${time(h.last_event_utc)}`:'No events received.';
  }
  function renderCards() {
    const s=model.stats||{}, summary=(model.api||{}).summary||{}, rates=summary.hashrate||[], results=summary.results||{}, miners=summary.miners||{},p=model.persistence||{},c=p.cumulative||{},r=p.current_round||{};
    $('activeMiners').textContent=nf.format((model.api||{}).status==='connected'?(miners.now||0):(s.active_miners||0)); setRate($('hashrate1m'),rates.length?rates[0]:null); setRate($('hashrate10m'),rates.length>1?rates[1]:null); $('templates').textContent=nf.format(s.templates||0); $('localAccepted').textContent=nf.format(s.local_accepted||0); $('apiAccepted').textContent=(model.api||{}).status==='connected'?nf.format(results.accepted||0):'—'; $('rejected').textContent=nf.format(s.rejected||0); $('blocksAccepted').textContent=nf.format(s.blocks_accepted||0);
    $('durableHashes').textContent=compact(c.credited_hashes_events);$('currentEffort').textContent=percent(r.effort_percent);$('averageEffort').textContent=percent(p.average_round_effort_percent);$('bigShareCount').textContent=nf.format(p.big_share_count||0);
  }
  function renderSources() {
    const host=$('sources'); host.replaceChildren(); $('sourceCount').textContent=`${model.sources.length} observed`;
    if(!model.sources.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='Waiting for daemon-backed jobs…';host.appendChild(empty);return;}
    for(const source of model.sources){const row=document.createElement('div');row.className='source-row'; const elapsed=Date.now()-model.stateAt, ageMs=source.age_ms==null?null:source.age_ms+elapsed, age=ageMs==null?'—':`${(ageMs/1000).toFixed(1)}s`, values=[`S${source.source_id}`,`T${source.template_id||'—'}`,`height ${source.height||'—'} · net ${compact(source.network_target_diff)}`,age,source.status||'observed']; values.forEach((value,index)=>{const span=document.createElement('span');span.textContent=value;if(index===3&&ageMs!==null)span.className=templateAgeClass(ageMs);if(index===4)span.className=statusClass(source.status);row.appendChild(span);});host.appendChild(row);}
  }
  function renderApiAge() {
    const api=model.api||{}, updateAge=api.last_update_utc?Math.max(0,(Date.now()-new Date(api.last_update_utc).valueOf())/1000):null;
    $('apiUpdated').textContent=api.enabled?`${api.message||api.status} · ${time(api.last_update_utc)}${updateAge===null?'':` · ${updateAge.toFixed(1)}s ago`}`:'not configured';
  }
  function renderApi() {
    const api=model.api||{}, summary=api.summary||{}, rates=summary.hashrate||[], miners=summary.miners||{}, upstreams=summary.upstreams||{}, results=summary.results||{}, resources=summary.resources||{}, memory=resources.memory||{}, loads=resources.load_average||[], workers=api.workers||[],solo=summary.daemon_solo||{},payouts=solo.payouts||[];
    renderApiAge();
    setRate($('hashrate1h'),rates.length>2?rates[2]:null); $('apiMiners').textContent=api.status==='connected'?`${miners.now||0} / ${miners.max||0}`:'—'; $('apiUpstreams').textContent=api.status==='connected'?`${upstreams.active||0} / ${upstreams.total||0}`:'—'; $('apiResults').textContent=api.status==='connected'?`${results.accepted||0} / ${results.rejected||0} / ${results.invalid||0}`:'—'; $('apiLatency').textContent=api.status==='connected'?`${Number(results.latency||0).toFixed(1)} ms`:'—'; $('apiUptime').textContent=api.status==='connected'?`${Math.floor((summary.uptime||0)/3600)}h ${Math.floor(((summary.uptime||0)%3600)/60)}m`:'—'; $('apiResources').textContent=api.status==='connected'?`${compact(memory.resident_set_memory||0)}B / ${Number(loads[0]||0).toFixed(2)}`:'—';
    const payoutHost=$('soloPayouts');payoutHost.replaceChildren();if(!payouts.length){const empty=document.createElement('span');empty.className='muted';empty.textContent=solo.enabled?'Daemon-solo enabled; no validated payout returned.':'No daemon-solo payout exposed by the API.';payoutHost.appendChild(empty);}else{for(const payout of payouts){const card=document.createElement('div');card.className='seed';const title=document.createElement('b');title.textContent=`${payout.coin||'coin'} · ${payout.network||'network'}`;const address=document.createElement('div');address.className='payout-address';address.textContent=payout.address||'—';address.title='Select to copy, or click the card for JSON details';const state=document.createElement('div');state.className=payout.validated?'status-accepted':'status-warning';state.textContent=`${payout.type||'address'} · ${payout.validated?'validated':'unvalidated'}`;card.append(title,address,state);card.addEventListener('click',()=>showDetails(payout));payoutHost.appendChild(card);}}
    const body=$('apiWorkersBody');body.replaceChildren();$('apiWorkersEmpty').style.display=workers.length?'none':'block';
    for(const worker of workers){const tr=document.createElement('tr'),rates=worker.hashrate||[];td(tr,worker.name||'—');td(tr,String(worker.connections||0));const one=td(tr,hashrate(rates[0],'kH/s'));one.title=rateTitle(rates[0]);const ten=td(tr,hashrate(rates[1],'kH/s'));ten.title=rateTitle(rates[1]);td(tr,String(worker.accepted||0),statusClass('accepted'));td(tr,String(worker.rejected||0),worker.rejected?'status-rejected':'');td(tr,String(worker.invalid||0),worker.invalid?'status-rejected':'');td(tr,exact(worker.hashes));tr.addEventListener('click',()=>showDetails(worker));body.appendChild(tr);}
  }
  function renderWallet(){const wallet=model.wallet||{},live=wallet.transfers||[],durable=(model.persistence||{}).wallet_transfers||[],transfers=live.length?live:durable,body=$('walletTransfersBody');$('walletUpdated').textContent=wallet.enabled?`${wallet.message||wallet.status} · ${time(wallet.last_update_utc)}`:'not configured';body.replaceChildren();$('walletTransfersEmpty').style.display=transfers.length?'none':'block';for(const transfer of transfers){const tr=document.createElement('tr'),timestamp=Number(transfer.timestamp||0);td(tr,timestamp?time(new Date(timestamp*1000).toISOString()):'—');td(tr,String(transfer.height||'—'));td(tr,xmrAmount(transfer.amount_atomic));td(tr,nf.format(Number(transfer.confirmations||0)));td(tr,transfer.locked?'locked':'unlocked',transfer.locked?'status-warning':'status-accepted');td(tr,`${transfer.account_index??0} / ${transfer.subaddress_index??0}`);const txid=td(tr,short(transfer.txid));txid.title=transfer.txid||'';tr.addEventListener('click',()=>showDetails(transfer));body.appendChild(tr);}}
  function renderTop() {
    const body=$('topBody'); body.replaceChildren(); $('topEmpty').style.display=model.top.length?'none':'block';
    model.top.forEach((share,index)=>{const tr=document.createElement('tr');td(tr,String(index+1));td(tr,time(share.time_utc));const d=td(tr,exact(share.share_diff));d.title=`Reported difficulty ${share.share_diff}`;td(tr,share.miner_label||'—');td(tr,share.worker||'—');td(tr,share.height||'—');td(tr,share.status==='accepted_upstream'?'upstream':'local',statusClass(share.status));tr.addEventListener('click',()=>showDetails(share));body.appendChild(tr);});
  }
  function renderPersistence() {
    const p=model.persistence||{},r=p.current_round||{},c=p.cumulative||{},rounds=p.recent_rounds||[],blocks=p.recent_blocks||[],big=p.big_shares||[];
    $('trackingSince').textContent=p.tracking_since?`tracking since ${time(p.tracking_since)} · events ${p.coverage_complete?'complete':'incomplete'} · current round ${r.coverage_complete?'complete':'partial'} · API ${(c.api_coverage_complete??true)?'complete':'incomplete'}`:'persistence disabled';
    $('roundId').textContent=r.id?`#${r.id}`:'—';$('roundHashes').textContent=exact(r.credited_hashes);$('roundShares').textContent=exact(r.accepted_shares);$('roundEffort').textContent=percent(r.effort_percent);$('apiWorkerHashes').textContent=exact(c.api_worker_hashes);$('workReconciliation').textContent=exact(c.api_minus_events);
    const roundBody=$('roundsBody');roundBody.replaceChildren();$('roundsEmpty').style.display=rounds.length?'none':'block';
    for(const item of rounds){const tr=document.createElement('tr');td(tr,`#${item.id}`);td(tr,time(item.started_utc));td(tr,time(item.ended_utc));td(tr,item.end_height||item.start_height||'—');td(tr,exact(item.accepted_shares));td(tr,exact(item.credited_hashes));td(tr,percent(item.effort_percent));td(tr,item.coverage_complete?'complete':'incomplete',item.coverage_complete?'status-accepted':'status-warning');tr.addEventListener('click',()=>loadRound(item.id));roundBody.appendChild(tr);}
    const blockBody=$('blocksBody');blockBody.replaceChildren();$('blocksEmpty').style.display=blocks.length?'none':'block';
    for(const item of blocks){const tr=document.createElement('tr');td(tr,time(item.time_utc));td(tr,`#${item.round_id}`);td(tr,item.height||'—');const block=td(tr,short(item.block_id));block.title=item.block_id||'';td(tr,exact(item.share_diff));td(tr,item.latency_ms?`${item.latency_ms} ms`:'—');tr.addEventListener('click',()=>loadRound(item.round_id));blockBody.appendChild(tr);}
    const bigBody=$('bigSharesBody');bigBody.replaceChildren();$('bigSharesEmpty').style.display=big.length?'none':'block';
    for(const item of big){const tr=document.createElement('tr');td(tr,time(item.time_utc));td(tr,`#${item.round_id}`);td(tr,exact(item.share_diff));td(tr,item.worker||'—');td(tr,item.height||'—');tr.addEventListener('click',()=>loadShare(item.event_key));bigBody.appendChild(tr);}
  }
  function renderVerifier() {
    const p=model.persistence||{},v=p.verifier||{},s=v.status||{},seeds=v.seeds||[];
    $('verifierUpdated').textContent=v.last_event_utc?`last telemetry ${time(v.last_event_utc)}`:'waiting for verifier telemetry';$('verifyCounts').textContent=`${exact(v.requests||0)} / ${exact(v.results||0)}`;$('verifyFailures').textContent=`${exact(v.mismatches||0)} / ${exact(v.errors||0)}`;$('verifyQueue').textContent=v.results?`${Number(v.average_queue_ms||0).toFixed(3)} ms`:'—';$('verifyHash').textContent=v.results?`${Number(v.average_hash_ms||0).toFixed(3)} ms`:'—';$('verifyTotal').textContent=v.results?`${Number(v.average_total_ms||0).toFixed(3)} ms`:'—';$('verifyLoad').textContent=(s.active!==undefined||s.queued!==undefined)?`${s.active||0} / ${s.queued||0} / ${s.queue_limit||'—'}`:'—';$('verifySeedCount').textContent=(s.seed_count!==undefined||s.seed_capacity!==undefined)?`${s.seed_count||0} / ${s.seed_capacity||'—'}`:`${seeds.length} / —`;$('verifyVms').textContent=s.vm_pool_size??'—';
    const host=$('verifierSeeds');host.replaceChildren();if(!seeds.length){const empty=document.createElement('span');empty.className='muted';empty.textContent='No seed lifecycle events observed.';host.appendChild(empty);return;}for(const seed of seeds){const card=document.createElement('div');card.className='seed';const role=document.createElement('b');role.textContent=seed.role||'retained';const hash=document.createElement('div');hash.textContent=short(seed.seed_hash);hash.title=seed.seed_hash;const state=document.createElement('div');state.className='muted';state.textContent=`${seed.status||'observed'}${seed.prepare_ms?` · ${seed.prepare_ms} ms`:''}`;card.append(role,hash,state);card.addEventListener('click',()=>showDetails(seed));host.appendChild(card);}
  }
  function renderRoundDetail(value){const round=value.round||{},shares=value.top_shares||[],panel=$('selectedRoundPanel'),body=$('selectedRoundShares');panel.style.display='block';$('selectedRoundTitle').textContent=`Round #${round.id||'—'} · top ${shares.length} retained shares`;$('selectedRoundEmpty').style.display=shares.length?'none':'block';body.replaceChildren();shares.forEach((item,index)=>{const tr=document.createElement('tr');td(tr,String(index+1));td(tr,time(item.time_utc));td(tr,exact(item.share_diff));td(tr,exact(item.credited_diff));td(tr,item.worker||'—');td(tr,item.height||'—');td(tr,item.status||'—',statusClass(item.status));tr.addEventListener('click',()=>loadShare(item.event_key));body.appendChild(tr);});showDetails({round:value.round,blocks:value.blocks});panel.scrollIntoView({behavior:'smooth',block:'nearest'});}
  async function loadRound(id){try{const response=await fetch(`/api/round?id=${encodeURIComponent(id)}`,{headers:{Accept:'application/json'}});const value=await response.json();if(!response.ok)throw new Error(value.error||`HTTP ${response.status}`);renderRoundDetail(value);}catch(error){showDetails({error:String(error),round_id:id});}}
  async function loadShare(key){try{const response=await fetch(`/api/share?key=${encodeURIComponent(key)}`,{headers:{Accept:'application/json'}});const value=await response.json();if(!response.ok)throw new Error(value.error||`HTTP ${response.status}`);showDetails(value);}catch(error){showDetails({error:String(error),share_event_key:key});}}
  function filteredEvents() {
    const category=$('category').value;
    return newestMatchingEvents(model.events,{categoryFn:category==='all'?null:groups[category],query:$('search').value,connectionUuid:model.traceConnectionUuid,minimumDifficulty:model.minShareDiff});
  }
  function updateSelectionControls(values=filteredEvents()) {
    const selectedCount=model.selectedEventKeys.size,visibleKeys=values.map(eventKey).filter(Boolean),visibleSelected=visibleKeys.filter(key=>model.selectedEventKeys.has(key)).length,selectVisible=$('selectVisible');
    $('copySelected').textContent=`Copy selected JSON (${selectedCount})`;$('copySelected').disabled=!selectedCount;$('clearSelected').disabled=!selectedCount;
    selectVisible.disabled=!visibleKeys.length;selectVisible.checked=visibleKeys.length>0&&visibleSelected===visibleKeys.length;selectVisible.indeterminate=visibleSelected>0&&visibleSelected<visibleKeys.length;
  }
  let scheduled=false, forceFollow=false;
  function scheduleTimeline(force){forceFollow=forceFollow||force;if(scheduled)return;scheduled=true;setTimeout(()=>{scheduled=false;renderTimeline(forceFollow);forceFollow=false;},100);}
  function renderTimeline(force) {
    const values=filteredEvents(),body=$('eventsBody'),scroller=$('eventsScroll');body.replaceChildren();
    for(const row of values){const tr=document.createElement('tr'),key=eventKey(row),selected=key&&model.selectedEventKeys.has(key),archived=key&&model.protectedEventKeys.has(key);if(archived)tr.classList.add('event-archived');if(selected)tr.classList.add('event-selected');const selectCell=td(tr,'','selection-cell'),checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.className='row-select';checkbox.checked=selected;checkbox.disabled=!key;checkbox.setAttribute('aria-label',`Select event ${row.event_seq||key||''}`);checkbox.addEventListener('click',event=>event.stopPropagation());checkbox.addEventListener('change',()=>{updateSelections([key],checkbox.checked);tr.classList.toggle('event-selected',checkbox.checked);updateSelectionControls(values);renderStorageBadge();});selectCell.appendChild(checkbox);td(tr,time(row.time_utc));td(tr,row.event||'—',eventClass(row.event||''));const connection=td(tr,short(row.connection_uuid));connection.title=row.connection_uuid||'';td(tr,row.miner_label?`${row.miner_label}${row.worker?` · ${row.worker}`:''}`:'—');td(tr,row.source_id?`S${row.source_id}${row.template_id?`:T${row.template_id}`:''}`:'—');td(tr,row.height||'—');const diff=td(tr,compact(row.share_diff));if(row.share_diff)diff.title=exact(row.share_diff);td(tr,row.status||'—',statusClass(row.status));td(tr,detailText(row));tr.addEventListener('click',()=>showDetails(row));body.appendChild(tr);}
    $('eventCount').textContent=`${values.length} shown · ${model.events.length} stored · ${model.protectedEventKeys.size} error-archive rows`;
    renderStorageBadge();
    updateSelectionControls(values);
    if((force||$('follow').checked)&&!model.paused) scroller.scrollTop=scroller.scrollHeight;
  }
  function renderTraceControls(){const value=model.detailValue,candidate=value&&typeof value==='object'?String(value.connection_uuid||''):'',active=model.traceConnectionUuid;$('followConnection').disabled=!candidate;$('followConnection').textContent=candidate&&candidate===active?'Following connection':'Follow connection';$('traceState').hidden=!active;$('traceState').textContent=active?`trace: ${model.traceConnectionLabel||short(active)}`:'';$('traceState').title=active;$('clearTrace').disabled=!active;}
  function showDetails(value){model.detailValue=value&&typeof value==='object'?value:null;model.detailsText=jsonText(value);$('details').innerHTML=jsonHtml(value);$('copyState').textContent='';renderTraceControls();}
  function followSelectedConnection(){const row=model.detailValue,connection=String((row||{}).connection_uuid||'');if(!connection)return;model.traceConnectionUuid=connection;model.traceConnectionLabel=String(row.miner_label||short(connection));renderTraceControls();scheduleTimeline(true);}
  function clearConnectionTrace(){model.traceConnectionUuid='';model.traceConnectionLabel='';renderTraceControls();scheduleTimeline(false);}
  function updateMinimumDifficulty(){const input=$('minShareDiff'),parsed=parseMinimumDifficulty(input.value),invalid=parsed===undefined;input.setCustomValidity(invalid?'Enter a non-negative whole number.':'');input.setAttribute('aria-invalid',String(invalid));$('minDiffState').textContent=invalid?'whole numbers only':'';model.minShareDiff=invalid?null:parsed;scheduleTimeline(false);}
  async function clearBrowserRows(kind){const archive=kind==='errors',rows=model.events.filter(row=>archive?model.protectedEventKeys.has(eventKey(row)):!model.protectedEventKeys.has(eventKey(row))),keys=rows.map(eventKey).filter(Boolean);extendClearWatermarks(model.events);if(archive){model.incidentTailOrder=0;model.incidentIncomplete=false;incidentStateDirty=true;}removeEventKeys(keys,{persist:false});await clearStoredHistory(keys);scheduleTimeline(false);}
  async function copyText(value){try{await navigator.clipboard.writeText(value);return;}catch(_){const area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();}}

  $('category').addEventListener('change',()=>scheduleTimeline(false)); $('search').addEventListener('input',()=>scheduleTimeline(false));$('minShareDiff').addEventListener('input',updateMinimumDifficulty);
  $('pause').addEventListener('click',()=>{model.paused=!model.paused;if(model.paused){$('pause').textContent='Resume';}else{model.pending=0;$('pause').textContent='Pause view';scheduleTimeline(true);}});
  $('clear').addEventListener('click',async()=>{if(window.confirm('Clear ordinary browser history and its selections? The Errors archive will remain.'))await clearBrowserRows('normal');});
  $('clearErrors').addEventListener('click',async()=>{if(window.confirm('Permanently clear all archived error incidents, their 100-row context windows, and any selections on those rows?'))await clearBrowserRows('errors');});
  $('closeDetails').addEventListener('click',()=>{model.detailValue=null;model.detailsText='';$('details').textContent='Select a timeline, share, block, seed, worker, or round row to inspect every field.';$('copyState').textContent='';renderTraceControls();});
  $('followConnection').addEventListener('click',followSelectedConnection);$('clearTrace').addEventListener('click',clearConnectionTrace);
  $('selectVisible').addEventListener('change',event=>{updateSelections(filteredEvents().map(eventKey),event.currentTarget.checked);scheduleTimeline(false);});
  $('clearSelected').addEventListener('click',()=>{updateSelections([...model.selectedEventKeys],false);$('selectionState').textContent='';scheduleTimeline(false);});
  $('copySelected').addEventListener('click',async()=>{const rows=selectedRows(model.events,model.selectedEventKeys);if(!rows.length){$('selectionState').textContent='nothing selected';return;}await copyText(selectedJson(model.events,model.selectedEventKeys));$('selectionState').textContent=`copied ${rows.length} rows`;setTimeout(()=>{$('selectionState').textContent='';},1500);});
  $('copyDetails').addEventListener('click',async()=>{if(!model.detailsText){$('copyState').textContent='nothing selected';return;}await copyText(model.detailsText);$('copyState').textContent='copied';setTimeout(()=>{$('copyState').textContent='';},1500);});
  $('inspectVerifier').addEventListener('click',()=>showDetails((model.persistence||{}).verifier||{}));
  $('closeRound').addEventListener('click',()=>{$('selectedRoundPanel').style.display='none';$('selectedRoundShares').replaceChildren();});
  const loadRoundLookup=()=>{const value=$('roundLookup').value.trim();if(!/^\d+$/.test(value)||value==='0'){showDetails({error:'Enter a positive round ID.'});return;}loadRound(value);};
  $('loadRoundButton').addEventListener('click',loadRoundLookup);
  $('roundLookup').addEventListener('keydown',event=>{if(event.key==='Enter')loadRoundLookup();});

  let startupReady=false,startupMessages=[];
  function dispatchStreamMessage(kind,data){if(kind==='snapshot')applySnapshot(data);else if(kind==='update')applyUpdate(data);else applyState(data);}
  function drainStreamMessages(){if(!startupReady||model.storageSuspended)return;const messages=startupMessages;startupMessages=[];for(const [kind,data] of messages)dispatchStreamMessage(kind,data);}
  function receiveStreamMessage(kind,event){const data=JSON.parse(event.data);if(!startupReady||model.storageSuspended)startupMessages.push([kind,data]);else dispatchStreamMessage(kind,data);}
  async function startDashboard(){const stream=new EventSource('/api/stream');stream.onopen=()=>{const badge=$('browserBadge');badge.textContent='dashboard: live';badge.className='badge ok';};stream.addEventListener('snapshot',event=>receiveStreamMessage('snapshot',event));stream.addEventListener('update',event=>receiveStreamMessage('update',event));stream.addEventListener('state',event=>receiveStreamMessage('state',event));stream.onerror=()=>{const badge=$('browserBadge');badge.textContent='dashboard: reconnecting';badge.className='badge warn';};await restoreBrowserHistory();startupReady=true;drainStreamMessages();}
  function suspendBrowserStorage(){if(!model.browserDb||model.browserStorageStatus!=='ready')return;model.storageSuspended=true;if(storageLeaseTimer!==null){clearInterval(storageLeaseTimer);storageLeaseTimer=null;}if(storageFlushTimer!==null){clearTimeout(storageFlushTimer);storageFlushTimer=null;}flushBrowserStorage();releaseBrowserLease().catch(()=>{});setBrowserStorageStatus('opening','Browser history is suspended until this page regains its fenced writer lease');}
  async function resumeBrowserStorage(){if(!model.browserDb||model.browserStorageStatus==='error'){model.storageSuspended=false;drainStreamMessages();return;}try{await acquireBrowserLease(model.browserDb);setBrowserStorageStatus('ready',`IndexedDB keeps about ${nf.format(BROWSER_EVENT_LIMIT)} ordinary rows or ${compact(model.maxEventBytes)}B; selections and 201-row error windows are pinned`);storageLeaseTimer=setInterval(heartbeatBrowserLease,STORAGE_LEASE_HEARTBEAT_MS);model.storageSuspended=false;drainStreamMessages();if(pendingEventWrites.size||pendingEventDeletes.size||pendingSelectionWrites.size||positionsDirty||incidentStateDirty)scheduleStorageFlush(0);}catch(error){storageFailed(error);model.storageSuspended=false;drainStreamMessages();}}
  window.addEventListener('pagehide',suspendBrowserStorage);
  window.addEventListener('pageshow',event=>{if(event.persisted)resumeBrowserStorage();});
  startDashboard();
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
        parsed_path = urlsplit(self.path)
        path = parsed_path.path
        if path == "/":
            self._send_bytes(200, "text/html; charset=utf-8", HTML.encode("utf-8"), head_only)
        elif path == "/api/snapshot":
            self._send_json(200, self.state.snapshot(), head_only)
        elif path == "/api/round":
            values = parse_qs(parsed_path.query, keep_blank_values=True)
            raw_id = values.get("id", [""])[0]
            if not raw_id.isdigit() or not 1 <= int(raw_id) <= (1 << 63) - 1:
                self._send_json(400, {"error": "id must be a positive round integer"}, head_only)
                return
            detail = self.state.round_detail(int(raw_id))
            if detail is None:
                self._send_json(404, {"error": "round not found"}, head_only)
            else:
                self._send_json(200, detail, head_only)
        elif path == "/api/share":
            values = parse_qs(parsed_path.query, keep_blank_values=True)
            event_key = values.get("key", [""])[0]
            if (
                not event_key or len(event_key) > 256
                or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-" for char in event_key)
            ):
                self._send_json(400, {"error": "invalid share event key"}, head_only)
                return
            detail = self.state.share_detail(event_key)
            if detail is None:
                self._send_json(404, {"error": "retained share not found"}, head_only)
            else:
                self._send_json(200, detail, head_only)
        elif path == "/healthz":
            health = self.state.health()
            self._send_json(200, {"ok": True, "socket_connected": health["socket_connected"]}, head_only)
        elif path == "/readyz":
            health = self.state.health()
            ready = bool(
                health["socket_connected"]
                and health["reader_status"] == "connected"
                and health["coverage_complete"]
            )
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
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        self._write_sse_encoded(event, encoded, event_id)

    def _write_sse_encoded(self, event: str, encoded: bytes,
                           event_id: Optional[int] = None) -> None:
        if event_id is not None:
            self.wfile.write(f"id: {event_id}\n".encode("ascii"))
        self.wfile.write(f"event: {event}\n".encode("ascii"))
        self.wfile.write(b"data: " + encoded + b"\n\n")
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
                    event, event_id, encoded = subscriber.get_message(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if subscriber.closed.is_set():
                    break
                self._write_sse_encoded(event, encoded, event_id)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.close_connection = True
            self.state.unsubscribe(subscriber)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Serve a local web dashboard for the XMRig Proxy schema-v2/v3 Unix event stream."
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
    parser.add_argument("--wallet-rpc-url", metavar="URL", help="optional loopback monero-wallet-rpc endpoint, for example http://127.0.0.1:18082/json_rpc")
    parser.add_argument("--wallet-rpc-login", metavar="USER:PASS", help="Digest-auth login for --wallet-rpc-url")
    parser.add_argument("--wallet-rpc-interval", type=float, default=DEFAULT_WALLET_RPC_INTERVAL, metavar="SECONDS", help="wallet RPC polling interval (default: 20; minimum: 5)")
    parser.add_argument("--database", default=DEFAULT_DATABASE, metavar="FILE", help=f"persistent SQLite database (default: {DEFAULT_DATABASE})")
    parser.add_argument("--no-database", action="store_true", help="disable persistence and round history")
    parser.add_argument("--big-share-diff", type=int, default=DEFAULT_BIG_SHARE_DIFFICULTY, metavar="DIFF", help=f"persist every share at or above this difficulty (default: {DEFAULT_BIG_SHARE_DIFFICULTY})")
    parser.add_argument("--round-top-shares", type=int, default=DEFAULT_ROUND_TOP_SHARES, metavar="N", help=f"top accepted shares retained per round (default: {DEFAULT_ROUND_TOP_SHARES})")
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


def normalize_wallet_rpc_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("--wallet-rpc-url must use http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "--wallet-rpc-url cannot contain credentials, a query, or a fragment"
        )
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("--wallet-rpc-url must use a loopback host")
    if parsed.path not in {"", "/", "/json_rpc"}:
        raise ValueError("--wallet-rpc-url path must be /json_rpc")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid --wallet-rpc-url port: {exc}") from exc
    return f"{parsed.scheme}://{parsed.netloc}/json_rpc"


def parse_wallet_rpc_login(value: str) -> Tuple[str, str]:
    if ":" not in value:
        raise ValueError("--wallet-rpc-login must use USER:PASS")
    username, password = value.split(":", 1)
    if not username or not password:
        raise ValueError("--wallet-rpc-login requires a non-empty user and password")
    if len(value) > 4096 or any(ord(char) < 0x20 for char in value):
        raise ValueError("--wallet-rpc-login contains invalid characters")
    return username, password


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
    if bool(args.wallet_rpc_url) != bool(args.wallet_rpc_login):
        raise ValueError("--wallet-rpc-url and --wallet-rpc-login must be supplied together")
    if not math.isfinite(args.wallet_rpc_interval) or not 5.0 <= args.wallet_rpc_interval <= 3600.0:
        raise ValueError("--wallet-rpc-interval must be a finite number between 5 and 3600 seconds")
    if not 1 <= args.big_share_diff <= (1 << 64) - 1:
        raise ValueError("--big-share-diff must be between 1 and UINT64_MAX")
    if not 1 <= args.round_top_shares <= 10000:
        raise ValueError("--round-top-shares must be between 1 and 10000")
    if not args.no_database and not args.database:
        raise ValueError("--database cannot be empty unless --no-database is used")


def run(args: argparse.Namespace) -> int:
    validate_args(args)
    api_url = normalize_api_url(args.api_url) if args.api_url else ""
    api_token = load_api_token(args) if api_url else ""
    wallet_url = normalize_wallet_rpc_url(args.wallet_rpc_url) if args.wallet_rpc_url else ""
    wallet_login = parse_wallet_rpc_login(args.wallet_rpc_login) if wallet_url else ("", "")
    stop_event = threading.Event()
    store = None if args.no_database else SQLiteStore(
        args.database, args.big_share_diff, args.round_top_shares,
    )
    state = DashboardState(
        args.socket, args.max_events, args.top_shares,
        api_enabled=bool(api_url), api_interval=args.api_interval,
        wallet_enabled=bool(wallet_url), wallet_interval=args.wallet_rpc_interval,
        store=store,
    )
    reader = UnixEventReader(args.socket, state, stop_event, args.retry_cap)
    api_poller = ApiPoller(api_url, api_token, args.api_interval, state, stop_event) if api_url else None
    wallet_poller = WalletRpcPoller(
        wallet_url, wallet_login[0], wallet_login[1],
        args.wallet_rpc_interval, state, stop_event,
    ) if wallet_url else None
    server = DashboardHTTPServer(("127.0.0.1", args.port), state)

    print(f"XMRig event dashboard: http://127.0.0.1:{args.port}/", flush=True)
    print(f"Consuming Unix socket: {args.socket}", flush=True)
    if store is not None:
        print(f"Persisting statistics: {store.path}", flush=True)
    if api_url:
        print(f"Polling proxy API: {api_url} every {args.api_interval:g}s", flush=True)
    if wallet_url:
        print(f"Polling wallet RPC: {wallet_url} every {args.wallet_rpc_interval:g}s", flush=True)
    print("The HTTP listener is restricted to 127.0.0.1.", flush=True)

    if store is not None:
        store.start()
    reader.start()
    if api_poller:
        api_poller.start()
    if wallet_poller:
        wallet_poller.start()
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
        if wallet_poller:
            wallet_poller.join(timeout=3.0)
        state.shutdown()
        if store is not None:
            store.close()
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
