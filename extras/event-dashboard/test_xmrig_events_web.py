#!/usr/bin/env python3

import argparse
import ast
import csv
import http.client
import importlib.util
import io
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("xmrig_events_web.py")
SPEC = importlib.util.spec_from_file_location("xmrig_events_web", MODULE_PATH)
assert SPEC and SPEC.loader
events = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(events)


def csv_record(values):
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerow(values)
    return output.getvalue().encode("utf-8")


def row(**updates):
    value = {name: "" for name in events.HEADER}
    value.update({
        "schema_version": "2",
        "event_seq": "1",
        "time_utc": "2026-08-08T00:00:00.001Z",
        "event": "template_cached",
        "source_id": "1",
        "template_id": "1",
        "height": "42",
        "network_target_diff": "500000",
        "status": "updated",
    })
    value.update({key: str(item) for key, item in updates.items()})
    return value


def encoded(value):
    return csv_record([value[name] for name in events.HEADER])


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


class ParserTest(unittest.TestCase):
    def test_schema_has_exact_v2_shape(self):
        self.assertEqual(len(events.HEADER), 35)
        self.assertEqual(events.HEADER[10], "source_id")

    def test_header_matches_live_event_stream_producer(self):
        producer = MODULE_PATH.parents[2] / "src/proxy/live/LiveEventStream.cpp"
        source = producer.read_text(encoding="utf-8")
        block = re.search(r"static const std::string header =\s*(.*?);", source, re.S)
        self.assertIsNotNone(block)
        literals = re.findall(r'"(?:[^"\\]|\\.)*"', block.group(1))
        produced = "".join(ast.literal_eval(value) for value in literals)
        self.assertEqual(tuple(produced.rstrip("\n").split(",")), events.HEADER)

    def test_fragmented_records_parse(self):
        payload = csv_record(events.HEADER) + encoded(row())
        framer = events.FrameBuffer()
        records = []
        for byte in payload:
            records.extend(framer.feed(bytes([byte])))
        parser = events.RowParser()
        self.assertIsNone(parser.parse(records[0]))
        parsed = parser.parse(records[1])
        self.assertEqual(parsed["height"], "42")

    def test_empty_event_sequence_is_protocol_error(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER).rstrip(b"\n"))
        with self.assertRaises(events.ProtocolError):
            parser.parse(encoded(row(event_seq="")).rstrip(b"\n"))

    def test_quoted_unicode_worker(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER).rstrip(b"\n"))
        parsed = parser.parse(encoded(row(worker='東京, worker "A"')).rstrip(b"\n"))
        self.assertEqual(parsed["worker"], '東京, worker "A"')


class StateTest(unittest.TestCase):
    def state(self, limit=5, max_events=100):
        state = events.DashboardState("/tmp/events.sock", max_events, limit)
        state.begin_session()
        return state

    def test_coverage_is_unknown_until_first_clean_session(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        self.assertFalse(state.health()["coverage_complete"])
        state.begin_session()
        self.assertTrue(state.health()["coverage_complete"])

    def test_top_five_accepted_shares_include_exact_times(self):
        state = self.state()
        for sequence, difficulty in enumerate((10, 50, 20, 70, 30, 60), 1):
            state.ingest(row(
                event="share_result",
                event_seq=sequence,
                time_utc=f"2026-08-08T00:00:0{sequence}.000Z",
                share_id=sequence,
                share_diff=difficulty,
                miner_id=2,
                mapper_id=1,
                worker="worker-a",
                status="accepted_local",
            ))
        state.ingest(row(
            event="share_result", event_seq=7, share_id=7,
            share_diff=999, status="rejected_local",
        ))

        top = state.snapshot()["top_shares"]
        self.assertEqual([int(item["share_diff"]) for item in top], [70, 60, 50, 30, 20])
        self.assertEqual(top[0]["time_utc"], "2026-08-08T00:00:04.000Z")
        self.assertEqual(top[0]["miner_id"], "2")
        self.assertNotIn("_difficulty", top[0])

    def test_reused_share_id_after_reconnect_is_distinct(self):
        state = self.state()
        state.ingest(row(event="share_result", share_id=1, share_diff=100, status="accepted_local"))
        state.end_session("test disconnect")
        state.begin_session()
        state.ingest(row(event_seq=1, event="share_result", share_id=1, share_diff=999, status="accepted_local"))
        snapshot = state.snapshot()
        self.assertEqual([int(item["share_diff"]) for item in snapshot["top_shares"]], [999, 100])
        self.assertFalse(snapshot["health"]["coverage_complete"])

    def test_submit_row_inherits_share_identity(self):
        state = self.state()
        state.ingest(row(
            event="share_received", share_id=9, miner_id=7, mapper_id=3,
            worker="rental-a", job_id="abcd", status="received",
        ))
        state.ingest(row(
            event_seq=2, event="submit_block", share_id=9,
            miner_id="", mapper_id="", worker="", status="requested",
        ))
        last = state.snapshot()["events"][-1]
        self.assertEqual((last["miner_id"], last["mapper_id"], last["worker"]), ("7", "3", "rental-a"))

    def test_ring_is_bounded(self):
        state = self.state(max_events=3)
        for sequence in range(1, 8):
            state.ingest(row(event_seq=sequence))
        self.assertEqual(len(state.snapshot()["events"]), 3)

    def test_fake_socket_reader_covers_session_control(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        stop = events.threading.Event()
        reader = events.UnixEventReader("/tmp/events.sock", state, stop, 1.0)
        payload = csv_record(events.HEADER) + encoded(row())
        reader._read(FakeSocket([payload[:17], payload[17:61], payload[61:], b""]))
        snapshot = state.snapshot()
        self.assertEqual(snapshot["stats"]["templates"], 1)
        self.assertEqual(snapshot["events"][-2]["event"], "template_cached")

    def test_protocol_error_is_not_reported_healthy(self):
        state = self.state()
        state.protocol_error("bad row")
        health = state.snapshot()["health"]
        self.assertTrue(health["socket_connected"])
        self.assertEqual(health["reader_status"], "degraded")
        self.assertFalse(health["coverage_complete"])

    def test_full_browser_queue_closes_subscriber(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        subscriber, _ = state.subscribe()
        subscriber.messages = queue.Queue(maxsize=1)
        state.waiting("first notice")
        state.waiting("second notice")
        self.assertTrue(subscriber.closed.is_set())
        self.assertNotIn(subscriber, state._subscribers)

    def test_high_rate_event_updates_do_not_repeat_api_worker_arrays(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5, api_enabled=True)
        state.begin_session()
        state.update_api({"hashrate": {"total": [1]}}, {"workers": []})
        subscriber, snapshot = state.subscribe()
        self.assertIn("api", snapshot)
        state.ingest(row())
        update = subscriber.messages.get_nowait()
        self.assertEqual(update["kind"], "update")
        self.assertNotIn("api", update)
        state.unsubscribe(subscriber)


class ApiTest(unittest.TestCase):
    def test_summary_and_workers_are_allowlisted(self):
        summary = events.sanitize_api_summary({
            "id": "proxy", "version": "6.26.0", "mode": "simple", "uptime": 65,
            "hashrate": {"total": [1.5, 2.5, 3.5]},
            "miners": {"now": 2, "max": 3}, "workers": 1,
            "upstreams": {"active": 2, "total": 2, "ratio": 1.0},
            "results": {"accepted": 4, "rejected": 1, "invalid": 2, "hashes_total": 999},
            "resources": {"memory": {"resident_set_memory": 1234}, "load_average": [0.1]},
            "password": "must-not-leak",
        })
        workers = events.sanitize_api_workers({
            "workers": [["rig-a", "203.0.113.1", 2, 3, 1, 0, 50000, 123, 1, 2, 3, 4, 5]],
            "password": "must-not-leak",
        })
        encoded_snapshot = events.json.dumps({"summary": summary, "workers": workers})
        self.assertNotIn("must-not-leak", encoded_snapshot)
        self.assertNotIn("203.0.113.1", encoded_snapshot)
        self.assertEqual(summary["hashrate"], [1.5, 2.5, 3.5])
        self.assertEqual(workers[0]["hashrate"], [1.0, 2.0, 3.0, 4.0, 5.0])

    def test_password_worker_mode_is_redacted(self):
        workers = events.sanitize_api_workers({
            "mode": "password",
            "workers": [["actual-password", "127.0.0.1", 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
        })
        self.assertEqual(workers[0]["name"], "[password worker hidden]")
        self.assertNotIn("actual-password", events.json.dumps(workers))

    def test_state_never_contains_api_token(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5, api_enabled=True)
        subscriber, _ = state.subscribe()
        state.update_api(
            {"hashrate": {"total": [1]}, "access-token": "TOKEN-SECRET"},
            {"workers": [], "password": "TOKEN-SECRET"},
        )
        self.assertNotIn("TOKEN-SECRET", events.json.dumps(state.snapshot()))
        self.assertEqual(subscriber.messages.get_nowait()["kind"], "state")
        state.unsubscribe(subscriber)

    def test_api_url_must_be_loopback(self):
        self.assertEqual(
            events.normalize_api_url("http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080",
        )
        with self.assertRaises(ValueError):
            events.normalize_api_url("http://example.com:8080")

    def test_mode_0600_token_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "token")
            Path(path).write_text("secret-token\n", encoding="utf-8")
            os.chmod(path, 0o600)
            args = argparse.Namespace(api_token_file=path, api_token_env="IGNORED")
            self.assertEqual(events.load_api_token(args), "secret-token")

    def test_token_file_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "target")
            link = os.path.join(directory, "link")
            Path(target).write_text("secret-token\n", encoding="utf-8")
            os.chmod(target, 0o600)
            os.symlink(target, link)
            args = argparse.Namespace(api_token_file=link, api_token_env="IGNORED")
            with self.assertRaises(OSError):
                events.load_api_token(args)

    def test_token_file_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "token-fifo")
            os.mkfifo(path, 0o600)
            args = argparse.Namespace(api_token_file=path, api_token_env="IGNORED")
            with self.assertRaises(ValueError):
                events.load_api_token(args)


class PageTest(unittest.TestCase):
    def setUp(self):
        self.state = events.DashboardState("/tmp/events.sock", 100, 5)
        self.server = events.DashboardHTTPServer(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.state.shutdown()

    def request(self, path, host=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        headers = {"Host": host} if host else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), body
        connection.close()
        return result

    def test_page_has_dashboard_sections_and_unique_ids(self):
        for text in (
            "Top 5 observed accepted shares", "Live event timeline",
            "XMRig Proxy HTTP API", "apiWorkersBody", "Hashrate 1m",
        ):
            self.assertIn(text, events.HTML)
        ids = re.findall(r'id="([^"]+)"', events.HTML)
        self.assertEqual(len(ids), len(set(ids)))

    def test_loopback_request_authorities(self):
        allowed = events.DashboardHandler._loopback_authority
        self.assertTrue(allowed("127.0.0.1:8787", False))
        self.assertTrue(allowed("http://localhost:8787", True))
        self.assertFalse(allowed("evil.example:8787", False))
        self.assertFalse(allowed("https://evil.example", True))

    def test_browser_subscriber_count_is_bounded(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        subscribers = [state.subscribe()[0] for _ in range(events.MAX_BROWSER_SUBSCRIBERS)]
        with self.assertRaises(events.SubscriberLimitError):
            state.subscribe()
        for subscriber in subscribers:
            state.unsubscribe(subscriber)

    def test_http_snapshot_security_and_host_validation(self):
        status, headers, body = self.request("/api/snapshot")
        self.assertEqual(status, 200)
        self.assertEqual(events.json.loads(body)["kind"], "snapshot")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

        status, _, body = self.request("/api/snapshot", "evil.example")
        self.assertEqual(status, 421)
        self.assertIn("loopback", events.json.loads(body)["error"])

    def test_health_is_liveness_and_ready_requires_clean_socket(self):
        status, _, body = self.request("/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(events.json.loads(body)["ok"])

        status, _, body = self.request("/readyz")
        self.assertEqual(status, 503)
        self.assertFalse(events.json.loads(body)["ready"])

        self.state.begin_session()
        status, _, body = self.request("/readyz")
        self.assertEqual(status, 200)
        self.assertTrue(events.json.loads(body)["ready"])

        self.state.protocol_error("malformed record")
        status, _, body = self.request("/readyz")
        self.assertEqual(status, 503)
        self.assertFalse(events.json.loads(body)["ready"])

    @unittest.skipUnless(shutil.which("node"), "node is unavailable")
    def test_browser_time_formatter_includes_date_time_and_milliseconds(self):
        helper = re.search(r"  const time = (.*?);\n", events.HTML)
        self.assertIsNotNone(helper)
        script = (
            "const time = " + helper.group(1) + ";\n"
            "console.log(time('2026-08-08T00:00:04.123Z'));\n"
        )
        output = subprocess.check_output(["node", "-e", script], text=True).strip()
        self.assertIn("2026", output)
        self.assertIn("04", output)
        self.assertIn("123", output)


if __name__ == "__main__":
    unittest.main()
