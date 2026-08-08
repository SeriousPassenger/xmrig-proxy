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
import time
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


def encoded(value, header=None):
    selected = header or events.HEADER
    return csv_record([value[name] for name in selected])


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""


class ParserTest(unittest.TestCase):
    def test_schema_v3_is_an_append_only_extension_of_v2(self):
        self.assertEqual(len(events.HEADER_V2), 35)
        self.assertEqual(events.HEADER_V2[10], "source_id")
        self.assertEqual(events.HEADER[:len(events.HEADER_V2)], events.HEADER_V2)
        self.assertEqual(events.HEADER[len(events.HEADER_V2)], "stream_id")
        self.assertNotIn("signature_data_hex", events.HEADER)

    def test_header_matches_live_event_stream_producer(self):
        producer = MODULE_PATH.parents[2] / "src/proxy/live/LiveEventStream.cpp"
        source = producer.read_text(encoding="utf-8")
        block = re.search(r"static const std::string header =\s*(.*?);", source, re.S)
        self.assertIsNotNone(block)
        literals = re.findall(r'"(?:[^"\\]|\\.)*"', block.group(1))
        produced = "".join(ast.literal_eval(value) for value in literals)
        self.assertEqual(tuple(produced.rstrip("\n").split(",")), events.HEADER)

    def test_fragmented_records_parse(self):
        payload = csv_record(events.HEADER) + encoded(row(schema_version=3, stream_id="a" * 32))
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
            parser.parse(encoded(row(schema_version=3, stream_id="a" * 32, event_seq="")).rstrip(b"\n"))

    def test_quoted_unicode_worker(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER).rstrip(b"\n"))
        parsed = parser.parse(encoded(row(schema_version=3, stream_id="a" * 32, worker='東京, worker "A"')).rstrip(b"\n"))
        self.assertEqual(parsed["worker"], '東京, worker "A"')

    def test_v2_capture_is_upconverted_with_empty_v3_fields(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER_V2).rstrip(b"\n"))
        parsed = parser.parse(encoded(row(), events.HEADER_V2).rstrip(b"\n"))
        self.assertEqual(parsed["schema_version"], "2")
        self.assertEqual(parsed["stream_id"], "")

    def test_v3_accepts_decimal_verifier_timings_and_nested_stats(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER).rstrip(b"\n"))
        parsed = parser.parse(encoded(row(
            schema_version=3, stream_id="a" * 32,
            verifier_queue_ms="1.25", verifier_hash_ms="2.75",
            verifier_stats_json='{"scheduler":{"active":1}}',
        )).rstrip(b"\n"))
        self.assertEqual(parsed["verifier_hash_ms"], "2.75")

    def test_v3_rejects_missing_stream_identity(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER).rstrip(b"\n"))
        with self.assertRaises(events.ProtocolError):
            parser.parse(encoded(row(schema_version=3)).rstrip(b"\n"))

    def test_frame_limit_matches_producer_client_budget(self):
        self.assertEqual(events.MAX_LINE_BYTES, 8 * 1024 * 1024)
        exact = b"x" * events.MAX_LINE_BYTES
        self.assertEqual(events.FrameBuffer().feed(exact + b"\n"), [exact])
        framer = events.FrameBuffer(limit=32)
        self.assertEqual(framer.feed(b"x" * 32 + b"\n"), [b"x" * 32])
        with self.assertRaises(events.ProtocolError):
            framer.feed(b"x" * 33)

    def test_difficulty_fields_must_fit_uint64(self):
        parser = events.RowParser()
        parser.parse(csv_record(events.HEADER).rstrip(b"\n"))
        with self.assertRaisesRegex(events.ProtocolError, "unsigned 64-bit"):
            parser.parse(encoded(row(
                schema_version=3, stream_id="a" * 32,
                share_diff=(1 << 64),
            )).rstrip(b"\n"))


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

    def test_no_database_state_is_explicitly_disabled(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        persistence = state.snapshot()["persistence"]
        self.assertFalse(persistence["enabled"])
        self.assertEqual(persistence["status"], "disabled")

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

    def test_live_ring_omits_blobs_and_is_byte_bounded(self):
        state = events.DashboardState(
            "/tmp/events.sock", 100, 5,
            live_byte_limit=events.MAX_LIVE_ROW_BYTES * 2,
        )
        state.begin_session()
        for sequence in range(1, 40):
            state.ingest(row(
                event_seq=sequence,
                blocktemplate_blob="ab" * 100_000,
                error_message="x" * 10_000,
            ))
        snapshot = state.snapshot()
        self.assertLess(len(snapshot["events"]), 40)
        self.assertLessEqual(snapshot["live_event_bytes"], snapshot["live_event_byte_limit"])
        last = snapshot["events"][-1]
        self.assertEqual(last["blocktemplate_blob"], "")
        self.assertEqual(last["_omitted_live_fields"]["blocktemplate_blob"]["decoded_bytes"], 100_000)
        self.assertEqual(last["_truncated_live_fields"]["error_message"], 10_000)
        self.assertEqual(
            snapshot["live_event_bytes"],
            sum(len(events.json.dumps(
                item, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")) for item in snapshot["events"]),
        )

    def test_first_observed_event_above_one_degrades_live_coverage(self):
        state = self.state()
        state.ingest(row(
            schema_version=3, stream_id="a" * 32, event_seq=7,
        ))
        snapshot = state.snapshot()
        self.assertFalse(snapshot["health"]["coverage_complete"])
        self.assertEqual(snapshot["events"][-2]["event"], "viewer_sequence_gap")
        self.assertIn("first observed 7", snapshot["events"][-2]["error_message"])

    def test_fake_socket_reader_covers_session_control(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        stop = events.threading.Event()
        reader = events.UnixEventReader("/tmp/events.sock", state, stop, 1.0)
        payload = csv_record(events.HEADER) + encoded(row(schema_version=3, stream_id="a" * 32))
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

    def test_browser_queue_is_bounded_by_serialized_bytes(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5)
        subscriber, _ = state.subscribe()
        subscriber.byte_limit = 1024
        with state._lock:
            state._broadcast_locked({"kind": "state", "payload": "x" * 700})
            state._broadcast_locked({"kind": "state", "payload": "y" * 700})
        self.assertTrue(subscriber.closed.is_set())
        self.assertNotIn(subscriber, state._subscribers)
        self.assertLessEqual(subscriber.queued_bytes, subscriber.byte_limit)

    def test_high_rate_event_updates_do_not_repeat_api_worker_arrays(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5, api_enabled=True)
        state.begin_session()
        state.update_api({"hashrate": {"total": [1]}}, {"workers": []})
        subscriber, snapshot = state.subscribe()
        self.assertIn("api", snapshot)
        state.ingest(row())
        update = subscriber.get_nowait()
        self.assertEqual(update["kind"], "update")
        self.assertNotIn("api", update)
        state.unsubscribe(subscriber)


class SQLiteStoreTest(unittest.TestCase):
    def make_store(self, directory, **kwargs):
        store = events.SQLiteStore(str(Path(directory) / "events.sqlite3"), **kwargs)
        store.start()
        return store

    @staticmethod
    def event(sequence, **updates):
        return row(
            schema_version=3,
            stream_id="0123456789abcdef0123456789abcdef",
            event_seq=sequence,
            **updates,
        )

    def test_failed_schema_step_rolls_back_all_ddl(self):
        db = events.sqlite3.connect(":memory:")
        try:
            with self.assertRaises(events.sqlite3.OperationalError):
                events.SQLiteStore._apply_migration(db, """
                    CREATE TABLE must_not_survive(id INTEGER);
                    INSERT INTO missing_table VALUES(1);
                    PRAGMA user_version=99;
                """)
            self.assertIsNone(db.execute(
                "SELECT name FROM sqlite_master WHERE name='must_not_survive'"
            ).fetchone())
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 0)
        finally:
            db.close()

    def test_exact_once_credited_work_uses_assigned_target(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            accepted = self.event(
                1, event="share_result", status="accepted_local", share_id=1,
                miner_target_diff=4_194_304, share_diff=20_000_000_001,
                network_target_diff=600_000_000_000,
            )
            store.enqueue_event(accepted, 1)
            store.enqueue_event(accepted, 1)
            store.close()
            snapshot = store.snapshot()
            current = snapshot["current_round"]
            self.assertEqual(current["credited_hashes"], "4194304")
            self.assertEqual(current["observed_diff_sum"], "20000000001")
            self.assertEqual(current["accepted_shares"], 1)
            self.assertEqual(snapshot["big_share_count"], 1)

    def test_uint64_share_rank_is_exact_and_round_closes_after_winner_credit(self):
        maximum = (1 << 64) - 1
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory, big_share_difficulty=1, round_top_limit=1000)
            store.enqueue_event(self.event(
                1, event="share_result", status="accepted_local", share_id=1,
                miner_target_diff=100, share_diff=maximum - 1,
                network_target_diff=1000,
            ), 1)
            common = dict(
                source_id=1, daemon_request_id=9, share_id=2, job_id="job",
                height=99, share_diff=maximum, network_target_diff=1000,
            )
            store.enqueue_event(self.event(2, event="submit_block", status="requested", **common), 1)
            store.enqueue_event(self.event(3, event="submit_block_result", status="accepted", block_id="b" * 64, **common), 1)
            store.enqueue_event(self.event(
                4, event="share_result", status="accepted_upstream",
                miner_target_diff=100, **common,
            ), 1)
            store.close()
            snapshot = store.snapshot()
            self.assertEqual(len(snapshot["recent_rounds"]), 1)
            closed = snapshot["recent_rounds"][0]
            self.assertEqual(closed["accepted_shares"], 2)
            self.assertEqual(closed["credited_hashes"], "200")
            detail = store.round_detail(closed["id"])
            self.assertIsNotNone(detail)
            self.assertEqual(detail["top_shares"][0]["share_diff"], str(maximum))
            self.assertEqual(detail["blocks"][0]["block_id"], "b" * 64)

    def test_api_worker_counter_starts_at_zero_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            first_workers = {"mode": "rig_id", "workers": [["w", "hidden", 1, 0, 0, 0, 1_000, 0, 0, 0, 0, 0, 0]]}
            second_workers = {"mode": "rig_id", "workers": [["w", "hidden", 1, 0, 0, 0, 1_600, 0, 0, 0, 0, 0, 0]]}
            store.enqueue_api({"uptime": 100}, first_workers)
            store.enqueue_api({"uptime": 101}, second_workers)
            store.close()
            cumulative = store.snapshot()["cumulative"]
            self.assertEqual(cumulative["api_worker_hashes"], "600")
            self.assertTrue(cumulative["api_baseline_set"])

    def test_api_ledger_sums_workers_beyond_browser_display_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            first_rows = [
                [f"w-{index}", "hidden", 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]
                for index in range(10_001)
            ]
            second_rows = [list(row) for row in first_rows]
            second_rows[-1][6] = 6
            store.enqueue_api({"uptime": 100}, {"mode": "rig_id", "workers": first_rows})
            store.enqueue_api({"uptime": 101}, {"mode": "rig_id", "workers": second_rows})
            store.close()
            cumulative = store.snapshot()["cumulative"]
            self.assertEqual(cumulative["api_worker_hashes"], "5")
            self.assertTrue(cumulative["api_coverage_complete"])
            self.assertEqual(len(events.sanitize_api_workers({
                "mode": "rig_id", "workers": second_rows,
            })), 10_000)

    def test_disabled_or_unknown_worker_mode_marks_api_coverage_incomplete(self):
        for mode in ("none", "", "unexpected"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                store = self.make_store(directory)
                store.enqueue_api({"uptime": 100}, {"mode": mode, "workers": []})
                store.close()
                cumulative = store.snapshot()["cumulative"]
                self.assertFalse(cumulative["api_coverage_complete"])
                self.assertFalse(cumulative["api_baseline_set"])
                self.assertTrue(cumulative["api_coverage_reason"])

    def test_stream_identity_deduplicates_across_dashboard_restart_and_marks_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_store(directory)
            accepted = self.event(
                1, event="share_result", status="accepted_local", share_id=1,
                miner_target_diff=100, share_diff=1000, network_target_diff=10000,
            )
            first.enqueue_event(accepted, 1)
            first.close()

            second = self.make_store(directory)
            second.enqueue_event(accepted, 1)  # durable duplicate
            second.enqueue_event(self.event(
                3, event="share_result", status="accepted_local", share_id=2,
                miner_target_diff=100, share_diff=2000, network_target_diff=10000,
            ), 1)
            second.close()
            snapshot = second.snapshot()
            self.assertEqual(snapshot["cumulative"]["credited_hashes_events"], "200")
            self.assertFalse(snapshot["coverage_complete"])
            self.assertIn("sequence gap", snapshot["coverage_reason"])

    def test_first_observed_sequence_above_one_is_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            store.enqueue_event(self.event(
                7, event="share_result", status="accepted_local", share_id=1,
                miner_target_diff=100, share_diff=1000, network_target_diff=10000,
            ), 1)
            store.close()
            snapshot = store.snapshot()
            self.assertFalse(snapshot["coverage_complete"])
            self.assertIn("first observed 7", snapshot["coverage_reason"])

    def test_dashboard_process_restart_is_incomplete_even_if_sequence_is_contiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_store(directory)
            first.enqueue_event(self.event(
                1, event="share_result", status="accepted_local", share_id=1,
                miner_target_diff=100, share_diff=1000, network_target_diff=10000,
            ), 1)
            first.close()

            second = self.make_store(directory)
            second.enqueue_event(self.event(
                2, event="share_result", status="accepted_local", share_id=2,
                miner_target_diff=100, share_diff=2000, network_target_diff=10000,
            ), 1)
            second.close()
            snapshot = second.snapshot()
            self.assertFalse(snapshot["coverage_complete"])
            self.assertIn("dashboard process restarted", snapshot["coverage_reason"])

    def test_api_restart_adds_new_epoch_and_ambiguous_decrease_never_double_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            worker = lambda hashes: {
                "mode": "rig_id",
                "workers": [["w", "hidden", 1, 0, 0, 0, hashes, 0, 0, 0, 0, 0, 0]],
            }
            store.enqueue_api({"uptime": 100}, worker(1_000))  # baseline only
            store.enqueue_api({"uptime": 101}, worker(1_500))  # +500
            store.enqueue_api({"uptime": 1}, worker(200))      # restart: +200
            store.enqueue_api({"uptime": 2}, worker(100))      # ambiguous: +0
            store.close()
            cumulative = store.snapshot()["cumulative"]
            self.assertEqual(cumulative["api_worker_hashes"], "700")
            self.assertFalse(cumulative["api_coverage_complete"])

    def test_api_restart_alone_marks_sampled_ledger_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            worker = lambda hashes: {
                "mode": "rig_id",
                "workers": [["w", "hidden", 1, 0, 0, 0, hashes, 0, 0, 0, 0, 0, 0]],
            }
            store.enqueue_api({"uptime": 100}, worker(1_000))
            store.enqueue_api({"uptime": 1}, worker(200))
            store.close()
            cumulative = store.snapshot()["cumulative"]
            self.assertEqual(cumulative["api_worker_hashes"], "200")
            self.assertFalse(cumulative["api_coverage_complete"])
            self.assertIn("previous epoch tail", cumulative["api_coverage_reason"])

    def test_newer_database_schema_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "future.sqlite3"
            db = events.sqlite3.connect(path)
            db.execute("PRAGMA user_version=999")
            db.close()
            with self.assertRaises(ValueError):
                events.SQLiteStore(str(path))

    def test_schema_five_migrates_verifier_metric_sample_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite3"
            original = events.SQLiteStore(str(path))
            db = original._connect()
            try:
                with db:
                    db.executescript("""
                        ALTER TABLE verifier_totals RENAME TO verifier_totals_v6;
                        CREATE TABLE verifier_totals (
                            id INTEGER PRIMARY KEY CHECK (id = 1),
                            requests INTEGER NOT NULL DEFAULT 0,
                            results INTEGER NOT NULL DEFAULT 0,
                            mismatches INTEGER NOT NULL DEFAULT 0,
                            errors INTEGER NOT NULL DEFAULT 0,
                            queue_ms TEXT NOT NULL DEFAULT '0',
                            hash_ms TEXT NOT NULL DEFAULT '0',
                            total_ms TEXT NOT NULL DEFAULT '0',
                            last_event_utc TEXT NOT NULL DEFAULT '',
                            last_status_json TEXT NOT NULL DEFAULT '{}'
                        );
                        INSERT INTO verifier_totals(
                            id,requests,results,mismatches,errors,queue_ms,hash_ms,total_ms,
                            last_event_utc,last_status_json
                        ) SELECT id,requests,results,mismatches,errors,queue_ms,hash_ms,total_ms,
                            last_event_utc,last_status_json FROM verifier_totals_v6;
                        UPDATE verifier_totals SET results=2,queue_ms='2',hash_ms='4',total_ms='6';
                        DROP TABLE verifier_totals_v6;
                        PRAGMA user_version=5;
                    """)
            finally:
                db.close()
            migrated = events.SQLiteStore(str(path))
            db = migrated._read_connect()
            try:
                self.assertEqual(
                    db.execute("PRAGMA user_version").fetchone()[0],
                    events.SQLiteStore.SCHEMA_VERSION,
                )
                columns = {item[1] for item in db.execute("PRAGMA table_info(verifier_totals)")}
                self.assertTrue({"queue_samples", "hash_samples", "total_samples"} <= columns)
                samples = db.execute(
                    "SELECT queue_samples,hash_samples,total_samples FROM verifier_totals"
                ).fetchone()
                self.assertEqual(tuple(samples), (2, 2, 2))
            finally:
                db.close()

    def test_context_budget_queries_use_retention_covering_indexes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            store.close()
            db = store._read_connect()
            try:
                for table, index in (
                    ("job_contexts", "job_contexts_retained_budget"),
                    ("template_contexts", "template_contexts_retained_budget"),
                ):
                    plan = " ".join(
                        str(field)
                        for row_value in db.execute(
                            f"EXPLAIN QUERY PLAN SELECT count(*),coalesce(sum(size_bytes),0) "
                            f"FROM {table} WHERE retained=0"
                        ).fetchall()
                        for field in row_value
                    )
                    self.assertIn(index, plan)
            finally:
                db.close()

    def test_decimal_verifier_metrics_and_seed_status_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            store.enqueue_event(self.event(1, event="verify_requested", status="requested"), 1)
            store.enqueue_event(self.event(
                2, event="verify_result", status="accepted_local",
                verifier_queue_ms="1.25", verifier_hash_ms="2.50", verifier_total_ms="3.75",
            ), 1)
            store.enqueue_event(self.event(
                3, event="verifier_status", status="healthy", seed_hash="a" * 64,
                previous_seed_hash="b" * 64, next_seed_hash="c" * 64,
                verifier_active=1, verifier_queued=2, verifier_queue_limit=256,
                verifier_seed_count=3, verifier_seed_capacity=3, verifier_vm_pool_size=4,
                verifier_stats_json='{"service":{"healthy":true}}',
            ), 1)
            # Admission failures have no timing sample and must not dilute the
            # measured latency average with a fabricated zero.
            store.enqueue_event(self.event(
                4, event="verify_error", status="unavailable",
            ), 1)
            store.close()
            verifier = store.snapshot()["verifier"]
            self.assertEqual(verifier["requests"], 1)
            self.assertEqual(verifier["results"], 2)
            self.assertEqual(verifier["errors"], 1)
            self.assertEqual(verifier["hash_samples"], 1)
            self.assertEqual(verifier["average_hash_ms"], 2.5)
            self.assertEqual(verifier["status"]["vm_pool_size"], 4)
            self.assertEqual(verifier["status"]["current_seed_hash"], "a" * 64)

    def test_seed_roles_do_not_claim_readiness_without_a_ready_event(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            seed = "a" * 64
            store.enqueue_event(self.event(
                1, event="verifier_seed_roles", status="observed", seed_hash=seed,
            ), 1)
            store.close()
            seeds = store.snapshot()["verifier"]["seeds"]
            self.assertEqual(seeds[0]["role"], "current")
            self.assertEqual(seeds[0]["status"], "observed")

    def test_service_status_does_not_overwrite_seed_lifecycle_status(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            seed = "a" * 64
            store.enqueue_event(self.event(
                1, event="verifier_seed_ready", status="ready", seed_hash=seed,
                verifier_seed_role="current", verifier_seed_status="ready",
            ), 1)
            store.enqueue_event(self.event(
                2, event="verifier_status", status="healthy", seed_hash=seed,
            ), 1)
            store.close()
            self.assertEqual(store.snapshot()["verifier"]["seeds"][0]["status"], "ready")

    def test_service_status_populates_seed_roles_on_cold_attach(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            previous = "a" * 64
            current = "b" * 64
            following = "c" * 64
            store.enqueue_event(self.event(
                1, event="verifier_status", status="healthy",
                previous_seed_hash=previous, seed_hash=current,
                next_seed_hash=following,
            ), 1)
            store.close()
            seeds = {
                item["role"]: (item["seed_hash"], item["status"])
                for item in store.snapshot()["verifier"]["seeds"]
            }
            self.assertEqual(seeds, {
                "previous": (previous, "observed"),
                "current": (current, "observed"),
                "next": (following, "observed"),
            })

    def test_socket_disconnect_marks_persistent_round_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            state = events.DashboardState("/tmp/events.sock", 100, 5, store=store)
            state.begin_session()
            state.end_session("test disconnect; no replay")
            store.close()
            snapshot = store.snapshot()
            self.assertFalse(snapshot["coverage_complete"])
            self.assertIn("no replay", snapshot["coverage_reason"])

    def test_fatal_reader_failure_marks_persistent_round_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            state = events.DashboardState("/tmp/events.sock", 100, 5, store=store)
            state.begin_session()
            state.fatal("event path is not a Unix socket")
            store.close()
            state.shutdown()
            snapshot = store.snapshot()
            self.assertFalse(snapshot["coverage_complete"])
            self.assertIn("not a Unix socket", snapshot["coverage_reason"])

    def test_group_writable_database_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "unsafe"
            parent.mkdir(mode=0o770)
            os.chmod(parent, 0o770)
            with self.assertRaisesRegex(ValueError, "writable by group/others"):
                events.SQLiteStore(str(parent / "events.sqlite3"))

    def test_retained_share_embeds_reconstruction_job_context(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            state = events.DashboardState("/tmp/events.sock", 100, 5, store=store)
            state.begin_session()
            template = dict(source_id=1, template_id=2, height=99)
            state.ingest(self.event(
                1, event="template_cached", status="updated",
                blocktemplate_blob="aa", hashing_blob="bb",
                reserved_offset=100, reserved_size=16, **template,
            ))
            state.ingest(self.event(
                2, event="template_derived", status="derived", hashing_blob="cc",
                entropy_hex="66" * 16, job_id="job-a", **template,
            ))
            state.ingest(self.event(
                3, event="job_sent", status="sent", hashing_blob="dd",
                miner_target_hex="ee", job_id="job-a", seed_hash="11" * 32,
                prev_hash="22" * 32, algo="rx/0", nonce_offset=39,
                nonce_size=4, **template,
            ))
            state.ingest(self.event(
                4, event="share_received", status="received", share_id=7,
                miner_target_diff=100, share_diff=900, network_target_diff=10000,
                job_id="job-a", nonce="01020304", result_hash="33" * 32,
                signature_hex="44" * 64, algo="rx/0", seed_hash="11" * 32,
                prev_hash="22" * 32, view_tag=5, extra_nonce=6, **template,
            ))
            state.ingest(self.event(
                5, event="verify_result", status="accepted_local", share_id=7,
                miner_target_diff=100, share_diff=1000, network_target_diff=10000,
                job_id="job-a", result_hash="55" * 32, verifier_queue_ms="1.2",
                verifier_hash_ms="2.3", verifier_total_ms="3.5", **template,
            ))
            state.ingest(self.event(
                6, event="share_result", status="accepted_local", share_id=7,
                miner_target_diff=100, share_diff=1000, network_target_diff=10000,
                job_id="job-a", **template,
            ))
            store.close()
            state.shutdown()
            round_id = store.snapshot()["current_round"]["id"]
            detail = store.round_detail(round_id)
            audit = store.share_detail(detail["top_shares"][0]["event_key"])
            self.assertTrue(audit["audit_context_complete"])
            self.assertEqual(audit["audit_context_missing"], [])
            self.assertEqual(audit["template_context"]["blocktemplate_blob"], "aa")
            self.assertEqual(audit["job_context"]["template_derived"]["hashing_blob"], "cc")
            self.assertEqual(audit["job_context"]["job_sent"]["hashing_blob"], "dd")
            self.assertEqual(audit["share"]["nonce"], "01020304")
            self.assertEqual(audit["share"]["result_hash"], "55" * 32)
            self.assertEqual(audit["share"]["signature_hex"], "44" * 64)
            self.assertEqual(audit["share"]["_claimed_result_hash"], "33" * 32)
            self.assertEqual(audit["share"]["_computed_result_hash"], "55" * 32)
            self.assertEqual(audit["share"]["_difficulty_source"], "verifier_computed")
            self.assertEqual(audit["share"]["_verifier_total_ms"], "3.5")

    def test_reused_job_id_keeps_immutable_per_miner_audit_context(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                directory, big_share_difficulty=1_000_000, round_top_limit=2,
            )
            state = events.DashboardState("/tmp/events.sock", 100, 5, store=store)
            state.begin_session()
            common = dict(source_id=1, template_id=2, height=99, job_id="shared-job")
            state.ingest(self.event(
                1, event="template_cached", status="updated", blocktemplate_blob="base",
                reserved_offset=100, reserved_size=16,
                source_id=1, template_id=2, height=99,
            ))
            state.ingest(self.event(
                2, event="template_derived", status="derived", hashing_blob="derived",
                entropy_hex="66" * 16, **common,
            ))

            sequence = 3
            for miner_id, mapper_id, share_id, sent_blob, target, difficulty in (
                (11, 21, 31, "miner-one-blob", "target-one", 1000),
                (12, 22, 32, "miner-two-blob", "target-two", 2000),
            ):
                identity = dict(miner_id=miner_id, mapper_id=mapper_id)
                state.ingest(self.event(
                    sequence, event="job_sent", status="sent", hashing_blob=sent_blob,
                    miner_target_hex=target, seed_hash="11" * 32, algo="rx/0",
                    nonce_offset=39, nonce_size=4, **identity, **common,
                ))
                sequence += 1
                state.ingest(self.event(
                    sequence, event="share_received", status="received", share_id=share_id,
                    nonce=f"{share_id:08x}", result_hash="33" * 32,
                    miner_target_diff=100, share_diff=difficulty,
                    network_target_diff=10000, **identity, **common,
                ))
                sequence += 1
                state.ingest(self.event(
                    sequence, event="verify_result", status="accepted_local", share_id=share_id,
                    result_hash="44" * 32, miner_target_diff=100,
                    share_diff=difficulty, network_target_diff=10000,
                    **identity, **common,
                ))
                sequence += 1
                state.ingest(self.event(
                    sequence, event="share_result", status="accepted_local", share_id=share_id,
                    miner_target_diff=100, share_diff=difficulty,
                    network_target_diff=10000, **identity, **common,
                ))
                sequence += 1

            store.close()
            state.shutdown()
            detail = store.round_detail(store.snapshot()["current_round"]["id"])
            audits = {
                item["share_id"]: store.share_detail(item["event_key"])
                for item in detail["top_shares"]
            }
            self.assertEqual(
                audits["31"]["job_context"]["job_sent"]["hashing_blob"],
                "miner-one-blob",
            )
            self.assertEqual(
                audits["31"]["job_context"]["job_sent"]["miner_target_hex"],
                "target-one",
            )
            self.assertEqual(
                audits["32"]["job_context"]["job_sent"]["hashing_blob"],
                "miner-two-blob",
            )
            self.assertEqual(
                audits["32"]["job_context"]["job_sent"]["miner_target_hex"],
                "target-two",
            )

    def test_retry_attempts_correlate_without_stable_daemon_request_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(directory)
            common = dict(
                source_id=1, template_id=2, share_id=7, job_id="job-a",
                height=99, share_diff=5000, network_target_diff=10000,
            )
            for sequence, event, request_id in (
                (1, "submit_block", 10),
                (2, "submit_block_attempt", 10),
                (3, "submit_block_retry", 11),
                (4, "submit_block_reconcile", 12),
            ):
                store.enqueue_event(self.event(
                    sequence, event=event, daemon_request_id=request_id,
                    status="requested", submitted_block_blob="aa", **common,
                ), 1)
            store.enqueue_event(self.event(
                5, event="submit_block_result", daemon_request_id=12,
                status="accepted", block_id="b" * 64, submitted_block_blob="aa", **common,
            ), 1)
            store.enqueue_event(self.event(
                6, event="share_result", status="accepted_upstream",
                miner_target_diff=100, **common,
            ), 1)
            store.close()
            closed = store.snapshot()["recent_rounds"][0]
            detail = store.round_detail(closed["id"])
            submit_audit = events.json.loads(detail["blocks"][0]["submit_json"])
            attempts = submit_audit["attempts"]
            result_audit = events.json.loads(detail["blocks"][0]["result_json"])
            self.assertEqual(
                [item["event"] for item in attempts],
                ["submit_block", "submit_block_attempt", "submit_block_retry", "submit_block_reconcile"],
            )
            self.assertEqual([item["daemon_request_id"] for item in attempts], ["10", "10", "11", "12"])
            self.assertEqual(submit_audit["submitted_block_blob"], "aa")
            self.assertTrue(all(not item["submitted_block_blob"] for item in attempts))
            self.assertEqual(result_audit["submitted_block_blob"], "")
            self.assertEqual(
                result_audit["_submitted_block_blob_ref"],
                "submit_audit.submitted_block_blob",
            )

    def test_pending_submissions_and_nonaccepted_blocks_are_capped(self):
        old_pending = events.MAX_PENDING_SUBMISSIONS
        old_blocks = events.MAX_NONACCEPTED_BLOCKS
        events.MAX_PENDING_SUBMISSIONS = 3
        events.MAX_NONACCEPTED_BLOCKS = 3
        try:
            with tempfile.TemporaryDirectory() as directory:
                store = self.make_store(directory)
                for sequence in range(1, 6):
                    common = dict(source_id=1, template_id=1, share_id=sequence, job_id=f"job-{sequence}")
                    store.enqueue_event(self.event(
                        sequence, event="submit_block", status="requested", **common,
                    ), 1)
                for sequence in range(6, 11):
                    store.enqueue_event(self.event(
                        sequence, event="submit_block_result", status="ambiguous",
                        source_id=1, template_id=1, share_id=sequence, job_id=f"job-{sequence}",
                    ), 1)
                store.close()
                db = store._read_connect()
                try:
                    self.assertEqual(db.execute("SELECT count(*) FROM pending_submissions").fetchone()[0], 3)
                    self.assertEqual(db.execute("SELECT count(*) FROM blocks WHERE status!='accepted'").fetchone()[0], 3)
                finally:
                    db.close()
        finally:
            events.MAX_PENDING_SUBMISSIONS = old_pending
            events.MAX_NONACCEPTED_BLOCKS = old_blocks

    def test_pending_and_nonaccepted_submission_history_obeys_byte_bounds(self):
        old_pending_bytes = events.MAX_PENDING_SUBMISSION_BYTES
        old_block_bytes = events.MAX_NONACCEPTED_BLOCK_BYTES
        events.MAX_PENDING_SUBMISSION_BYTES = 12_000
        events.MAX_NONACCEPTED_BLOCK_BYTES = 12_000
        try:
            with tempfile.TemporaryDirectory() as directory:
                store = self.make_store(directory)
                for sequence in range(1, 7):
                    common = dict(
                        source_id=1, template_id=1, share_id=sequence,
                        job_id=f"job-{sequence}", submitted_block_blob="aa" * 2000,
                    )
                    store.enqueue_event(self.event(
                        sequence, event="submit_block", status="requested", **common,
                    ), 1)
                for sequence in range(7, 13):
                    store.enqueue_event(self.event(
                        sequence, event="submit_block_result", status="ambiguous",
                        source_id=1, template_id=1, share_id=sequence,
                        job_id=f"job-{sequence}", submitted_block_blob="bb" * 2000,
                    ), 1)
                store.close()
                db = store._read_connect()
                try:
                    pending_bytes = db.execute(
                        "SELECT coalesce(sum(length(CAST(row_json AS BLOB))),0) "
                        "FROM pending_submissions"
                    ).fetchone()[0]
                    block_bytes = db.execute(
                        "SELECT coalesce(sum(length(CAST(submit_json AS BLOB))+"
                        "length(CAST(result_json AS BLOB))),0) "
                        "FROM blocks WHERE status!='accepted'"
                    ).fetchone()[0]
                    self.assertLessEqual(pending_bytes, events.MAX_PENDING_SUBMISSION_BYTES)
                    self.assertLessEqual(block_bytes, events.MAX_NONACCEPTED_BLOCK_BYTES)
                finally:
                    db.close()
        finally:
            events.MAX_PENDING_SUBMISSION_BYTES = old_pending_bytes
            events.MAX_NONACCEPTED_BLOCK_BYTES = old_block_bytes

    def test_average_effort_uses_all_complete_closed_rounds(self):
        with tempfile.TemporaryDirectory() as directory:
            store = events.SQLiteStore(str(Path(directory) / "events.sqlite3"))
            db = store._connect()
            try:
                with db:
                    for effort in (["1"] * 50 + ["100"]):
                        db.execute(
                            "INSERT INTO rounds(started_utc,ended_utc,effort_units,coverage_complete,status) "
                            "VALUES('a','b',?,1,'closed')",
                            (effort,),
                        )
                store._refresh_cache(db)
            finally:
                db.close()
            self.assertAlmostEqual(store.snapshot()["average_round_effort_percent"], 15000 / 51)

    def test_restart_recovers_unclosed_accepted_block_as_incomplete_round(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_store(directory)
            common = dict(
                source_id=1, template_id=2, share_id=7, job_id="job-a",
                height=99, share_diff=5000, network_target_diff=10000,
            )
            first.enqueue_event(self.event(1, event="submit_block", status="requested", **common), 1)
            first.enqueue_event(self.event(
                2, event="submit_block_result", status="accepted", block_id="b" * 64, **common,
            ), 1)
            first.close()

            second = self.make_store(directory)
            second.close()
            snapshot = second.snapshot()
            self.assertEqual(len(snapshot["recent_rounds"]), 1)
            self.assertFalse(bool(snapshot["recent_rounds"][0]["coverage_complete"]))
            self.assertNotEqual(snapshot["current_round"]["id"], snapshot["recent_rounds"][0]["id"])
            detail = second.round_detail(snapshot["recent_rounds"][0]["id"])
            self.assertEqual(detail["blocks"][0]["round_closed"], 1)

    def test_late_winning_share_after_restart_stays_in_recovered_round(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.make_store(directory)
            common = dict(
                source_id=1, template_id=2, share_id=7, job_id="job-a",
                height=99, share_diff=5000, network_target_diff=10000,
            )
            first.enqueue_event(self.event(
                1, event="submit_block", status="requested", **common,
            ), 1)
            first.enqueue_event(self.event(
                2, event="submit_block_result", status="accepted",
                block_id="b" * 64, **common,
            ), 1)
            first.close()

            second = self.make_store(directory)
            second.enqueue_event(self.event(
                3, event="share_result", status="accepted_upstream",
                miner_target_diff=100, **common,
            ), 1)
            second.close()
            snapshot = second.snapshot()
            self.assertEqual(snapshot["recent_rounds"][0]["accepted_shares"], 1)
            self.assertEqual(snapshot["recent_rounds"][0]["credited_hashes"], "100")
            self.assertEqual(snapshot["current_round"]["accepted_shares"], 0)

    def test_sqlite_queue_enforces_byte_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            store = events.SQLiteStore(
                str(Path(directory) / "events.sqlite3"),
                queue_limit=100, queue_byte_limit=events.MAX_LINE_BYTES,
            )
            accepted = store.enqueue_event(self.event(
                1, event="template_cached", blocktemplate_blob="a" * events.MAX_LINE_BYTES,
            ), 1)
            self.assertFalse(accepted)
            self.assertEqual(store.snapshot()["dropped_messages"], 1)

    def test_unretained_template_and_job_contexts_obey_count_bounds(self):
        old_job_limit = events.MAX_PENDING_JOB_CONTEXTS
        old_template_limit = events.MAX_PENDING_TEMPLATE_CONTEXTS
        events.MAX_PENDING_JOB_CONTEXTS = 2
        events.MAX_PENDING_TEMPLATE_CONTEXTS = 2
        try:
            with tempfile.TemporaryDirectory() as directory:
                store = self.make_store(directory)
                sequence = 1
                for template_id in range(1, 5):
                    common = dict(source_id=1, template_id=template_id, height=99)
                    store.enqueue_event(self.event(
                        sequence, event="template_cached", blocktemplate_blob="aa", **common,
                    ), 1)
                    sequence += 1
                    store.enqueue_event(self.event(
                        sequence, event="template_derived", hashing_blob="bb",
                        job_id=f"job-{template_id}", **common,
                    ), 1)
                    sequence += 1
                store.close()
                db = store._read_connect()
                try:
                    self.assertLessEqual(db.execute(
                        "SELECT count(*) FROM template_contexts WHERE retained=0"
                    ).fetchone()[0], 2)
                    self.assertLessEqual(db.execute(
                        "SELECT count(*) FROM job_contexts WHERE retained=0"
                    ).fetchone()[0], 2)
                finally:
                    db.close()
        finally:
            events.MAX_PENDING_JOB_CONTEXTS = old_job_limit
            events.MAX_PENDING_TEMPLATE_CONTEXTS = old_template_limit

    def test_context_retention_is_recomputed_when_share_leaves_top_set(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.make_store(
                directory, big_share_difficulty=1_000_000, round_top_limit=1,
            )
            sequence = 1
            for template_id, job_id, share_id, difficulty in (
                (1, "job-a", 1, 100),
                (2, "job-b", 2, 200),
            ):
                common = dict(source_id=1, template_id=template_id, height=99)
                store.enqueue_event(self.event(
                    sequence, event="template_cached", blocktemplate_blob="aa", **common,
                ), 1)
                sequence += 1
                store.enqueue_event(self.event(
                    sequence, event="template_derived", hashing_blob="bb",
                    job_id=job_id, **common,
                ), 1)
                sequence += 1
                store.enqueue_event(self.event(
                    sequence, event="share_result", status="accepted_local",
                    share_id=share_id, miner_target_diff=10, share_diff=difficulty,
                    network_target_diff=1000, job_id=job_id, **common,
                ), 1)
                sequence += 1
            store.close()

            db = store._read_connect()
            try:
                self.assertEqual(
                    [value[0] for value in db.execute(
                        "SELECT retained FROM job_contexts ORDER BY id"
                    ).fetchall()],
                    [0, 1],
                )
                self.assertEqual(
                    [value[0] for value in db.execute(
                        "SELECT retained FROM template_contexts ORDER BY id"
                    ).fetchall()],
                    [0, 1],
                )
            finally:
                db.close()


class ApiTest(unittest.TestCase):
    def test_summary_and_workers_are_allowlisted(self):
        summary = events.sanitize_api_summary({
            "id": "proxy", "version": "6.26.0", "mode": "simple", "uptime": 65,
            "hashrate": {"total": [1.5, 2.5, 3.5]},
            "miners": {"now": 2, "max": 3}, "workers": 1,
            "upstreams": {"active": 2, "total": 2, "ratio": 1.0},
            "results": {"accepted": 4, "rejected": 1, "invalid": 2, "hashes_total": 999},
            "daemon_solo": {"enabled": True, "payouts": [{
                "address": "4" + "a" * 94, "coin": "XMR", "network": "mainnet",
                "type": "primary", "validated": True, "secret": "must-not-leak",
            }]},
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
        self.assertTrue(summary["daemon_solo"]["enabled"])
        self.assertEqual(summary["daemon_solo"]["payouts"][0]["coin"], "XMR")
        self.assertNotIn("secret", summary["daemon_solo"]["payouts"][0])

    def test_invalid_hashrates_remain_unknown(self):
        summary = events.sanitize_api_summary({
            "hashrate": {"total": [-1, "unknown", None, 999]},
        })
        self.assertEqual(summary["hashrate"], [None, None, None, 999])

    def test_mixed_api_epoch_is_detected(self):
        self.assertFalse(events.ApiPoller._mixed_epoch(
            {"uptime": 100}, 1000.0, {"uptime": 102}, 1002.0,
        ))
        self.assertTrue(events.ApiPoller._mixed_epoch(
            {"uptime": 100}, 1000.0, {"uptime": 1}, 1002.0,
        ))
        self.assertTrue(events.ApiPoller._mixed_epoch(
            {"uptime": "bad"}, 1000.0, {"uptime": 1}, 1002.0,
        ))

    def test_password_worker_mode_is_redacted(self):
        workers = events.sanitize_api_workers({
            "mode": "password",
            "workers": [["actual-password", "127.0.0.1", 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
        })
        self.assertEqual(workers[0]["name"], "[password worker hidden]")
        self.assertNotIn("actual-password", events.json.dumps(workers))

    def test_unknown_worker_mode_never_exposes_column_zero(self):
        workers = events.sanitize_api_workers({
            "mode": "future-secret-mode",
            "workers": [["must-not-leak", "127.0.0.1", 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]],
        })
        self.assertEqual(workers[0]["name"], "[worker name hidden: unknown mode]")
        self.assertNotIn("must-not-leak", events.json.dumps(workers))

    def test_state_never_contains_api_token(self):
        state = events.DashboardState("/tmp/events.sock", 100, 5, api_enabled=True)
        subscriber, _ = state.subscribe()
        state.update_api(
            {"hashrate": {"total": [1]}, "access-token": "TOKEN-SECRET"},
            {"workers": [], "password": "TOKEN-SECRET"},
        )
        self.assertNotIn("TOKEN-SECRET", events.json.dumps(state.snapshot()))
        self.assertEqual(subscriber.get_nowait()["kind"], "state")
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
            "Persistent mining rounds", "RandomX verifier", "Copy JSON",
            "Validated daemon-solo payout destinations",
            "Load any past round ID",
        ):
            self.assertIn(text, events.HTML)
        ids = re.findall(r'id="([^"]+)"', events.HTML)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("'\"':'&quot;'", events.HTML)
        self.assertIn("address.textContent=payout.address", events.HTML)

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

    def test_ready_rejects_incomplete_sequence_coverage(self):
        self.state.begin_session()
        self.state.ingest(row(
            schema_version=3, stream_id="a" * 32, event_seq=7,
        ))
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

    @unittest.skipUnless(shutil.which("node"), "node is unavailable")
    def test_hashrate_formatter_auto_scales_and_rejects_unknown_values(self):
        missing = re.search(r"  const missing = (.*?);\n", events.HTML)
        helper = re.search(r"  const hashrate = (.+);\n", events.HTML)
        self.assertIsNotNone(missing)
        self.assertIsNotNone(helper)
        script = (
            "const missing = " + missing.group(1) + ";\n"
            "const hashrate = " + helper.group(1) + ";\n"
            "console.log(JSON.stringify([hashrate(999),hashrate(1000),hashrate(999000),"
            "hashrate(1000000),hashrate(-1),hashrate('unknown'),"
            "hashrate(999,'kH/s'),hashrate(1000,'kH/s')]));\n"
        )
        output = events.json.loads(subprocess.check_output(["node", "-e", script], text=True))
        self.assertEqual(output, [
            "999 H/s", "1.00 kH/s", "999 kH/s", "1.00 MH/s", "—", "—",
            "999 kH/s", "1.00 MH/s",
        ])

    @unittest.skipUnless(shutil.which("node"), "node is unavailable")
    def test_json_inspector_colors_strings_and_escapes_markup(self):
        block = re.search(
            r"  const jsonReady = (.*?);\n  const detailText =",
            events.HTML,
            re.S,
        )
        self.assertIsNotNone(block)
        script = block.group(0).rsplit("\n  const detailText =", 1)[0]
        output = subprocess.check_output(
            ["node", "-e", script + "\nconsole.log(jsonHtml({key:'<script>alert(1)</script>'}));"],
            text=True,
        )
        self.assertIn('class="json-key"', output)
        self.assertIn('class="json-string"', output)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)


if __name__ == "__main__":
    unittest.main()
