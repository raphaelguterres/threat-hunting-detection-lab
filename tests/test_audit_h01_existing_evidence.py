"""Offline tests for H01's bounded identity-only historical sample audit."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import audit_h01_existing_evidence as h01  # noqa: E402


def record(rule, timestamp, agent="004"):
    return (rule, agent, h01.parse_time(timestamp))


TASK = "2026-11-01T23:19:52.407+0000"
PS = "2026-11-02T00:22:15.606Z"


class HistoricalH01Tests(unittest.TestCase):
    def test_known_sample_reversed_and_outside_window(self):
        result = h01.audit([
            record("110120", TASK), record("110100", PS),
            record("110140", PS), record("110140", TASK),
            record("110130", TASK), record("110110", TASK),
        ])
        self.assertEqual(result["sample_events"], 6)
        self.assertEqual(result["order"], "task_then_powershell")
        self.assertEqual(result["absolute_separation_seconds"], 3743.199)
        self.assertEqual(
            result["temporal_result"], "h01_not_supported_by_this_bounded_sample"
        )
        self.assertFalse(result["actor_process_and_task_creation_verified"])
        self.assertFalse(result["incident_determined"])

    def test_positive_timing_is_not_incident_confirmation(self):
        records = [
            record("110100", "2026-11-02T00:00:00Z"),
            record("110120", "2026-11-02T00:15:00Z"),
        ]
        result = h01.audit(records)
        self.assertEqual(
            result["temporal_result"], "candidate_requires_actor_and_task_creation_proof"
        )
        self.assertFalse(result["incident_determined"])

    def test_outside_window(self):
        result = h01.audit([
            record("110100", "2026-11-02T00:00:00Z"),
            record("110120", "2026-11-02T00:15:01Z"),
        ])
        self.assertEqual(result["temporal_result"],
                         "h01_not_supported_by_this_bounded_sample")

    def test_simultaneous_is_not_h01(self):
        result = h01.audit([
            record("110100", PS), record("110120", PS),
        ])
        self.assertEqual(result["order"], "simultaneous")
        self.assertEqual(result["temporal_result"],
                         "h01_not_supported_by_this_bounded_sample")

    def test_different_agents_not_correlated(self):
        result = h01.audit([
            record("110100", PS), record("110120", TASK, agent="999"),
        ])
        self.assertEqual(result["temporal_result"], "different_agents_not_correlated")
        self.assertNotIn("absolute_separation_seconds", result)

    def test_multiple_same_rule_is_inconclusive(self):
        result = h01.audit([
            record("110100", PS), record("110100", TASK), record("110120", TASK),
        ])
        self.assertEqual(result["temporal_result"], "inconclusive_event_count")

    def test_no_data_not_clear(self):
        result = h01.audit([])
        self.assertEqual(result["temporal_result"], "inconclusive_event_count")
        self.assertFalse(result["incident_determined"])

    def test_timezone_normalization(self):
        self.assertEqual(h01.parse_time(PS),
                         h01.parse_time("2026-11-01T16:22:15.606-08:00"))
        self.assertEqual(h01.parse_time(TASK),
                         h01.parse_time("2026-11-01T23:19:52.407+00:00"))

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            h01.parse_time("2026-11-02T00:22:15.606")

    def test_duplicate_original_ids_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.jsonl"
            item = {"id": "synthetic-a", "rule": {"id": "110100"},
                    "agent": {"id": "004"}, "timestamp": PS}
            path.write_text(json.dumps(item) + "\n" + json.dumps(item), encoding="utf-8")
            with self.assertRaises(ValueError):
                h01.read_identity_export(path)

    def test_invalid_record_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.jsonl"
            path.write_text('{"id":"a","timestamp":"2026-11-02"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                h01.read_identity_export(path)

    def test_sample_size_restricted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.jsonl"
            path.write_bytes(b"x" * 65537)
            with self.assertRaises(ValueError):
                h01.read_identity_export(path)

    def test_fixture_access_policy(self):
        fixture = ROOT / "tests" / "fixtures" / "m1-synthetic.jsonl"
        self.assertTrue(h01.is_private_input(fixture, ROOT, True))
        self.assertFalse(h01.is_private_input(fixture, ROOT, False))
        self.assertFalse(h01.is_private_input(ROOT / "README.md", ROOT, True))

    def test_private_only_missing_file_is_sanitized(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = h01.main(["--input", ".lab/sensitive-name-do-not-display.jsonl"])
        self.assertEqual(code, 2)
        self.assertNotIn("sensitive-name", err.getvalue())

    def test_cli_synthetic_fixture_exact_projection(self):
        path = ROOT / "tests" / "fixtures" / "m1-phase3-h01-synthetic.jsonl"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = h01.main(["--input", str(path), "--fixture"])
        self.assertEqual(code, 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["sample_events"], 6)
        self.assertEqual(result["provenance"], "synthetic_fixture")
        self.assertEqual(result["temporal_result"],
                         "h01_not_supported_by_this_bounded_sample")
        self.assertNotIn("synthetic-1", out.getvalue())


if __name__ == "__main__":
    unittest.main()
