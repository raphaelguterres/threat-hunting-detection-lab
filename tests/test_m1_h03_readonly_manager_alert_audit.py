"""Synthetic-only tests of the read-only M1/H03 Manager alerts aggregate."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import m1_h03_readonly_manager_alert_audit as audit  # noqa: E402


def sample(rule, path, when, channel="", event_id=None, agent="004"):
    record = {
        "agent": {"id": agent, "name": "PRIVATE_HOST_DO_NOT_PRINT"},
        "timestamp": when,
        "rule": {"id": rule},
        "syscheck": {"path": path},
        "data": {"win": {"system": {"channel": channel, "eventID": event_id}}},
    }
    return record


class ReadonlyManagerAlertAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "fake-alerts.json"

    def write_events(self, records):
        self.path.write_text("\n".join(json.dumps(r) for r in records) + "\n",
                             encoding="utf-8")

    def test_counts_file_registry_sysmon_and_scope(self):
        self.write_events([
            sample("550", r"C:\\TestPrivate\\bin.exe", "2026-11-04T12:00:00Z"),
            sample("594", r"HKEY_LOCAL_MACHINE\\Fake", "2026-11-04T12:01:00+0000"),
            sample("61618", "", "2026-11-04T12:02:00Z",
                   "Microsoft-Windows-Sysmon/Operational", 1),
            sample("60132", "", "2026-11-04T12:03:00Z", "Security", 4672),
            sample("550", r"C:\\OTHER_PRIVATE\\x.exe", "2026-11-04T12:04:00Z",
                   agent="005"),
        ])
        report = audit.audit_alerts(self.path)
        c = report["counts"]
        self.assertEqual(c["agent_alerts"], 4)
        self.assertEqual(c["fim_file_rules"], 1)
        self.assertEqual(c["fim_registry_rules"], 1)
        self.assertEqual(c["syscheck_paths"], 2)
        self.assertEqual(c["registry_paths"], 1)
        self.assertEqual(c["nonregistry_paths"], 1)
        self.assertEqual(c["sysmon_eid1"], 1)
        self.assertEqual(c["security_events"], 1)
        self.assertEqual(c["invalid_timestamp"], 0)
        self.assertEqual(report["first_timestamp_utc"], "2026-11-04T12:00:00+00:00")
        self.assertEqual(report["last_timestamp_utc"], "2026-11-04T12:03:00+00:00")
        self.assertEqual(report["h03_real_pair"], "not_assessed")

    def test_cli_never_prints_private_event_data(self):
        self.write_events([sample(
            "550", r"C:\\SECRET_USERNAME\\private-key.exe", "2026-11-04T00:00:00Z"
        )])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = audit.main(["--input", str(self.path)])
        self.assertEqual(exit_code, 0)
        report = output.getvalue()
        self.assertNotIn("SECRET_USERNAME", report)
        self.assertNotIn("PRIVATE_HOST", report)
        self.assertNotIn(str(self.path), report)
        self.assertIn("single_active_manager_alerts_file", report)

    def test_invalid_json_is_counted_without_echo(self):
        self.path.write_text(
            "INVALID PRIVATE CONTENT\n" + json.dumps({
                "agent": {"id": "004"}, "timestamp": "without_zone",
                "rule": {"id": "554"}
            }) + "\n", encoding="utf-8"
        )
        result = audit.audit_alerts(self.path)
        self.assertEqual(result["counts"]["invalid_json_lines"], 1)
        self.assertEqual(result["counts"]["invalid_timestamp"], 1)
        self.assertEqual(result["counts"]["fim_file_rules"], 1)
        self.assertEqual(result["first_timestamp_utc"], "none")

    def test_missing_file_error_is_sanitized(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = audit.main(["--input", str(self.path)])
        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue().strip(), "ERROR=INPUT_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
