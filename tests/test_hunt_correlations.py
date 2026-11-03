"""Unit tests for M1 offline hypothesis correlation. Synthetic records only."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hunt_correlations as hunting  # noqa: E402


def raw(kind, source, ref, time="2026-11-02T12:00:00Z",
        asset="win-a", actor="actor-a", obj="object-a"):
    return {
        "timestamp": time, "kind": kind, "source": source,
        "event_ref": ref, "asset_key": asset,
        "actor_key": actor, "object_key": obj,
    }


class HypothesisTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            raw("powershell_process", "sysmon_eid1", "a"),
            raw("task_created", "security_eid4698", "b", "2026-11-02T12:14:59Z"),
        ]

    def count(self, records, key="H01_POWERSHELL_TASK"):
        result = hunting.correlate([hunting.parse_event(e) for e in records])
        return result["hypotheses"][key]["candidate_pairs"]

    def test_all_three_positives_and_three_controls_fixture(self):
        fixture = ROOT / "tests" / "fixtures" / "m1-synthetic.jsonl"
        result = hunting.correlate(hunting.load_events(fixture))
        self.assertEqual(result["input_events"], 12)
        self.assertEqual(
            {name: x["candidate_pairs"] for name, x in result["hypotheses"].items()},
            {"H01_POWERSHELL_TASK": 1, "H02_ACCOUNT_PRIVILEGE": 1,
             "H03_FIM_EXECUTION": 1},
        )
        self.assertEqual(result["verdict"], "not_an_incident_determination")

    def test_empty_sample_reports_insufficient_coverage_not_clearance(self):
        result = hunting.correlate([])
        self.assertTrue(all(x["candidate_pairs"] == 0
                            for x in result["hypotheses"].values()))
        self.assertTrue(all(x["status"] == "insufficient_source_coverage"
                            for x in result["hypotheses"].values()))
        self.assertEqual(result["verdict"], "not_an_incident_determination")

    def test_missing_required_source_is_not_misreported_as_negative_result(self):
        only_first = [raw("powershell_process", "sysmon_eid1", "first")]
        result = hunting.correlate([hunting.parse_event(e) for e in only_first])
        h01 = result["hypotheses"]["H01_POWERSHELL_TASK"]
        self.assertEqual(h01["first_kind_events"], 1)
        self.assertEqual(h01["second_kind_events"], 0)
        self.assertEqual(h01["status"], "insufficient_source_coverage")

    def test_both_sources_without_valid_join_produce_no_candidate_status(self):
        rows = [raw("powershell_process", "sysmon_eid1", "first"),
                raw("task_created", "security_eid4698", "second",
                    "2026-11-02T12:05:00Z", asset="other-host")]
        result = hunting.correlate([hunting.parse_event(e) for e in rows])
        h01 = result["hypotheses"]["H01_POWERSHELL_TASK"]
        self.assertEqual(h01["first_kind_events"], 1)
        self.assertEqual(h01["second_kind_events"], 1)
        self.assertEqual(h01["candidate_pairs"], 0)
        self.assertEqual(h01["status"], "no_candidate_in_supplied_sample")

    def test_15_min_boundary_is_inclusive(self):
        self.events[1]["timestamp"] = "2026-11-02T12:15:00Z"
        self.assertEqual(self.count(self.events), 1)

    def test_over_window_rejected(self):
        self.events[1]["timestamp"] = "2026-11-02T12:15:00.001Z"
        self.assertEqual(self.count(self.events), 0)

    def test_reversed_sequence_rejected(self):
        self.events[1]["timestamp"] = "2026-11-02T11:59:00Z"
        self.assertEqual(self.count(self.events), 0)

    def test_same_instant_rejected(self):
        self.events[1]["timestamp"] = "2026-11-02T12:00:00Z"
        self.assertEqual(self.count(self.events), 0)

    def test_different_actor_rejected(self):
        self.events[1]["actor_key"] = "another-actor"
        self.assertEqual(self.count(self.events), 0)

    def test_different_asset_rejected(self):
        self.events[1]["asset_key"] = "other-vm"
        self.assertEqual(self.count(self.events), 0)

    def test_account_hypothesis_joins_target_account_not_actor(self):
        rows = [
            raw("account_created", "security_eid4720", "c",
                obj="account-xyz", actor="admin-01"),
            raw("privileged_logon", "security_eid4672", "d",
                "2026-11-02T12:29:00Z", obj="account-xyz", actor="different-actor"),
        ]
        self.assertEqual(self.count(rows, "H02_ACCOUNT_PRIVILEGE"), 1)
        rows[1]["object_key"] = "different-account"
        self.assertEqual(self.count(rows, "H02_ACCOUNT_PRIVILEGE"), 0)
        rows[1]["object_key"] = "account-xyz"
        rows[1]["timestamp"] = "2026-11-02T12:30:01Z"
        self.assertEqual(self.count(rows, "H02_ACCOUNT_PRIVILEGE"), 0)

    def test_fim_hypothesis_joins_artifact_and_host(self):
        rows = [
            raw("file_change", "wazuh_fim", "c", obj="file-xyz"),
            raw("file_execution", "sysmon_eid1", "d",
                "2026-11-02T12:20:00Z", obj="file-xyz"),
        ]
        self.assertEqual(self.count(rows, "H03_FIM_EXECUTION"), 1)
        rows[1]["asset_key"] = "other-vm"
        self.assertEqual(self.count(rows, "H03_FIM_EXECUTION"), 0)

    def test_timezone_equivalence(self):
        self.events[0]["timestamp"] = "2026-11-02T04:00:00-0800"
        self.assertEqual(self.count(self.events), 1)

    def test_naive_timestamp_rejected(self):
        self.events[0]["timestamp"] = "2026-11-02T12:00:00"
        with self.assertRaises(ValueError):
            self.count(self.events)

    def test_disallowed_source_rejected(self):
        self.events[0]["source"] = "security_eid4720"
        with self.assertRaises(ValueError):
            self.count(self.events)

    def test_unknown_kind_rejected(self):
        self.events[0]["kind"] = "ransomware_confirmed"
        with self.assertRaises(ValueError):
            self.count(self.events)

    def test_extra_field_or_missing_field_rejected(self):
        self.events[0]["hostname"] = "REAL-SENSITIVE"
        with self.assertRaises(ValueError):
            self.count(self.events)
        del self.events[0]["hostname"]
        del self.events[0]["asset_key"]
        with self.assertRaises(ValueError):
            self.count(self.events)

    def test_duplicate_event_ref_rejected(self):
        self.events[1]["event_ref"] = self.events[0]["event_ref"]
        with self.assertRaises(ValueError):
            self.count(self.events)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.jsonl"
            path.write_text('{"kind":"a","kind":"b"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                hunting.load_events(path)

    def test_nonfinite_json_constant_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nonfinite.jsonl"
            row = json.dumps(raw("powershell_process", "sysmon_eid1", "synthetic-ref"))
            row = row.replace('"actor_key": "actor-a"', '"actor_key": NaN')
            path.write_text(row + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "nonfinite JSON constant"):
                hunting.load_events(path)

    def test_deeply_nested_jsonl_fails_closed_without_private_path(self):
        (ROOT / ".lab").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m1-hunt-nested-", dir=ROOT / ".lab") as tmp:
            path = Path(tmp) / "SYNTHETIC_DO_NOT_PRINT.jsonl"
            path.write_text("[" * 2000 + "0" + "]" * 2000 + "\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                code = hunting.main(["--input", str(path)])
            self.assertEqual(code, 2)
            self.assertIn("M1_INPUT_REJECTED", output.getvalue())
            self.assertNotIn("SYNTHETIC_DO_NOT_PRINT", output.getvalue())
            self.assertNotIn(str(path), output.getvalue())
            self.assertNotIn("Traceback", output.getvalue())

    def test_identity_aliases_with_control_characters_are_rejected(self):
        for field in ("event_ref", "asset_key", "actor_key", "object_key"):
            for value in ("safe\nspoofed", "safe\x1b[31m", "safe\x7f"):
                with self.subTest(field=field, value=repr(value)):
                    item = raw("powershell_process", "sysmon_eid1", "safe")
                    item[field] = value
                    with self.assertRaisesRegex(ValueError, "control character"):
                        hunting.parse_event(item)

    def test_reject_symlinked_private_parent_even_when_target_is_private(self):
        (ROOT / ".lab").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m1-parent-", dir=ROOT / ".lab") as folder:
            original = Path(folder) / "source"
            original.mkdir()
            file = original / "events.jsonl"
            file.write_text("{}\n", encoding="utf-8")
            link = Path(folder) / "alias"
            try:
                link.symlink_to(original, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not permitted on this platform")
            self.assertTrue(hunting.allowed_input(file, ROOT, False))
            self.assertFalse(hunting.allowed_input(link / "events.jsonl", ROOT, False))

    def test_private_only_input_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            lab = repo / ".lab"
            lab.mkdir()
            fixture = repo / "tests" / "fixtures"
            fixture.mkdir(parents=True)
            self.assertTrue(hunting.allowed_input(lab / "records.jsonl", repo, False))
            self.assertFalse(hunting.allowed_input(fixture / "fixture.jsonl", repo, False))
            self.assertTrue(hunting.allowed_input(fixture / "fixture.jsonl", repo, True))
            self.assertFalse(hunting.allowed_input(repo / "README.md", repo, True))

    def test_missing_input_returns_error_without_dump(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = hunting.main(["--input", ".lab/file-that-is-not-there.jsonl"])
        self.assertEqual(code, 2)
        self.assertNotIn("file-that-is-not-there", output.getvalue())

    def test_cli_synthetic_fixture_aggregate_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = hunting.main([
                "--input", "tests/fixtures/m1-synthetic.jsonl", "--fixture"
            ])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["sample_provenance"], "synthetic_fixture")
        self.assertEqual(result["hypotheses"]["H01_POWERSHELL_TASK"]["candidate_pairs"], 1)
        self.assertNotIn("win-01", output.getvalue())
        self.assertNotIn("lab-syn-001", output.getvalue())


    def test_wazuh_schtasks_create_command_is_not_a_confirmed_task(self):
        item = raw("task_created", "wazuh_rule110120", "unconfirmed",
                   "2026-11-02T12:07:00Z")
        with self.assertRaises(ValueError):
            hunting.parse_event(item)

    def test_schtasks_attempt_is_not_counted_as_h01_confirmed_creation(self):
        records = [
            raw("powershell_process", "sysmon_eid1", "first"),
            raw("task_creation_attempt", "wazuh_rule110120", "second",
                "2026-11-02T12:05:00Z"),
        ]
        self.assertEqual(self.count(records), 0)
        records[1]["kind"] = "task_created"
        records[1]["source"] = "security_eid4698"
        self.assertEqual(self.count(records), 1)


if __name__ == "__main__":
    unittest.main()
