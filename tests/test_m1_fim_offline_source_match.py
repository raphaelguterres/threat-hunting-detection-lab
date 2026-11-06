"""Offline-only contract tests for private Manager/Indexer FIM export comparison."""
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import contextlib
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "scripts/m1_fim_offline_source_match.py"
spec = importlib.util.spec_from_file_location("m1_fim_offline_source_match", MODULE)
matcher = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = matcher
spec.loader.exec_module(matcher)


def records():
    output = []
    for agent in matcher.AGENTS:
        path = (r"C:\\Fake\\FIM\\safe.m1probe" if agent == "004"
                else "/private-lab/fim/safe-" + agent + ".txt")
        for pos, kind in enumerate(("added", "modified", "deleted")):
            output.append({
                "id": f"18700000.{agent}.{pos}",
                "timestamp": f"2026-11-05T17:12:{20+pos*7:02d}.000+0000",
                "rule": {"id": 550 + pos},
                "agent": {"id": agent, "name": "SECRET_INTERNAL_HOST"},
                "syscheck": {"path": path, "event": kind},
            })
    return output


def scope_for(data):
    return {agent: next(e["syscheck"]["path"] for e in data if e["agent"]["id"] == agent)
            for agent in matcher.AGENTS}


def load_in_memory(data, scope):
    return [matcher.parse_event(v, scope) for v in data]


class FimOfflineCompareTests(unittest.TestCase):
    def setUp(self):
        self.data = records()
        self.scope = matcher.load_scope_map_for_tests if False else {
            a: matcher.scoped_path(path, a) for a, path in scope_for(self.data).items()
        }

    def test_exact_nine_pairs(self):
        manager = load_in_memory(self.data, self.scope)
        indexer = load_in_memory([{"_source": dict(record)} for record in self.data], self.scope)
        report = matcher.compare(manager, indexer)
        self.assertEqual(report["comparison"], "MATCHED_PRIVATE_EXPORTS")
        self.assertEqual(report["exact_identity_matches"], 9)
        self.assertTrue(all(x["complete_three_operations"] for x in report["per_agent"].values()))
        self.assertFalse(report["independent_manager_attestation"])
        self.assertFalse(report["independent_reviewer_verified"])

    def test_mismatched_id_is_rejected(self):
        indexer = [{"_source": dict(record)} for record in self.data]
        indexer[0]["_source"]["id"] = "WRONG_ID"
        outcome = matcher.compare(load_in_memory(self.data, self.scope),
                                  load_in_memory(indexer, self.scope))
        self.assertEqual(outcome["comparison"], "MISMATCH_OR_INCOMPLETE")
        self.assertEqual(outcome["exact_identity_matches"], 8)

    def test_wrong_artifact_is_excluded(self):
        broken = [dict(item) for item in self.data]
        broken[0]["syscheck"] = dict(broken[0]["syscheck"], path="/wrong/private/artifact")
        report = matcher.compare(load_in_memory(self.data, self.scope),
                                 [item for item in load_in_memory(broken, self.scope) if item])
        self.assertEqual(report["comparison"], "MISMATCH_OR_INCOMPLETE")

    def test_rule_or_clock_mismatch_is_rejected(self):
        indexer = [dict(row) for row in self.data]
        indexer[2]["rule"] = {"id": "999"}
        self.assertEqual(matcher.compare(load_in_memory(self.data, self.scope),
                                         load_in_memory(indexer, self.scope))["exact_identity_matches"], 8)
        indexer = [dict(row) for row in self.data]
        indexer[2]["timestamp"] = "2026-11-05T18:42:34+00:00"
        self.assertEqual(matcher.compare(load_in_memory(self.data, self.scope),
                                         load_in_memory(indexer, self.scope))["exact_identity_matches"], 8)

    def test_duplicate_event_id_fails_and_errors_are_sanitized(self):
        with tempfile.TemporaryDirectory(prefix="m1-offline-synthetic-", dir=REPO / ".lab") as folder:
            path = Path(folder) / "private-events.jsonl"
            data = list(self.data)
            data[1] = dict(data[1], id=data[0]["id"])
            path.write_text("\n".join(json.dumps(row) for row in data) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                matcher.load_events(path, self.scope)

    def test_timestamp_require_tz_and_control_char_rejected(self):
        with self.assertRaises(ValueError):
            matcher.timestamp("2026-11-05T14:00:00")
        with self.assertRaises(ValueError):
            matcher.clean_string("private\nleak", 50)
        self.assertEqual(matcher.timestamp("2026-11-05T14:00:00-0300"),
                         datetime(2026, 11, 5, 17, 0, tzinfo=timezone.utc))

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(ValueError):
            matcher.decode_json('{"id":"a","id":"b"}')
        with self.assertRaises(ValueError):
            matcher.decode_json('{"value":NaN}')

    def test_unrelated_alerts_are_skipped(self):
        self.assertIsNone(matcher.parse_event({"id": "a", "rule": {"id": "550"}}, self.scope))

    def test_cli_fixture_is_aggregate_only_and_no_fake_manager_attestation(self):
        with tempfile.TemporaryDirectory(prefix="m1-synthetic-offline-", dir=REPO / "tests/fixtures") as folder:
            base = Path(folder)
            a, b, c = (base / s for s in
                       ("m1-manager-synthetic.jsonl", "m1-indexer-synthetic.jsonl",
                        "m1-scope-synthetic.json"))
            a.write_text("\n".join(json.dumps(row) for row in self.data) + "\n", encoding="utf-8")
            b.write_text("\n".join(json.dumps({"_source": row}) for row in self.data) + "\n", encoding="utf-8")
            c.write_text(json.dumps(scope_for(self.data)), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = matcher.main(["--manager", str(a), "--indexer", str(b),
                                   "--scope", str(c), "--fixture"])
            result = out.getvalue()
            self.assertEqual(rc, 0)
            self.assertIn('"exact_identity_matches": 9', result)
            self.assertIn('"sample_type": "SYNTHETIC_ONLY"', result)
            self.assertNotIn("SECRET_INTERNAL_HOST", result)
            self.assertNotIn("private-lab/fim", result)
            self.assertNotIn(str(base), result)
            self.assertIn('"independent_manager_attestation": false', result)

    def test_reject_outside_lab_and_fixture_cross_usage(self):
        with self.assertRaises(ValueError):
            matcher.safe_file(REPO / "README.md", False)
        with self.assertRaises(ValueError):
            matcher.safe_file(REPO / "README.md", True)

    def test_missing_operations_are_not_approved(self):
        e = load_in_memory(self.data[:-1], self.scope)
        report = matcher.compare(e, e)
        self.assertEqual(report["comparison"], "MISMATCH_OR_INCOMPLETE")
        self.assertFalse(report["per_agent"]["005"]["complete_three_operations"])


if __name__ == "__main__":
    unittest.main()
