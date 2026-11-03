"""Contracts for preliminary, fail-closed operator-dashboard triage."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "m1_observed_agents_triage.py"
spec = importlib.util.spec_from_file_location("m1_observed_agents_triage", SCRIPT)
sys.path.insert(0, str(ROOT / "scripts"))
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


def sample():
    return {
        "schema_version": 1,
        "agents": [
            {"id": f"{idx:03d}",
             "os": "Microsoft Windows Server 2022 Standard Evaluation 10.0.20348.587"
                   if idx == 4 else "Amazon Linux 2023",
             "status": "disconnected" if idx == 1 else "active",
             "groups_ordered": None, "group_sync": "unverified",
             "last_keepalive": None, "observed_at": None,
             "evidence_ref": "SYNTHETIC_PRIVATE_REF"}
            for idx in (1, 2, 4, 5)
        ],
    }


class SnapshotTriageTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".lab").mkdir(exist_ok=True)
        folder = tempfile.TemporaryDirectory(prefix="m1-triage-synthetic-", dir=ROOT / ".lab")
        self.addCleanup(folder.cleanup)
        self.filename = Path(folder.name) / "synthetic-observation.json"

    def invoke(self, data):
        self.filename.write_text(json.dumps(data), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--snapshot", str(self.filename)],
            capture_output=True, text=True,
        )

    def test_partial_disconnected_snapshot_reports_unknowns_and_block(self):
        result = self.invoke(sample())
        self.assertEqual(result.returncode, 0, result.stderr)
        for marker in (
            "SNAPSHOT_CLASS=PRELIMINARY_UNATTESTED",
            "OBSERVED_ROWS=4", "LINUX_FAMILY_OBSERVED=3",
            "WINDOWS_FAMILY_OBSERVED=1", "STATUS_ACTIVE=3",
            "STATUS_DISCONNECTED=1", "GROUP_MEMBERSHIP_UNKNOWN=4",
            "GROUP_SYNC_UNKNOWN=4", "LAST_KEEPALIVE_UNKNOWN=4",
            "OBSERVATION_TIMESTAMP_UNKNOWN=4",
            "GROUP_MEMBERSHIP_ATTESTED=false",
            "DEPLOYMENT_GATE=BLOCKED", "WRITES_PERFORMED=false",
        ):
            self.assertIn(marker, result.stdout)
        self.assertNotIn("SYNTHETIC_PRIVATE_REF", result.stdout)
        self.assertNotIn("001", result.stdout)
        self.assertNotIn(str(self.filename), result.stdout)

    def test_even_all_active_and_group_display_does_not_authorize(self):
        doc = sample()
        for agent in doc["agents"]:
            agent["status"] = "active"
            agent["groups_ordered"] = ["default"]
            agent["group_sync"] = "synced"
        result = self.invoke(doc)
        self.assertEqual(result.returncode, 0)
        self.assertIn("DEFAULT_MEMBERSHIP_OBSERVED=4", result.stdout)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)
        self.assertIn("GROUP_MEMBERSHIP_ATTESTED=false", result.stdout)

    def test_duplicate_ids_and_invalid_group_precedence_fail(self):
        data = sample()
        data["agents"][1]["id"] = "001"
        self.assertEqual(self.invoke(data).returncode, 2)
        data = sample()
        data["agents"][1]["groups_ordered"] = ["default", "default"]
        self.assertEqual(self.invoke(data).returncode, 2)

    def test_file_outside_private_folder_is_rejected(self):
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "--snapshot", str(ROOT / "README.md")],
            capture_output=True, text=True,
        )
        self.assertEqual(p.returncode, 2)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", p.stdout)
        self.assertNotIn(str(ROOT), p.stdout)

    def test_unknown_timestamps_must_not_be_filled_with_fabrications(self):
        data = sample()
        data["agents"][0]["observed_at"] = "2026-11-03T16:00:00"
        self.assertEqual(self.invoke(data).returncode, 2)
        data["agents"][0]["observed_at"] = "2026-11-03T16:00:00-03:00"
        out = self.invoke(data)
        self.assertEqual(out.returncode, 0)
        self.assertIn("OBSERVATION_TIMESTAMP_UNKNOWN=3", out.stdout)

    def test_future_observation_and_future_keepalive_are_rejected(self):
        for field in ("observed_at", "last_keepalive"):
            with self.subTest(field=field):
                data = sample()
                data["agents"][0][field] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
                out = self.invoke(data)
                self.assertEqual(out.returncode, 2)
                self.assertIn("DEPLOYMENT_GATE=BLOCKED", out.stdout)
                self.assertNotIn(field, out.stdout)

    def test_keepalive_newer_than_observation_is_rejected(self):
        data = sample()
        data["agents"][0]["observed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        data["agents"][0]["last_keepalive"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        self.assertEqual(self.invoke(data).returncode, 2)
        data["agents"][0]["last_keepalive"] = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat()
        good = self.invoke(data)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", good.stdout)

    def test_boolean_schema_version_is_not_integer_one(self):
        data = sample()
        data["schema_version"] = True
        self.assertEqual(self.invoke(data).returncode, 2)

    def test_oversized_or_deeply_nested_inputs_fail_safely(self):
        self.filename.write_bytes(b" " * 33000)
        r = subprocess.run([sys.executable, str(SCRIPT), "--snapshot", str(self.filename)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", r.stdout)
        self.filename.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
        r = subprocess.run([sys.executable, str(SCRIPT), "--snapshot", str(self.filename)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
