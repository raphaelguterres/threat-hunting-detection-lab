"""Offline end-to-end checkpoint summary: no network, no operational approval."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/m1_checkpoint_summary.py"


def sample():
    return {"schema_version": 1, "agents": [
        {"id": f"{i:03d}", "os": "Microsoft Windows Server 2022 Standard Evaluation 10.0.20348.587"
         if i == 4 else "Amazon Linux 2023",
         "status": "disconnected" if i == 1 else "active",
         "groups_ordered": None, "group_sync": "unverified",
         "last_keepalive": None, "observed_at": None,
         "evidence_ref": "SYNTHETIC_PRIVATE_REF"}
        for i in (1, 2, 4, 5)]}


class CheckpointSummaryTests(unittest.TestCase):
    def setUp(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        folder = tempfile.TemporaryDirectory(prefix="m1-checkpoint-synthetic-", dir=REPO / ".lab")
        self.addCleanup(folder.cleanup)
        self.snapshot = Path(folder.name) / "snapshot.json"
        self.manifest = Path(folder.name) / "manifest.json"
        self.snapshot.write_text(json.dumps(sample()), encoding="utf-8")
        self.manifest.write_text('{"schema_version":1,"change_id":"M1-FIM-OS-SCOPE","checks":{}}',
                                 encoding="utf-8")

    def run_script(self, mode="text"):
        return subprocess.run([sys.executable, str(SCRIPT),
                               "--snapshot", str(self.snapshot),
                               "--manifest", str(self.manifest),
                               "--format", mode],
                              capture_output=True, text=True)

    def test_combines_roadmap_and_partial_evidence_without_identity_leak(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^ROADMAP_DONE=[0-9]+$")
        self.assertRegex(result.stdout, r"(?m)^ROADMAP_TOTAL=[0-9]+$")
        for value in ("OBSERVED_AGENTS=4",
                      "ACTIVE_OBSERVED=3", "DISCONNECTED_OBSERVED=1",
                      "GROUP_MEMBERSHIPS_UNKNOWN=4", "GROUP_SYNC_UNKNOWN=4",
                      "KEEPALIVE_UNKNOWN=4", "MANIFEST_STATE=INCOMPLETE",
                      "OPERATIONAL_DEPLOYMENT_GATE=BLOCKED", "WRITES_PERFORMED=false",
                      "MANAGER_RUNTIME=NOT_CHECKED_BY_THIS_SCRIPT"):
            self.assertIn(value, result.stdout)
        for value in ("SYNTHETIC_PRIVATE_REF", "001", str(self.snapshot)):
            self.assertNotIn(value, result.stdout)

    def test_json_is_aggregated_and_fail_closed(self):
        result = self.run_script("json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["checkpoint_type"], "PRIVATE_OFFLINE_STATUS_ONLY")
        self.assertIsInstance(data["roadmap_done"], int)
        self.assertIsInstance(data["roadmap_total"], int)
        self.assertGreater(data["roadmap_total"], 0)
        self.assertGreaterEqual(data["roadmap_total"], data["roadmap_done"])
        self.assertEqual(data["operational_deployment_gate"], "BLOCKED")
        self.assertEqual(data["github_reviews"], "NOT_CHECKED_BY_THIS_SCRIPT")
        self.assertIs(data["writes_performed"], False)
        self.assertFalse(any("evidence_ref" in k for k in data))

    def test_missing_input_does_not_fabricate_evidence(self):
        self.snapshot.unlink()
        self.manifest.unlink()
        data = json.loads(self.run_script("json").stdout)
        self.assertEqual(data["observation_state"], "UNAVAILABLE_OR_INVALID")
        self.assertEqual(data["manifest_state"], "UNAVAILABLE_OR_INVALID")
        self.assertIsNone(data["observed_agents"])
        self.assertIsNone(data["manifest_missing_fields"])
        self.assertEqual(data["operational_deployment_gate"], "BLOCKED")

    def test_invalid_snapshot_and_manifest_fail_closed(self):
        self.snapshot.write_text("{\"schema_version\": 1, \"schema_version\": 1}", encoding="utf-8")
        self.manifest.write_text("{invalid", encoding="utf-8")
        result = self.run_script()
        self.assertEqual(result.returncode, 0)
        self.assertIn("OBSERVATION_STATE=UNAVAILABLE_OR_INVALID", result.stdout)
        self.assertIn("MANIFEST_STATE=UNAVAILABLE_OR_INVALID", result.stdout)
        self.assertIn("OPERATIONAL_DEPLOYMENT_GATE=BLOCKED", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_never_modifies_private_inputs(self):
        old_snapshot = self.snapshot.read_bytes()
        old_manifest = self.manifest.read_bytes()
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual(self.snapshot.read_bytes(), old_snapshot)
        self.assertEqual(self.manifest.read_bytes(), old_manifest)


if __name__ == "__main__":
    unittest.main()
