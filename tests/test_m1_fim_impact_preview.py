"""Synthetic offline tests for the non-authorizing FIM OS impact preview."""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/m1_fim_impact_preview.py"
COLUMNS = ("id", "os", "groups", "status", "sync", "observed_at", "evidence_ref")


def synthetic_agents():
    now = datetime.now(timezone.utc).isoformat()
    return [
        {"id": str(idx).zfill(3),
         "os": "Windows Server 2022" if idx in (2, 4) else "Linux Ubuntu 24.04",
         "groups": "default", "status": "active", "sync": "synced",
         "observed_at": now, "evidence_ref": "PRIVATE_SYNTHETIC_FAKE_SOURCE"}
        for idx in (1, 2, 3, 4)
    ]


class FimOsImpactPreviewTests(unittest.TestCase):
    def setUp(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        self.private = tempfile.TemporaryDirectory(dir=REPO / ".lab", prefix="synthetic-impact-test-")
        self.addCleanup(self.private.cleanup)
        self.folder = Path(self.private.name)
        self.csv = self.folder / "synthetic-operator.csv"
        self.output = self.folder / "synthetic-report.json"

    def write_csv(self, rows=None):
        with self.csv.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(synthetic_agents() if rows is None else rows)

    def invoke(self, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--csv", str(self.csv), *extra],
            capture_output=True, text=True,
        )

    def test_two_linux_two_windows_are_previewed_without_approval(self):
        self.write_csv()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("POTENTIAL_LINUX_MATCHES=2", result.stdout)
        self.assertIn("POTENTIAL_NON_LINUX_EXCLUSIONS=2", result.stdout)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)
        self.assertIn("WAZUH_RUNTIME_SELECTION_CONFIRMED=false", result.stdout)
        self.assertNotIn("PRIVATE_SYNTHETIC_FAKE_SOURCE", result.stdout)

    def test_precedence_hazard_is_reported(self):
        agents = synthetic_agents()
        agents[0]["groups"] = "default;other"
        agents[1]["groups"] = "other;default"
        self.write_csv(agents)
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertIn("MULTI_GROUP_AGENTS=2", result.stdout)
        self.assertIn("DEFAULT_NOT_LAST_IN_GROUP_ORDER=1", result.stdout)
        self.assertIn("REQUIRES_PRECEDENCE_REVIEW=true", result.stdout)

    def test_private_aggregate_file_contains_no_ids_or_references(self):
        self.write_csv()
        result = self.invoke("--output", str(self.output))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(data["potential_linux_matches"], 2)
        self.assertEqual(data["deployment_gate"], "BLOCKED")
        content = self.output.read_text(encoding="utf-8")
        self.assertNotIn("PRIVATE_SYNTHETIC_FAKE_SOURCE", content)
        self.assertNotIn("Ubuntu 24.04", content)

    def test_existing_report_must_not_be_overwritten(self):
        self.write_csv()
        self.output.write_text("sentinel", encoding="utf-8")
        result = self.invoke("--output", str(self.output))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "sentinel")

    def test_csv_outside_private_workspace_rejected(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--csv", str(REPO / "README.md")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_incomplete_inventory_rejected(self):
        self.write_csv(synthetic_agents()[:3])
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("INVENTORY_CSV_STRUCTURE=INVALID_OR_UNREADABLE", result.stdout)

    def test_local_preview_does_not_change_input(self):
        self.write_csv()
        before = self.csv.read_bytes()
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.csv.read_bytes(), before)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
