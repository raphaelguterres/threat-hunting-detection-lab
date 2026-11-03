"""End-to-end synthetic tests for the private, non-authorizing M1 evidence workflow.

All data live in temporary directories under the ignored .lab workspace.
No Wazuh connections, real agents, permissions changes or live deployments.
"""
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
FIELDS = ("id", "os", "groups", "status", "sync", "observed_at", "evidence_ref")


def synthetic_rows():
    observed = datetime.now(timezone.utc).isoformat()
    return [
        {
            "id": f"{i:03d}",
            "os": "Windows Server 2022" if i == 4 else "Linux Ubuntu 24.04",
            "groups": "default;second" if i == 1 else "default",
            "status": "active",
            "sync": "synced",
            "observed_at": observed,
            "evidence_ref": "SYNTHETIC_PRIVATE_TEST_REFERENCE",
        }
        for i in (1, 2, 3, 4)
    ]


class InventoryEndToEndTests(unittest.TestCase):
    def setUp(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(prefix="m1-e2e-synthetic-", dir=REPO / ".lab")
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.csv = self.folder / "synthetic-operator-inventory.csv"
        self.manifest = self.folder / "synthetic-private-manifest.json"

    def write_csv(self, items):
        with self.csv.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(items)

    def run_script(self, name, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / name), *map(str, arguments)],
            capture_output=True, text=True,
        )

    def import_inventory(self, apply=False):
        cmd = ["--csv", self.csv, "--manifest", self.manifest]
        if apply:
            cmd.append("--apply")
        return self.run_script("m1_import_authorized_inventory.py", *cmd)

    def gate(self):
        return self.run_script(
            "m1_evidence_gate.py", "--manifest", self.manifest, "--stage", "prechange"
        )

    def preview(self):
        return self.run_script("m1_fim_impact_preview.py", "--csv", self.csv)

    def test_valid_synthetic_csv_never_grants_operational_approval(self):
        self.write_csv(synthetic_rows())
        dry = self.import_inventory()
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertFalse(self.manifest.exists())
        applied = self.import_inventory(apply=True)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertIn("INDEPENDENT_EVIDENCE_REVIEW_REQUIRED=true", applied.stdout)
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["agents"]), 4)
        self.assertFalse(manifest["checks"])
        gate = self.gate()
        self.assertEqual(gate.returncode, 2)
        self.assertIn("EVIDENCE_SOURCE=PRIVATE_UNATTESTED", gate.stdout)
        self.assertIn("EVIDENCE_COMPLETENESS=INCOMPLETE", gate.stdout)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", gate.stdout)
        self.assertNotIn("SYNTHETIC_PRIVATE_TEST_REFERENCE", gate.stdout)

    def test_changed_group_order_revokes_review_but_preserves_baseline(self):
        items = synthetic_rows()
        self.write_csv(items)
        self.assertEqual(self.import_inventory(apply=True).returncode, 0)
        doc = json.loads(self.manifest.read_text(encoding="utf-8"))
        doc["checks"] = {
            "inventory_review": {"status": "verified", "evidence_ref": "prior-test-review"},
            "group_precedence_review": {"status": "verified", "evidence_ref": "prior-test-priority"},
            "change_approval": {"status": "verified", "evidence_ref": "prior-test-approval"},
            "backup_integrity_real": {"status": "verified", "evidence_ref": "prior-test-hash"},
        }
        self.manifest.write_text(json.dumps(doc), encoding="utf-8")
        items[0]["groups"] = "second;default"
        self.write_csv(items)
        self.assertEqual(self.import_inventory(apply=True).returncode, 0)
        new = json.loads(self.manifest.read_text(encoding="utf-8"))
        for key in ("inventory_review", "group_precedence_review", "change_approval"):
            self.assertEqual(new["checks"][key]["status"], "pending")
            self.assertFalse(new["checks"][key]["evidence_ref"])
        self.assertEqual(new["checks"]["backup_integrity_real"]["status"], "verified")
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", self.gate().stdout)

    def test_invalid_inventory_does_not_modify_existing_manifest(self):
        items = synthetic_rows()
        self.write_csv(items)
        self.assertEqual(self.import_inventory(apply=True).returncode, 0)
        prior = self.manifest.read_bytes()
        self.write_csv(items[:3])
        result = self.import_inventory(apply=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("MANIFEST_UPDATED=False", result.stdout)
        self.assertEqual(self.manifest.read_bytes(), prior)

    def test_preview_is_aggregate_only_and_never_authorizes(self):
        self.write_csv(synthetic_rows())
        result = self.preview()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("POTENTIAL_LINUX_MATCHES=3", result.stdout)
        self.assertIn("POTENTIAL_NON_LINUX_EXCLUSIONS=1", result.stdout)
        self.assertIn("MULTI_GROUP_AGENTS=1", result.stdout)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)
        self.assertNotIn("SYNTHETIC_PRIVATE_TEST_REFERENCE", result.stdout)
        self.assertFalse(self.manifest.exists())

    def test_placeholder_os_is_rejected_consistently(self):
        items = synthetic_rows()
        items[0]["os"] = "Linux"
        self.write_csv(items)
        self.assertEqual(self.import_inventory(apply=True).returncode, 2)
        self.assertEqual(self.preview().returncode, 2)
        self.assertFalse(self.manifest.exists())


if __name__ == "__main__":
    unittest.main()
