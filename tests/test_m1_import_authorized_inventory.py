"""Offline regression coverage for operator-provided (never auto-collected) Wazuh inventory."""
import csv
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/m1_import_authorized_inventory.py"
spec = importlib.util.spec_from_file_location("m1_import", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def rows():
    return [
        {
            "id": str(i).zfill(3),
            "os": "Windows Server 2022" if i == 4 else "Linux Ubuntu 24.04",
            "groups": "default", "status": "active", "sync": "synced",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "evidence_ref": "synthetic-private-review",
        }
        for i in (1, 2, 3, 4)
    ]


class AuthorizedInventoryImportTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".lab").mkdir(exist_ok=True)
        self.sandbox = tempfile.TemporaryDirectory(prefix="m1-import-synthetic-", dir=ROOT / ".lab")
        self.addCleanup(self.sandbox.cleanup)
        self.dir = Path(self.sandbox.name)
        self.csv_path = self.dir / "manual-inventory.csv"
        self.manifest = self.dir / "private-manifest.json"

    def write_csv(self, items=None, fields=None):
        with self.csv_path.open("w", encoding="utf-8-sig", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=fields or inventory.COLUMNS)
            writer.writeheader()
            writer.writerows(rows() if items is None else items)

    def invoke(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--csv", str(self.csv_path),
             "--manifest", str(self.manifest), *args],
            capture_output=True, text=True,
        )

    def test_preview_never_writes_manifest(self):
        self.write_csv()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CSV_STRUCTURE=VALID", result.stdout)
        self.assertIn("MANIFEST_UPDATED=False", result.stdout)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)
        self.assertFalse(self.manifest.exists())

    def test_explicit_apply_preserves_prior_checks(self):
        self.write_csv()
        original = {"schema_version": 1, "change_id": "M1-FIM-OS-SCOPE",
                    "checks": {"inventory_review": {"status": "pending", "evidence_ref": ""}}}
        self.manifest.write_text(json.dumps(original), encoding="utf-8")
        result = self.invoke("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MANIFEST_UPDATED=True", result.stdout)
        updated = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(len(updated["agents"]), 4)
        self.assertEqual(updated["checks"], original["checks"])

    def test_new_inventory_revokes_dependent_approvals(self):
        self.write_csv()
        document = {
            "schema_version": 1, "change_id": "M1-FIM-OS-SCOPE",
            "agents": [{"id": "999", "os": "Linux"}],
            "checks": {
                "inventory_review": {"status": "verified", "evidence_ref": "prior-review"},
                "os_impact_review": {"status": "verified", "evidence_ref": "prior-impact"},
                "group_precedence_review": {"status": "verified", "evidence_ref": "prior-priority-review"},
                "change_approval": {"status": "verified", "evidence_ref": "prior-approval"},
                "approved_window": {"status": "verified", "evidence_ref": "prior-window"},
                "windows_fim": {"status": "verified", "evidence_ref": "prior-fim"},
                "backup_integrity_real": {"status": "verified", "evidence_ref": "same-baseline"},
            },
        }
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = self.invoke("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        updated = json.loads(self.manifest.read_text(encoding="utf-8"))
        for name in ("inventory_review", "os_impact_review", "group_precedence_review", "change_approval", "approved_window", "windows_fim"):
            self.assertEqual(updated["checks"][name]["status"], "pending")
            self.assertFalse(updated["checks"][name]["evidence_ref"])
        self.assertEqual(updated["checks"]["backup_integrity_real"]["status"], "verified")

    def test_group_priority_change_invalidates_prior_approval(self):
        self.write_csv()
        first = rows()
        first[0]["groups"] = "other;default"
        self.write_csv(first)
        result = self.invoke("--apply")
        self.assertEqual(result.returncode, 0)
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["checks"]["group_precedence_review"] = {
            "status": "verified", "evidence_ref": "prior-review"
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        first[0]["groups"] = "default;other"
        self.write_csv(first)
        result = self.invoke("--apply")
        self.assertEqual(result.returncode, 0)
        updated = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(updated["checks"]["group_precedence_review"]["status"], "pending")

    def test_existing_duplicate_manifest_keys_rejected_without_overwrite(self):
        self.write_csv()
        original = '{"schema_version":1,"change_id":"M1-FIM-OS-SCOPE","checks":{},"checks":{}}'
        self.manifest.write_text(original, encoding="utf-8")
        self.assertEqual(self.invoke("--apply").returncode, 2)
        self.assertEqual(self.manifest.read_text(encoding="utf-8"), original)

    def test_boolean_manifest_schema_rejected(self):
        self.write_csv()
        original = '{"schema_version":true,"change_id":"M1-FIM-OS-SCOPE","checks":{}}'
        self.manifest.write_text(original, encoding="utf-8")
        self.assertEqual(self.invoke("--apply").returncode, 2)
        self.assertEqual(self.manifest.read_text(encoding="utf-8"), original)

    def test_duplicate_agents_rejected(self):
        items = rows()
        items[1]["id"] = "001"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)
        self.assertFalse(self.manifest.exists())

    def test_wrong_agent_count_rejected(self):
        self.write_csv(rows()[:3])
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_agent_004_must_be_windows(self):
        items = rows()
        items[-1]["os"] = "Linux"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_no_guessing_os(self):
        items = rows()
        items[0]["os"] = "UNKNOWN"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_duplicate_default_group_is_rejected(self):
        items = rows()
        items[0]["groups"] = "default;default"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_inventory_from_different_time_windows_is_rejected(self):
        items = rows()
        items[0]["observed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_other_group_is_rejected(self):
        items = rows()
        items[0]["groups"] = "other"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_unsynced_agents_are_blocked(self):
        items = rows()
        items[0]["sync"] = "unknown"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_missing_evidence_rejected(self):
        items = rows()
        items[0]["evidence_ref"] = ""
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_timestamp_requires_timezone(self):
        items = rows()
        items[0]["observed_at"] = "2026-11-02T23:45:00"
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_stale_inventory_rejected(self):
        items = rows()
        items[0]["observed_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_future_dated_inventory_rejected(self):
        items = rows()
        items[0]["observed_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.write_csv(items)
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_csv_outside_private_path_rejected(self):
        public_path = ROOT / "README.md"
        self.csv_path = public_path
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_wrong_header_rejected(self):
        self.csv_path.write_text("id,os\n004,Windows Server 2022\n", encoding="utf-8")
        self.assertEqual(self.invoke("--apply").returncode, 2)

    def test_does_not_print_private_reference(self):
        items = rows()
        items[0]["evidence_ref"] = "PRIVATE-MOCK-EVIDENCE-TOKEN"
        self.write_csv(items)
        result = self.invoke()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("PRIVATE-MOCK-EVIDENCE-TOKEN", result.stdout)


if __name__ == "__main__":
    unittest.main()
