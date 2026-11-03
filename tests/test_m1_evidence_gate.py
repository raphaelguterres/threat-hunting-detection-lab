"""Contract tests for the non-deploying, fail-closed M1 evidence gate."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "m1_evidence_gate.py"
spec = importlib.util.spec_from_file_location("m1_evidence_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def example():
    agents = [
        {"id": str(i).zfill(3), "os": "Windows Server 2022" if i == 4 else "Linux",
         "groups": ["default"], "sync": "synced", "evidence_ref": "private review"}
        for i in (1, 2, 3, 4)
    ]
    checks = {name: {"status": "verified", "evidence_ref": "private review"}
              for name in gate.PRECHANGE + gate.POSTCHANGE}
    return {"schema_version": 1, "change_id": "M1-FIM-OS-SCOPE",
            "agents": agents, "checks": checks}


class M1GateTests(unittest.TestCase):
    def test_complete_prechange_is_still_not_deploy_authorization(self):
        complete, missing = gate.assess(example())
        self.assertTrue(complete)
        self.assertEqual(missing, [])

    def test_complete_postchange_requires_extra_checks(self):
        complete, _ = gate.assess(example(), "postchange")
        self.assertTrue(complete)
        document = example()
        del document["checks"]["discover_visibility"]
        self.assertFalse(gate.assess(document, "postchange")[0])

    def test_three_agents_are_blocked(self):
        document = example()
        document["agents"].pop()
        self.assertIn("agents_exactly_four", gate.assess(document)[1])

    def test_duplicate_id_is_blocked(self):
        document = example()
        document["agents"][1]["id"] = "001"
        self.assertFalse(gate.assess(document)[0])

    def test_other_group_is_blocked(self):
        document = example()
        document["agents"][0]["groups"] = ["other"]
        self.assertFalse(gate.assess(document)[0])

    def test_unknown_sync_is_blocked(self):
        document = example()
        document["agents"][0]["sync"] = "unknown"
        self.assertFalse(gate.assess(document)[0])

    def test_wrong_004_os_is_blocked(self):
        document = example()
        document["agents"][-1]["os"] = "Linux"
        self.assertIn("agent_004_windows_expected", gate.assess(document)[1])

    def test_missing_004_is_blocked(self):
        document = example()
        document["agents"][-1]["id"] = "005"
        self.assertIn("agent_004_not_reconciled", gate.assess(document)[1])

    def test_absent_real_backup_or_human_approval_is_blocked(self):
        document = example()
        document["checks"]["backup_integrity_real"]["status"] = "pending"
        document["checks"]["change_approval"]["status"] = "pending"
        missing = gate.assess(document)[1]
        self.assertIn("backup_integrity_real", missing)
        self.assertIn("change_approval", missing)

    def test_synthetic_rollback_is_not_real_evidence(self):
        document = example()
        document["checks"]["rollback_rehearsal_real"]["status"] = "synthetic"
        self.assertFalse(gate.assess(document)[0])

    def test_bad_types_fail_closed(self):
        self.assertFalse(gate.assess(None)[0])
        self.assertFalse(gate.assess({"schema_version": "1"})[0])

    def test_public_path_denied_unless_fixture(self):
        self.assertFalse(gate.private_or_fixture(REPO / "README.md", False))
        self.assertFalse(gate.private_or_fixture(REPO / "README.md", True))
        self.assertTrue(gate.private_or_fixture(REPO / "tests/fixtures/m1-example-synthetic.json", True))

    def test_missing_manifest_cli_returns_nonzero_and_blocked(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_windows_utf8_bom_manifest_supported(self):
        # Windows PowerShell 5.1 Set-Content -Encoding UTF8 writes a UTF-8 BOM.
        with tempfile.TemporaryDirectory(prefix="m1-evidence-bom-synthetic-", dir=REPO / "tests/fixtures") as folder:
            source = Path(folder) / "m1-evidence-bom-synthetic.json"
            source.write_text(json.dumps(example()), encoding="utf-8-sig")
            result = subprocess.run([sys.executable, str(SCRIPT), "--manifest", str(source), "--fixture"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("EVIDENCE_COMPLETENESS=REVIEW_READY", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_no_real_evidence_is_printed(self):
        document = example()
        secret = "private-SENSITIVE-MOCK-VALUE"
        document["agents"][0]["evidence_ref"] = secret
        self.assertTrue(gate.assess(document)[0])
        self.assertNotIn(secret, str(gate.assess(document)))


if __name__ == "__main__":
    unittest.main()
