"""Owner-scoped continuation contract: never turns missing Manager proof into PASS."""
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "m1_evidence_gate.py"
spec = importlib.util.spec_from_file_location("m1_evidence_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def waiver(start=None):
    now = start or datetime.now(timezone.utc)
    return {
        "schema_version": 1,
        "change_id": "M1-FIM-OS-SCOPE",
        "scope": "isolated_lab_offline_and_readonly_continuation",
        "authorized_by": "project_owner_in_chat",
        "source": "explicit_owner_instruction_2026-11-05",
        "environment": "local_isolated_lab",
        "pending_checks": ["manager_ingestion"],
        "manager_ingestion_verified": False,
        "independent_review_verified": False,
        "rollback_preserved": True,
        "configuration_changes_authorized": False,
        "production_deployment_authorized": False,
        "approved_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=24)).isoformat(),
    }


def evidence():
    now = datetime.now(timezone.utc).isoformat()
    agents = [
        {"id": "002", "os": "Linux Ubuntu 24.04", "groups": ["default"],
         "sync": "synced", "status": "active", "observed_at": now, "evidence_ref": "private_agent_002"},
        {"id": "004", "os": "Windows Server 2022", "groups": ["default"],
         "sync": "synced", "status": "active", "observed_at": now, "evidence_ref": "private_agent_004"},
        {"id": "005", "os": "Linux Ubuntu 24.04", "groups": ["default"],
         "sync": "synced", "status": "active", "observed_at": now, "evidence_ref": "private_agent_005"},
    ]
    checks = {name: {"status": "verified", "evidence_ref": "private_review"}
              for name in gate.PRECHANGE + gate.POSTCHANGE}
    checks["manager_ingestion"] = {"status": "pending", "evidence_ref": ""}
    return {"schema_version": 1, "change_id": "M1-FIM-OS-SCOPE",
            "agents": agents, "checks": checks}


class OwnerContinuationTests(unittest.TestCase):
    def test_valid_declared_waiver_with_exactly_manager_missing(self):
        self.assertTrue(gate.valid_owner_continuation(waiver(), ["manager_ingestion"]))

    def test_no_general_or_production_permission(self):
        for key, value in (
            ("scope", "production"), ("environment", "production"),
            ("configuration_changes_authorized", True),
            ("production_deployment_authorized", True),
            ("manager_ingestion_verified", True),
            ("independent_review_verified", True),
            ("rollback_preserved", False),
            ("authorized_by", "unknown"),
        ):
            with self.subTest(key=key):
                data = waiver()
                data[key] = value
                self.assertFalse(gate.valid_owner_continuation(data, ["manager_ingestion"]))

    def test_other_missing_checks_fail_closed(self):
        for names in ([], ["linux_fim"], ["manager_ingestion", "discover_visibility"],
                      ["agent_1_observation_freshness", "manager_ingestion"]):
            self.assertFalse(gate.valid_owner_continuation(waiver(), names))

    def test_expired_future_or_overlong_waiver_denied(self):
        now = datetime.now(timezone.utc)
        expired = waiver(now - timedelta(days=2))
        future = waiver(now + timedelta(minutes=30))
        too_long = waiver()
        too_long["expires_at"] = (now + timedelta(days=3)).isoformat()
        for item in (expired, future, too_long):
            self.assertFalse(gate.valid_owner_continuation(item, ["manager_ingestion"]))

    def test_wrong_schema_and_naive_timestamp_denied(self):
        x = waiver()
        x["schema_version"] = True
        self.assertFalse(gate.valid_owner_continuation(x, ["manager_ingestion"]))
        x = waiver()
        x["approved_at"] = "2026-11-05T14:00:00"
        self.assertFalse(gate.valid_owner_continuation(x, ["manager_ingestion"]))

    def test_cli_private_scoped_waiver_only_opens_continuation(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owner-scoped-m1-", dir=REPO / ".lab") as folder:
            base = Path(folder)
            manifest = base / "evidence.json"
            exception = base / "owner-waiver.json"
            manifest.write_text(json.dumps(evidence()), encoding="utf-8")
            exception.write_text(json.dumps(waiver()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stage", "postchange",
                 "--manifest", str(manifest), "--owner-continuation", str(exception)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("MISSING_OR_UNVERIFIED=manager_ingestion", result.stdout)
            self.assertIn("EVIDENCE_COMPLETENESS=INCOMPLETE", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=OWNER_SCOPED_LAB_CONTINUATION", result.stdout)
            self.assertIn("PROJECT_CONTINUATION_GATE=OPEN", result.stdout)
            self.assertIn("PRODUCTION_DEPLOYMENT_GATE=BLOCKED", result.stdout)
            self.assertIn("CHANGE_A_FINAL_ACCEPTANCE=PENDING_MANAGER_AND_REVIEW", result.stdout)
            no_waiver = subprocess.run(
                [sys.executable, str(SCRIPT), "--stage", "postchange",
                 "--manifest", str(manifest)], capture_output=True, text=True)
            self.assertEqual(no_waiver.returncode, 2)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", no_waiver.stdout)

    def test_cli_rejects_unapproved_extra_missing_check(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="owner-extra-m1-", dir=REPO / ".lab") as folder:
            base = Path(folder)
            data = evidence()
            data["checks"]["linux_fim"]["status"] = "pending"
            a, b = base / "evidence.json", base / "waiver.json"
            a.write_text(json.dumps(data), encoding="utf-8")
            b.write_text(json.dumps(waiver()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stage", "postchange",
                 "--manifest", str(a), "--owner-continuation", str(b)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)


if __name__ == "__main__":
    unittest.main()
