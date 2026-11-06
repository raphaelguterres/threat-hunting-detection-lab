"""Contract tests for the non-deploying, fail-closed M1 evidence gate."""
from datetime import datetime, timedelta, timezone
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
        {"id": str(i).zfill(3), "os": "Windows Server 2022" if i == 4 else "Linux Ubuntu 24.04",
         "groups": ["default"], "sync": "synced", "status": "active",
         "observed_at": datetime.now(timezone.utc).isoformat(),
         "evidence_ref": "private review"}
        for i in (2, 4, 5)
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

    def test_two_agents_are_blocked(self):
        document = example()
        document["agents"].pop()
        self.assertIn("agents_exactly_three", gate.assess(document)[1])

    def test_duplicate_id_is_blocked(self):
        document = example()
        document["agents"][1]["id"] = "001"
        self.assertFalse(gate.assess(document)[0])

    def test_duplicate_group_in_manifest_is_blocked(self):
        document = example()
        document["agents"][0]["groups"] = ["default", "default"]
        self.assertIn("agent_1_groups_valid_unique_default", gate.assess(document)[1])

    def test_dashboard_os_labels_are_valid_but_not_deploy_permission(self):
        document = example()
        document["agents"][0]["os"] = "Amazon Linux 2023"
        document["agents"][1]["os"] = "Kali GNU/Linux 2025.3"
        document["agents"][1]["os"] = "Microsoft Windows Server 2022 Standard Evaluation 10.0.20348.587"
        self.assertTrue(gate.assess(document)[0])
        document["agents"][0]["status"] = "disconnected"
        self.assertIn("agent_1_status", gate.assess(document)[1])

    def test_missing_os_version_in_manifest_is_blocked(self):
        for value in ("Linux", "Windows", "macOS", "LinuxUbuntu24.04", "Linux Ubuntu TBD 24.04"):
            with self.subTest(os=value):
                document = example()
                document["agents"][0]["os"] = value
                self.assertIn("agent_1_os_version", gate.assess(document)[1])

    def test_placeholder_evidence_reference_is_blocked(self):
        document = example()
        document["agents"][0]["evidence_ref"] = "UNVERIFIED evidence"
        self.assertIn("agent_1_evidence", gate.assess(document)[1])

    def test_underscore_placeholder_evidence_is_blocked(self):
        document = example()
        document["agents"][0]["evidence_ref"] = "UNVERIFIED_001"
        self.assertIn("agent_1_evidence", gate.assess(document)[1])

    def test_incoherent_observation_window_is_blocked(self):
        document = example()
        document["agents"][0]["observed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
        self.assertIn("inventory_time_coherence", gate.assess(document)[1])

    def test_other_group_is_blocked(self):
        document = example()
        document["agents"][0]["groups"] = ["other"]
        self.assertFalse(gate.assess(document)[0])

    def test_old_agent_observation_is_blocked_even_after_import(self):
        document = example()
        document["agents"][0]["observed_at"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        self.assertIn("agent_1_observation_freshness", gate.assess(document)[1])

    def test_naive_timestamp_is_blocked(self):
        document = example()
        document["agents"][0]["observed_at"] = "2026-11-02T23:00:00"
        self.assertIn("agent_1_observation_freshness", gate.assess(document)[1])

    def test_future_agent_observation_is_blocked(self):
        document = example()
        document["agents"][0]["observed_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.assertIn("agent_1_observation_freshness", gate.assess(document)[1])

    def test_inactive_agent_is_blocked(self):
        document = example()
        document["agents"][0]["status"] = "inactive"
        self.assertIn("agent_1_status", gate.assess(document)[1])

    def test_unknown_sync_is_blocked(self):
        document = example()
        document["agents"][0]["sync"] = "unknown"
        self.assertFalse(gate.assess(document)[0])

    def test_wrong_004_os_is_blocked(self):
        document = example()
        document["agents"][1]["os"] = "Linux"
        self.assertIn("agent_004_windows_expected", gate.assess(document)[1])

    def test_missing_004_is_blocked(self):
        document = example()
        document["agents"][1]["id"] = "005"
        self.assertIn("agent_004_not_reconciled", gate.assess(document)[1])

    def test_unapproved_default_scope_is_blocked(self):
        document = example()
        document["agents"][-1]["id"] = "001"
        self.assertIn("default_scope_expected_ids", gate.assess(document)[1])

    def test_group_precedence_review_is_required_even_if_single_group(self):
        document = example()
        document["checks"].pop("group_precedence_review")
        self.assertIn("group_precedence_review", gate.assess(document)[1])

    def test_multi_group_agent_requires_review_reference(self):
        document = example()
        document["agents"][0]["groups"] = ["default", "other"]
        document["checks"]["group_precedence_review"] = {"status": "pending", "evidence_ref": ""}
        self.assertIn("group_precedence_review", gate.assess(document)[1])

    def test_absent_real_backup_or_human_approval_is_blocked(self):
        document = example()
        document["checks"]["backup_integrity_real"]["status"] = "pending"
        document["checks"]["change_approval"]["status"] = "pending"
        missing = gate.assess(document)[1]
        self.assertIn("backup_integrity_real", missing)
        self.assertIn("change_approval", missing)

    def test_review_checks_reject_placeholder_and_unsafe_references(self):
        for item in gate.PRECHANGE + gate.POSTCHANGE:
            for ref in ("UNVERIFIED_001", "pending-review", "placeholder", "review\ninvalid",
                        "private review " , "x" * 257):
                with self.subTest(check=item, ref=repr(ref)):
                    doc = example()
                    doc["checks"][item]["evidence_ref"] = ref
                    self.assertIn(item, gate.assess(doc, "postchange")[1])

    def test_review_checks_accept_well_formed_ref_but_never_authorize_deploy(self):
        doc = example()
        doc["checks"]["change_approval"]["evidence_ref"] = "private_review_record_20261103"
        self.assertTrue(gate.assess(doc)[0])
        self.assertTrue(gate.valid_review_reference("private_review_record_20261103"))
        self.assertFalse(gate.valid_review_reference("UNVERIFIED_001"))

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
        with tempfile.TemporaryDirectory(prefix="m1-allowed-synthetic-", dir=REPO / "tests/fixtures") as folder:
            source = Path(folder) / "m1-existing-synthetic.json"
            source.write_text("{}", encoding="utf-8")
            self.assertTrue(gate.private_or_fixture(source, True))

    def test_private_symlinked_manifest_is_denied(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m1-links-", dir=REPO / ".lab") as folder:
            target = Path(folder) / "private-evidence.json"
            target.write_text("{}", encoding="utf-8")
            link = Path(folder) / "private-alias.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation not permitted on this platform")
            self.assertFalse(gate.private_or_fixture(link, False))

    def test_missing_fixture_and_directory_are_denied(self):
        self.assertFalse(gate.private_or_fixture(REPO / "tests/fixtures/nonexistent-synthetic.json", True))
        self.assertFalse(gate.private_or_fixture(REPO / "tests/fixtures", True))

    def test_oversized_manifest_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory(prefix="m1-oversize-synthetic-", dir=REPO / "tests/fixtures") as folder:
            source = Path(folder) / "oversize-synthetic.json"
            source.write_bytes(b"{" + b" " * gate.MAX_MANIFEST_BYTES + b"}")
            result = subprocess.run([sys.executable, str(SCRIPT), "--manifest", str(source), "--fixture"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVIDENCE=UNAVAILABLE_OR_DISALLOWED", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_deeply_nested_manifest_fails_closed_without_traceback(self):
        with tempfile.TemporaryDirectory(prefix="m1-nested-synthetic-", dir=REPO / "tests/fixtures") as folder:
            source = Path(folder) / "nested-synthetic.json"
            source.write_text("[" * 2000 + "0" + "]" * 2000, encoding="utf-8")
            result = subprocess.run([sys.executable, str(SCRIPT), "--manifest", str(source), "--fixture"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)
            self.assertNotIn("Traceback", result.stderr)

    def test_allowed_small_private_manifest_file(self):
        (REPO / ".lab").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m1-small-evidence-", dir=REPO / ".lab") as folder:
            source = Path(folder) / "small-evidence.json"
            source.write_text("{}", encoding="utf-8")
            self.assertTrue(gate.private_or_fixture(source, False))

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
            self.assertIn("EVIDENCE_SOURCE=SYNTHETIC_FIXTURE", result.stdout)
            self.assertIn("EVIDENCE_COMPLETENESS=SYNTHETIC_VALIDATED", result.stdout)
            self.assertNotIn("EVIDENCE_COMPLETENESS=REVIEW_READY", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_incomplete_fixture_never_claims_operator_review_readiness(self):
        with tempfile.TemporaryDirectory(prefix="m1-incomplete-synthetic-", dir=REPO / "tests/fixtures") as folder:
            source = Path(folder) / "incomplete-synthetic.json"
            source.write_text(json.dumps({"schema_version": 1, "change_id": "M1-FIM-OS-SCOPE",
                                          "agents": [], "checks": {}}), encoding="utf-8")
            result = subprocess.run([sys.executable, str(SCRIPT), "--manifest", str(source), "--fixture"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVIDENCE_SOURCE=SYNTHETIC_FIXTURE", result.stdout)
            self.assertIn("EVIDENCE_COMPLETENESS=SYNTHETIC_INCOMPLETE", result.stdout)
            self.assertNotIn("EVIDENCE_COMPLETENESS=REVIEW_READY", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_boolean_schema_version_rejected(self):
        document = example()
        document["schema_version"] = True
        self.assertFalse(gate.assess(document)[0])

    def test_blank_approval_evidence_rejected(self):
        document = example()
        document["checks"]["change_approval"]["evidence_ref"] = "   "
        self.assertIn("change_approval", gate.assess(document)[1])

    def test_unapproved_os_value_rejected(self):
        document = example()
        document["agents"][0]["os"] = "UNKNOWN"
        self.assertFalse(gate.assess(document)[0])

    def test_traversal_outside_private_evidence_rejected(self):
        self.assertFalse(gate.private_or_fixture(REPO / ".lab/../README.md", False))
        self.assertFalse(gate.private_or_fixture(REPO / "tests/fixtures/../../README.md", True))

    def test_duplicate_json_key_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="m1-dupe-synthetic-", dir=REPO / "tests/fixtures") as folder:
            path = Path(folder) / "duplicate-synthetic.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--manifest", str(path), "--fixture"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVIDENCE=UNREADABLE", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_nonfinite_json_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="m1-nan-synthetic-", dir=REPO / "tests/fixtures") as folder:
            path = Path(folder) / "nonfinite-synthetic.json"
            path.write_text('{"schema_version":NaN}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--manifest", str(path), "--fixture"],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVIDENCE=UNREADABLE", result.stdout)
            self.assertIn("DEPLOYMENT_GATE=BLOCKED", result.stdout)

    def test_no_real_evidence_is_printed(self):
        document = example()
        secret = "private-SENSITIVE-MOCK-VALUE"
        document["agents"][0]["evidence_ref"] = secret
        self.assertTrue(gate.assess(document)[0])
        self.assertNotIn(secret, str(gate.assess(document)))


if __name__ == "__main__":
    unittest.main()
