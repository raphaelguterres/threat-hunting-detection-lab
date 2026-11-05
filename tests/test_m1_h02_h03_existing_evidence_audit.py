"""Synthetic regression tests for H02/H03 offline historical evidence review."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import m1_h02_h03_existing_evidence_audit as aud  # noqa: E402

H02 = """M1_H02_SECURITY_AUDIT 2026-10-31T00:00Z_TO_2026-11-03T00:00Z
account_created_events=1
account_events_with_target_sid=1
privileged_logons_same_sid_30m=0
successful_logons_same_sid_30m=0
matching_4624_4672_logon_id_chains=0
interpretation=potential_observational_chain_only_not_incident
"""
FIM = {
    "agent_id": "004", "event_counts": {"added": 1, "modified": 1, "deleted": 1},
    "file_extension": ".m1probe", "exact_artifact_hits": 3,
    "guest_cleanup_verified": True, "config_changes": False,
    "service_restart": False, "auditpol_changed": False,
    "local_manager_log_independently_verified": False,
}
H03 = {
    "agent_id": "004", "status": "READONLY_PARTIAL",
    "target_exists": False, "parent_exists": False, "security_gate": "NO_GO",
    "operator_review_required": True,
    "effective_fim_coverage_of_future_target": "not_present_currently",
    "local_directories": 6, "local_realtime_directories": 1,
}


class ExistingEvidenceTests(unittest.TestCase):
    def review(self, source=H02, fim=None, h03=None):
        return aud.audit(aud.parse_h02(source), fim if fim is not None else dict(FIM),
                         h03 if h03 is not None else dict(H03))

    def test_h02_historical_no_match_not_false_clearance(self):
        r = self.review()
        self.assertEqual(r["h02"]["account_created_events"], 1)
        self.assertEqual(r["h02"]["status"], "NO_SAME_SID_CHAIN_IN_HISTORICAL_SAMPLE")
        self.assertFalse(r["h02"]["account_compromise_assessed"])
        self.assertFalse(r["review_limitations"]["h02_source_identity_revalidated"])

    def test_h03_fim_not_execution(self):
        r = self.review()
        self.assertEqual(r["h03"]["benign_fim_added_modified_deleted"], [1, 1, 1])
        self.assertFalse(r["h03"]["fim_probe_executable"])
        self.assertFalse(r["h03"]["same_artifact_execution_attested"])
        self.assertFalse(r["h03"]["fim_then_same_executable_pair_verified"])
        self.assertEqual(r["h03"]["change_c_gate_on_baseline"], "NO_GO")

    def test_h02_window_must_not_be_silently_changed(self):
        with self.assertRaisesRegex(ValueError, "window"):
            aud.parse_h02(H02.replace("2026-11-03", "2026-11-05"))

    def test_h02_missing_duplicate_and_negative_counts_rejected(self):
        variants = (
            H02.replace("account_created_events=1\n", ""),
            H02 + "\naccount_created_events=1\n",
            H02.replace("account_created_events=1", "account_created_events=-1"),
            H02.replace("account_created_events=1", "account_created_events=NaN"),
        )
        for item in variants:
            with self.subTest(content=item[:95]):
                with self.assertRaises(ValueError):
                    aud.parse_h02(item)

    def test_h02_more_sids_than_creation_rejected(self):
        with self.assertRaises(ValueError):
            aud.parse_h02(H02.replace("account_events_with_target_sid=1",
                                      "account_events_with_target_sid=3"))

    def test_nonzero_h02_match_not_automatically_accepted(self):
        s = H02.replace("privileged_logons_same_sid_30m=0",
                        "privileged_logons_same_sid_30m=1")
        r = self.review(source=s)
        self.assertEqual(r["h02"]["status"], "H02_REQUIRES_IDENTITY_LEVEL_INDEPENDENT_REVIEW")
        self.assertFalse(r["review_limitations"]["h02_source_identity_revalidated"])

    def test_reject_h03_executable_assertion_from_fim_text_probe(self):
        fim = dict(FIM, file_extension=".exe")
        with self.assertRaisesRegex(ValueError, "non-executable"):
            self.review(fim=fim)

    def test_reject_wrong_agent_or_malformed_fim_operations(self):
        with self.assertRaises(ValueError):
            self.review(fim=dict(FIM, agent_id="005"))
        with self.assertRaises(ValueError):
            self.review(h03=dict(H03, agent_id="002"))
        with self.assertRaises(ValueError):
            self.review(fim=dict(FIM, event_counts={"added": 3}))
        with self.assertRaises(ValueError):
            self.review(fim=dict(FIM, exact_artifact_hits=9))
        with self.assertRaises(ValueError):
            self.review(fim=dict(FIM, event_counts=dict(FIM["event_counts"], added=True)))

    def test_reject_historical_baseline_claiming_approved(self):
        for changed in (
            dict(H03, security_gate="GO"),
            dict(H03, target_exists=True),
            dict(H03, operator_review_required=False),
            dict(H03, effective_fim_coverage_of_future_target="verified"),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    self.review(h03=changed)

    def test_reject_false_provenance_and_cleanup(self):
        for changed in (
            dict(FIM, guest_cleanup_verified=False),
            dict(FIM, local_manager_log_independently_verified=True),
            dict(FIM, config_changes=True),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    self.review(fim=changed)

    def test_json_duplicate_and_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            aud.parse_json('{"agent_id":"004","agent_id":"005"}')
        with self.assertRaises(ValueError):
            aud.parse_json('{"val":NaN}')
        with self.assertRaises(ValueError):
            aud.parse_json('["not an object"]')

    def test_cli_synthetic_only_does_not_leak_private_evidence(self):
        base = ROOT / "tests/fixtures"
        base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m1-h02-h03-synthetic-", dir=base) as td:
            items = [Path(td) / n for n in (
                "h02-synthetic.txt", "fim-synthetic.json", "h03-synthetic.json")]
            items[0].write_text(H02, encoding="utf-8")
            items[1].write_text(json.dumps(FIM), encoding="utf-8")
            items[2].write_text(json.dumps(H03), encoding="utf-8")
            args = ["--h02", str(items[0]), "--fim", str(items[1]),
                    "--h03", str(items[2])]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = aud.main(args + ["--fixture"])
            self.assertEqual(code, 0)
            self.assertIn('"evidence_mode": "SYNTHETIC_FIXTURES"', out.getvalue())
            self.assertNotIn(str(td), out.getvalue())
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                rc = aud.main(args)
            self.assertEqual(rc, 2)
            self.assertNotIn(str(td), error.getvalue())

    def test_reject_repository_document_as_private_input(self):
        with self.assertRaises(ValueError):
            aud.safe_file(ROOT / "README.md", ROOT / ".lab")

    def test_h03_remaining_lacuna_is_not_incident(self):
        r = self.review()
        self.assertEqual(r["result"], "HISTORICAL_EVIDENCE_REVIEW_NOT_FULL_CORRELATION")
        self.assertFalse(r["review_limitations"]["manager_alert_json_accessed"])
        self.assertFalse(r["review_limitations"]["new_test_events_generated"])
        self.assertFalse(r["review_limitations"]["production_or_change_a_approval"])


if __name__ == "__main__":
    unittest.main()
