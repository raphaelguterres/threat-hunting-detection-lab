"""Offline safety contract for H03 Change C single-directive FIM proposal."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import m1_h03_change_c_offline_diff_gate as gate  # noqa: E402

BASE = r"""<ossec_config>
  <!-- keep existing FIM and local sources intact -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories realtime="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories check_all="yes">C:\Windows\System32</directories>
    <ignore>c:\ignore-sample</ignore>
  </syscheck>
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
"""

TARGET = r'<directories realtime="yes" check_all="yes">C:\SecurityLab\H03</directories>'


def proposal(*additions: str) -> str:
    return BASE.replace("  </syscheck>", "\n".join(additions) + "\n  </syscheck>")


class H03ChangeCDiffTests(unittest.TestCase):
    def test_exact_one_realtime_addition_passes_without_go(self):
        result = gate.compare(BASE.encode(), proposal(TARGET).encode())
        self.assertEqual(result["directive_count_added"], 1)
        self.assertEqual(result["result"], "ONE_FIM_REALTIME_DIRECTORY_ADD_ONLY")
        self.assertFalse(result["go_for_change"])
        self.assertFalse(result["agent_restarted"])
        self.assertFalse(result["target_exists_on_guest_verified"])
        self.assertFalse(result["acl_effective_verified"])

    def test_change_existing_directory_not_allowed(self):
        altered = proposal(TARGET).replace("C:\\Windows\\System32", "C:\\Windows")
        with self.assertRaisesRegex(ValueError, "exceeds"):
            gate.compare(BASE.encode(), altered.encode())

    def test_modify_security_collector_not_allowed(self):
        altered = proposal(TARGET).replace(
            "<location>Security</location>", "<location>System</location>")
        with self.assertRaisesRegex(ValueError, "exceeds"):
            gate.compare(BASE.encode(), altered.encode())

    def test_existing_settings_or_comment_changes_rejected(self):
        for altered in (
            proposal(TARGET).replace("<frequency>43200</frequency>",
                                     "<frequency>600</frequency>"),
            proposal(TARGET).replace("<!-- keep existing FIM and local sources intact -->",
                                     "<!-- edited comment -->"),
            proposal(TARGET).replace("<disabled>no</disabled>",
                                     "<disabled>yes</disabled>"),
        ):
            with self.subTest(altered=altered[:60]):
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    gate.compare(BASE.encode(), altered.encode())

    def test_no_addition_and_duplicate_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            gate.compare(BASE.encode(), BASE.encode())
        with self.assertRaisesRegex(ValueError, "exactly one"):
            gate.compare(BASE.encode(), proposal(TARGET, TARGET).encode())

    def test_realtime_and_check_all_are_required(self):
        for bad in (
            TARGET.replace('realtime="yes"', 'realtime="no"'),
            TARGET.replace(' check_all="yes"', ""),
            TARGET.replace('check_all="yes"', 'check_all="no"'),
            TARGET.replace('realtime="yes"', 'whodata="yes"'),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    gate.compare(BASE.encode(), proposal(bad).encode())

    def test_only_target_path_permitted(self):
        for wrong in (r"C:\Windows\Temp", r"C:\SecurityLab\Other", r"\\server\share\H03"):
            with self.subTest(wrong=wrong):
                with self.assertRaises(ValueError):
                    gate.compare(BASE.encode(), proposal(TARGET.replace(
                        r"C:\SecurityLab\H03", wrong)).encode())

    def test_baseline_already_monitoring_target_is_not_new(self):
        before = proposal(TARGET)
        after = before.replace("</syscheck>", TARGET + "</syscheck>")
        with self.assertRaisesRegex(ValueError, "already monitored"):
            gate.compare(before.encode(), after.encode())

    def test_reject_changed_ancillary_attributes(self):
        with self.assertRaisesRegex(ValueError, "attributes"):
            gate.compare(BASE.encode(), proposal(TARGET.replace(
                'check_all="yes"', 'check_all="yes" report_changes="yes"')).encode())

    def test_reject_invalid_root_or_duplicate_syscheck(self):
        with self.assertRaisesRegex(ValueError, "root"):
            gate.compare(b"<config/>", proposal(TARGET).encode())
        with self.assertRaisesRegex(ValueError, "exactly one syscheck"):
            gate.compare(BASE.encode(), proposal(TARGET).replace(
                "</ossec_config>", "<syscheck/></ossec_config>").encode())

    def test_dtd_and_entity_rejected(self):
        with self.assertRaisesRegex(ValueError, "DTD"):
            gate.compare(BASE.encode(), ("<!DOCTYPE ossec_config>\n" +
                                         proposal(TARGET)).encode())
        with self.assertRaises(Exception):
            gate.compare(b"<ossec_config>", proposal(TARGET).encode())

    def test_cli_synthetic_sources_only(self):
        fixture_root = ROOT / "tests/fixtures"
        fixture_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="h03-synthetic-", dir=fixture_root) as td:
            old = Path(td) / "h03-synthetic-before.xml"
            new = Path(td) / "h03-synthetic-proposal.xml"
            old.write_text(BASE, encoding="utf-8")
            new.write_text(proposal(TARGET), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = gate.main(["--baseline", str(old), "--candidate", str(new),
                                "--fixture"])
            self.assertEqual(rc, 0)
            self.assertIn('"evidence": "SYNTHETIC_FIXTURE"', output.getvalue())
            self.assertIn('"go_for_change": false', output.getvalue())
            self.assertNotIn(str(old), output.getvalue())
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                rc = gate.main(["--baseline", str(old), "--candidate", str(new)])
            self.assertEqual(rc, 2)
            self.assertIn("NO_GO_UNVERIFIED", errors.getvalue())

    def test_public_repo_file_not_accepted_as_evidence(self):
        with self.assertRaises(ValueError):
            gate.protected_file(ROOT / "README.md", fixture=False)
        with self.assertRaises(ValueError):
            gate.protected_file(ROOT / "README.md", fixture=True)


if __name__ == "__main__":
    unittest.main()
