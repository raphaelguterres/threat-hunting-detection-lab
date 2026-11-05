"""Synthetic H01 active-rule contract checks; never runs PowerShell or Wazuh."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import m1_h01_rule_scope_audit as scope  # noqa: E402

VALID_XML = r"""<group name="local,windows,attack,">
  <rule id="110100" level="12">
    <if_sid>61603,92057</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(?:^|\s)-(?:enc|encodedcommand)\s+</field>
    <description>PowerShell started with an encoded command</description>
  </rule>
</group>
"""


class H01RuleScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / ".lab").mkdir(exist_ok=True)

    def test_authored_scope_reports_prior_file_does_not_alert(self):
        result = scope.check_scope(VALID_XML.encode())
        self.assertEqual(result["rule_level"], 12)
        self.assertEqual(result["scope"], "encoded_powershell_only")
        self.assertIs(result["prior_benign_file_matches"], False)
        self.assertIs(result["encoded_invocations_match"], True)
        self.assertEqual(result["synthetic_vectors_passed"], 5)
        self.assertIs(result["runtime_rule_loading_attested"], False)

    def test_reject_too_permissive_rule(self):
        bad = VALID_XML.replace("-(?:enc|encodedcommand)", "-(?:file|enc|encodedcommand)")
        with self.assertRaisesRegex(ValueError, "matcher drift"):
            scope.check_scope(bad.encode())

    def test_reject_inconsistent_parents(self):
        for value in ("61603", "61603,92056", "92057,61603"):
            with self.subTest(value=value):
                bad = VALID_XML.replace("61603,92057", value)
                with self.assertRaisesRegex(ValueError, "parent"):
                    scope.check_scope(bad.encode())

    def test_reject_rule_severity_changes(self):
        for level in ("0", "3", "13"):
            bad = VALID_XML.replace('level="12"', f'level="{level}"')
            with self.subTest(level=level):
                with self.assertRaisesRegex(ValueError, "severity"):
                    scope.check_scope(bad.encode())

    def test_reject_provider_or_eventid_changes(self):
        for original, substitute in (
            ("^Microsoft-Windows-Sysmon$", "^Unknown-Provider$"),
            ("^1$", "^3$"),
        ):
            with self.subTest(original=original):
                bad = VALID_XML.replace(original, substitute)
                with self.assertRaisesRegex(ValueError, "matcher drift"):
                    scope.check_scope(bad.encode())

    def test_reject_matching_without_pcre_type(self):
        bad = VALID_XML.replace('name="win.eventdata.commandLine" type="pcre2"',
                                'name="win.eventdata.commandLine"')
        with self.assertRaisesRegex(ValueError, "PCRE"):
            scope.check_scope(bad.encode())

    def test_reject_duplicate_rule_id(self):
        copy = VALID_XML[VALID_XML.index('  <rule id="110100"'):VALID_XML.index('</group>')]
        bad = VALID_XML.replace("</group>", copy + "</group>")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            scope.check_scope(bad.encode())

    def test_reject_doctype_and_malformed_xml(self):
        with self.assertRaisesRegex(ValueError, "DTD"):
            scope.check_scope(("<!DOCTYPE group>\n" + VALID_XML).encode())
        with self.assertRaises(Exception):
            scope.check_scope(b"<group><rule")

    def test_cli_private_mode_success_without_sensitive_details(self):
        with tempfile.TemporaryDirectory(prefix="h01-rule-", dir=ROOT / ".lab") as td:
            file = Path(td) / "active-rule-private.xml"
            file.write_text(VALID_XML, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = scope.main(["--rule", str(file)])
            self.assertEqual(rc, 0)
            body = output.getvalue()
            self.assertIn('"prior_benign_file_matches": false', body)
            self.assertIn('"synthetic_vectors_passed": 5', body)
            self.assertNotIn("C:\\Lab", body)
            self.assertNotIn(str(file), body)
            self.assertNotIn("PRIVATE_RULE_CONTENT", body)

    def test_fixture_mode_and_wrong_path_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="m1-h01-synthetic-", dir=ROOT / "tests/fixtures") as td:
            file = Path(td) / "h01-rule-synthetic.xml"
            file.write_text(VALID_XML, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = scope.main(["--rule", str(file), "--fixture"])
            self.assertEqual(rc, 0)
            self.assertIn("SYNTHETIC_FIXTURE_ONLY", output.getvalue())
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                fail = scope.main(["--rule", str(file)])
            self.assertEqual(fail, 2)
            self.assertIn("H01_RULE_SCOPE=UNVERIFIED_OR_DRIFTED", error.getvalue())
            self.assertNotIn(str(file), error.getvalue())

    def test_reject_public_repo_files(self):
        with self.assertRaises(ValueError):
            scope.safe_rule_file(ROOT / "README.md")
        with self.assertRaises(ValueError):
            scope.safe_rule_file(ROOT / "README.md", True)


if __name__ == "__main__":
    unittest.main()
