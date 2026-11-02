"""Purely synthetic tests for the Wazuh OS-targeting change proposal."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_fim_os_scope as scope  # noqa: E402


def fragment(os_name, directory, location=None):
    localfile = (
        f"<localfile><location>{location}</location><log_format>syslog</log_format></localfile>"
        if location else ""
    )
    return (
        f'<agent_config os="{os_name}"><syscheck>'
        f'<directories realtime="yes">{directory}</directories>'
        f'</syscheck>{localfile}</agent_config>'
    )


class OSScopeValidatorTests(unittest.TestCase):
    def test_proposed_fixture_valid_but_not_wazuh_verified(self):
        src = (ROOT / "tests" / "fixtures" / "m1-agent-conf-os-scope-synthetic.xml")
        data = scope.validate(src.read_text(encoding="utf-8"))
        self.assertEqual(data["linux_blocks"], 1)
        self.assertEqual(data["windows_blocks"], 1)
        self.assertEqual(data["linux_directories"], 1)
        self.assertEqual(data["windows_directories"], 1)
        self.assertEqual(data["linux_log_sources"], 1)
        self.assertFalse(data["wazuh_parser_verified"])
        self.assertFalse(data["deployed"])

    def test_reject_unscoped_linux_fim(self):
        with self.assertRaises(ValueError):
            scope.validate("<agent_config><syscheck><directories>/tmp/lab</directories></syscheck></agent_config>")

    def test_reject_linux_path_under_windows(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment("^Windows", "/var/log/lab"))

    def test_reject_windows_path_under_linux(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment("^Linux", r"C:\Windows\lab"))

    def test_reject_syslog_linux_path_under_windows(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment("^Windows", r"C:\Lab", "/var/log/syslog"))

    def test_reject_regex_matching_every_os(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment(".*", "/tmp/lab"))

    def test_reject_unanchored_linux_targeting(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment("Linux", "/tmp/lab"))

    def test_reject_network_path(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment("^Windows", r"\\server\share\lab"))

    def test_reject_dtd_entity(self):
        with self.assertRaises(ValueError):
            scope.validate('<!DOCTYPE x [<!ENTITY a "ABC">]>' + fragment("^Linux", "/tmp/demo"))

    def test_reject_broken_xml(self):
        with self.assertRaises(ValueError):
            scope.validate('<agent_config os="^Linux"><syscheck>')

    def test_reject_empty_directories(self):
        with self.assertRaises(ValueError):
            scope.validate(fragment("^Linux", "/tmp/demo, "))

    def test_windows_environment_variable(self):
        result = scope.validate(fragment("^Windows", r"%WINDIR%\System32"))
        self.assertEqual(result["windows_directories"], 1)

    def test_multidir_block_counts(self):
        result = scope.validate(fragment("^Linux", "/tmp/lab1,/tmp/lab2"))
        self.assertEqual(result["linux_directories"], 2)

    def test_cli_rejects_missing_input_without_filename_leak(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = scope.main(["--input", "/tmp/private-no-such-wazuh-file.xml"])
        self.assertEqual(result, 2)
        self.assertNotIn("private-no-such", err.getvalue())

    def test_cli_synthetic_ok_reports_aggregates(self):
        out = io.StringIO()
        f = ROOT / "tests" / "fixtures" / "m1-agent-conf-os-scope-synthetic.xml"
        with contextlib.redirect_stdout(out):
            result = scope.main(["--input", str(f)])
        self.assertEqual(result, 0)
        answer = json.loads(out.getvalue())
        self.assertEqual(answer["validation"], "synthetic_structural_checks_only")
        self.assertNotIn("M1_EXAMPLE_NOT_DEPLOYABLE", out.getvalue())


if __name__ == "__main__":
    unittest.main()
