"""Synthetic-only regression tests for minimal agent.conf OS scoping changes."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import review_fim_scope_only as reviewer


def base():
    return (
        '<agent_config>'
        '<syscheck><directories realtime="yes">/opt/M1_EXAMPLE_NOT_DEPLOYABLE</directories></syscheck>'
        '<localfile><location>/var/log/M1_EXAMPLE_NOT_DEPLOYABLE.log</location>'
        '<log_format>syslog</log_format></localfile>'
        '</agent_config>'
    )


def staged():
    return base().replace("<agent_config>", '<agent_config os="^Linux">')


class ChangeGuardTests(unittest.TestCase):
    def test_fixture_scope_only_change(self):
        b = (ROOT / "tests/fixtures/m1-original-unscoped-synthetic.xml").read_text()
        a = (ROOT / "tests/fixtures/m1-proposed-scoped-synthetic.xml").read_text()
        r = reviewer.compare(b, a)
        self.assertEqual(r["linux_scope_additions"], 1)
        self.assertEqual(r["blocks_checked"], 2)
        self.assertFalse(r["deployment_performed"])
        self.assertFalse(r["wazuh_parser_verified"])

    def test_single_linux_block_allowed(self):
        self.assertEqual(reviewer.compare(base(), staged())["linux_scope_additions"], 1)

    def test_no_change_rejected(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), base())

    def test_remaining_unscoped_linux_block_rejected(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base() + base(), staged() + base())

    def test_reject_hidden_windows_ignore_inside_linux_block(self):
        mixed = base().replace("</syscheck>", "<ignore>C:\\Windows\\Temp</ignore></syscheck>")
        with self.assertRaises(ValueError):
            reviewer.compare(mixed, mixed.replace("<agent_config>", '<agent_config os="^Linux">'))

    def test_reject_windows_registry_inside_linux_block(self):
        mixed = base().replace("</syscheck>", "<windows_registry>HKEY_LOCAL_MACHINE\\Software</windows_registry></syscheck>")
        with self.assertRaises(ValueError):
            reviewer.compare(mixed, mixed.replace("<agent_config>", '<agent_config os="^Linux">'))

    def test_reject_windows_path_hidden_in_attribute(self):
        mixed = base().replace('realtime="yes"', 'realtime="yes" alert_path="%PROGRAMDATA%\\Windows"')
        with self.assertRaises(ValueError):
            reviewer.compare(mixed, mixed.replace("<agent_config>", '<agent_config os="^Linux">'))

    def test_reject_encoded_windows_path_in_unrelated_element(self):
        mixed = base().replace("</syscheck>",
                               "<ignore>&#67;:/Windows/Temp</ignore></syscheck>")
        with self.assertRaises(ValueError):
            reviewer.compare(mixed, mixed.replace("<agent_config>", '<agent_config os="^Linux">'))

    def test_reject_unc_share_in_unrelated_element(self):
        mixed = base().replace("</syscheck>",
                               "<ignore>\\\\server\\share</ignore></syscheck>")
        with self.assertRaises(ValueError):
            reviewer.compare(mixed, mixed.replace("<agent_config>", '<agent_config os="^Linux">'))

    def test_reject_windows_only_log_format_even_with_unix_location(self):
        mixed = base().replace("<log_format>syslog</log_format>",
                               "<log_format>eventchannel</log_format>")
        with self.assertRaises(ValueError):
            reviewer.compare(mixed, mixed.replace("<agent_config>", '<agent_config os="^Linux">'))

    def test_allowed_unix_ignore_remains_structural_match(self):
        unix = base().replace("</syscheck>", "<ignore>/var/cache/example</ignore></syscheck>")
        result = reviewer.compare(unix, unix.replace("<agent_config>", '<agent_config os="^Linux">'))
        self.assertEqual(result["linux_scope_additions"], 1)

    def test_reject_changed_directory(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), staged().replace("/opt/", "/tmp/"))

    def test_reject_changed_log_location(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), staged().replace("/var/log/", "/tmp/"))

    def test_reject_removed_localfile(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), '<agent_config os="^Linux"><syscheck>'
                             '<directories realtime="yes">/opt/M1_EXAMPLE_NOT_DEPLOYABLE'
                             '</directories></syscheck></agent_config>')

    def test_reject_new_localfile(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), staged().replace("</agent_config>",
                '<localfile><location>/tmp/extra</location><log_format>syslog'
                '</log_format></localfile></agent_config>'))

    def test_reject_modified_realtime_attribute(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), staged().replace('realtime="yes"', 'realtime="no"'))

    def test_reject_modified_os_regex(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), staged().replace('os="^Linux"', 'os=".*"'))

    def test_reject_unix_windows_mismatch(self):
        with self.assertRaises(ValueError):
            reviewer.compare('<agent_config><syscheck><directories>'
                'C:\\Windows</directories></syscheck></agent_config>',
                '<agent_config os="^Linux"><syscheck><directories>'
                'C:\\Windows</directories></syscheck></agent_config>')

    def test_reject_dtd(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), '<!DOCTYPE xxx>' + staged())

    def test_reject_changed_comment(self):
        with self.assertRaises(ValueError):
            reviewer.compare('<!-- private synthetic note -->' + base(),
                             '<!-- edited note -->' + staged())

    def test_reject_changed_existing_scope(self):
        before = '<agent_config os="^Windows"><syscheck><directories>'
        after = '</directories></syscheck></agent_config>'
        with self.assertRaises(ValueError):
            reviewer.compare(base() + before + 'C:\\Lab' + after,
                staged() + before.replace('^Windows', '^Linux') + 'C:\\Lab' + after)

    def test_reject_unexpected_top_level(self):
        with self.assertRaises(ValueError):
            reviewer.compare(base(), staged() + '<global/>')

    def test_multiple_eligible_blocks_produces_count(self):
        r = reviewer.compare(base() + base(), staged() + staged())
        self.assertEqual(r["linux_scope_additions"], 2)

    def test_indentation_only_change_allowed(self):
        target = staged().replace("<syscheck>", "\n  <syscheck>")
        r = reviewer.compare(base(), target)
        self.assertEqual(r["linux_scope_additions"], 1)

    def test_reject_outside_private_directory(self):
        self.assertFalse(reviewer._input_allowed(
            ROOT / "README.md", ROOT, False))

    def test_reject_fixture_without_explicit_fixture_flag(self):
        path = ROOT / "tests/fixtures/m1-original-unscoped-synthetic.xml"
        self.assertFalse(reviewer._input_allowed(path, ROOT, False))
        self.assertTrue(reviewer._input_allowed(path, ROOT, True))

    def test_cli_fixture_aggregate_only(self):
        out = io.StringIO()
        args = [
            "--original", "tests/fixtures/m1-original-unscoped-synthetic.xml",
            "--proposed", "tests/fixtures/m1-proposed-scoped-synthetic.xml",
            "--fixture",
        ]
        with contextlib.redirect_stdout(out):
            code = reviewer.main(args)
        self.assertEqual(code, 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["input_provenance"], "synthetic_fixture")
        self.assertNotIn("M1_EXAMPLE_NOT_DEPLOYABLE", out.getvalue())

    def test_failure_does_not_echo_private_paths(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = reviewer.main([
                "--original", ".lab/super-private-file-name.xml",
                "--proposed", ".lab/super-private-proposed.xml",
            ])
        self.assertEqual(code, 2)
        self.assertNotIn("super-private", err.getvalue())


if __name__ == "__main__":
    unittest.main()
