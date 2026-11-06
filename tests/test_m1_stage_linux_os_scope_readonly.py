"""Offline-only tests of the single-tag Linux staging tool; never contacts a VM."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
from m1_stage_linux_os_scope_readonly import main, stage_linux_only  # noqa: E402

BASE = b"""<agent_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <syscheck>
    <directories realtime="yes">/opt/wazuh-lab/monitorado</directories>
  </syscheck>
</agent_config>
"""


class LinuxScopeStagingTests(unittest.TestCase):
    def test_only_one_opening_tag_changes(self):
        staged, result = stage_linux_only(BASE)
        self.assertEqual(
            staged.replace(b'<agent_config os="^Linux">', b"<agent_config>", 1), BASE
        )
        self.assertEqual(result["linux_log_sources_preserved"], 1)
        self.assertEqual(result["deployed"], False)
        self.assertEqual(result["manager_parser_staged_verified"], False)

    def test_refuse_previously_scoped_config(self):
        with self.assertRaises(ValueError):
            stage_linux_only(BASE.replace(b"<agent_config>", b'<agent_config os="^Linux">'))

    def test_refuse_multiple_blocks(self):
        with self.assertRaises(ValueError):
            stage_linux_only(BASE + BASE)

    def test_refuse_windows_directory(self):
        with self.assertRaises(ValueError):
            stage_linux_only(BASE.replace(b"/opt/wazuh-lab/monitorado", b"C:\\Windows"))

    def test_refuse_windows_log_source(self):
        with self.assertRaises(ValueError):
            stage_linux_only(BASE.replace(b"/var/log/syslog", b"C:\\Windows\\x.log"))

    def test_refuse_non_realtime_policy(self):
        with self.assertRaises(ValueError):
            stage_linux_only(BASE.replace(b'realtime="yes"', b'realtime="no"'))

    def test_refuse_missing_log_source(self):
        with self.assertRaises(ValueError):
            stage_linux_only(BASE.replace(b"<location>/var/log/syslog</location>", b""))

    def test_refuse_entity_injection(self):
        with self.assertRaises(ValueError):
            stage_linux_only(b'<!DOCTYPE x [<!ENTITY a "x">]>' + BASE)

    def test_private_output_create_once_without_overwrite(self):
        # All test bytes remain inside the ignored .lab area.
        lab = REPO / ".lab"
        lab.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m1-os-stage-", dir=lab) as directory:
            root = Path(directory)
            source = root / "source.xml"
            output = root / "staged.xml"
            source.write_bytes(BASE)
            argv = ["--source", str(source), "--output", str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(argv), 0)
            self.assertTrue(output.read_bytes().startswith(b'<agent_config os="^Linux">'))
            original_staged = output.read_bytes()
            with (contextlib.redirect_stdout(io.StringIO()),
                  contextlib.redirect_stderr(io.StringIO())):
                self.assertEqual(main(argv), 2)
            self.assertEqual(output.read_bytes(), original_staged)

    def test_reject_outside_private_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.xml"
            output = Path(directory) / "out.xml"
            source.write_bytes(BASE)
            with (contextlib.redirect_stdout(io.StringIO()),
                  contextlib.redirect_stderr(io.StringIO())):
                self.assertEqual(main(["--source", str(source), "--output", str(output)]), 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
