"""Synthetic-only checks for the fail-closed H03 candidate selector."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import m1_h03_candidate_safety_gate as gate  # noqa: E402


class CandidateSafetyGateTests(unittest.TestCase):
    def test_reject_programdata_startup(self):
        root = r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        candidate = root + r"\probe.exe"
        value = gate.classify_candidate(root, candidate, "realtime")
        self.assertEqual(value["status"], "NO_GO")
        self.assertEqual(value["reason"], "autostart_startup_folder")

    def test_reject_windows_system_directory(self):
        root = r"C:\Windows\System32\drivers\etc"
        candidate = root + r"\probe.exe"
        value = gate.classify_candidate(root, candidate, "scheduled")
        self.assertEqual(value["reason"], "operating_system_or_program_directory")

    def test_reject_out_of_scope_candidate(self):
        value = gate.classify_candidate(
            r"C:\Lab\H03", r"C:\Lab\Other\probe.exe", "realtime"
        )
        self.assertEqual(value["status"], "NO_GO")
        self.assertEqual(value["reason"], "candidate_not_beneath_monitored_root")

    def test_safe_looking_lab_root_still_requires_review(self):
        value = gate.classify_candidate(
            r"C:\Lab\H03", r"C:\Lab\H03\probe.exe", "realtime"
        )
        self.assertEqual(value["status"], "REVIEW_REQUIRED")
        self.assertEqual(value["test_approved"], "false")
        self.assertEqual(value["effective_fim_coverage"], "unverified")

    def test_scheduled_root_is_not_ready_for_20_min_h03(self):
        value = gate.classify_candidate(
            r"C:\Lab\H03", r"C:\Lab\H03\probe.exe", "scheduled"
        )
        self.assertEqual(value["status"], "REVIEW_REQUIRED")
        self.assertEqual(value["reason"], "scheduled_scan_may_exceed_h03_window")

    def test_cli_does_not_reveal_paths(self):
        secret_path = r"C:\Lab\SECRET_USERNAME\H03"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = gate.main([
                "--root", secret_path,
                "--candidate", secret_path + r"\probe.exe",
                "--mode", "realtime",
            ])
        self.assertEqual(result, 0)
        payload = out.getvalue()
        self.assertNotIn("SECRET_USERNAME", payload)
        self.assertIn("REVIEW_REQUIRED", payload)
        self.assertEqual(json.loads(payload)["test_approved"], "false")

    def test_reject_unresolved_relative_path(self):
        value = gate.classify_candidate(
            r"%PROGRAMDATA%\H03", r"%PROGRAMDATA%\H03\probe.exe", "realtime"
        )
        self.assertEqual(value["status"], "NO_GO")
        self.assertEqual(value["reason"], "unresolved_or_relative_path")


if __name__ == "__main__":
    unittest.main()
