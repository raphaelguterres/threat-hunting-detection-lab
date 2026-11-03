"""Contract tests for roadmap counter without any live Wazuh evidence."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import roadmap_progress as progress  # noqa: E402


class RoadmapProgressTests(unittest.TestCase):
    def test_current_roadmap_counts_only_checked_items(self):
        result = progress.summarize((REPO / "ROADMAP.md").read_text(encoding="utf-8-sig"))
        self.assertEqual(result["historical"]["phases"], 6)
        self.assertEqual(result["historical"]["pending"], 0)
        self.assertGreaterEqual(result["historical"]["done"], 8)
        self.assertGreaterEqual(result["m1"]["total"], result["m1"]["done"])
        self.assertEqual(
            result["m1"]["total"], result["m1"]["done"] + result["m1"]["pending"]
        )
        self.assertEqual(len(result["m1"]["remaining_labels"]), result["m1"]["pending"])
        self.assertFalse(result["operational_deployment_authorized"])
        self.assertFalse(result["human_review_verified"])

    def test_other_sections_and_nested_checkboxes_not_included(self):
        s = "".join(f"## Fase {i} - Sample\n- [x] done\n  - [ ] nested\n" for i in range(1, 7))
        s += "## Other roadmap\n- [x] unrelated\n## M1 - New\n- [x] prepared\n- [ ] real validation\n"
        r = progress.summarize(s)
        self.assertEqual(r["historical"]["total"], 6)
        self.assertEqual(r["m1"]["done"], 1)
        self.assertEqual(r["m1"]["pending"], 1)
        self.assertEqual(r["m1"]["percent_marked"], 50.0)

    def test_duplicate_or_missing_sections_rejected(self):
        sections = "".join(f"## Fase {i}\n- [x] done\n" for i in range(1, 7))
        with self.assertRaises(ValueError):
            progress.summarize(sections)
        with self.assertRaises(ValueError):
            progress.summarize(sections + "## M1\n- [ ] work\n## M1\n- [x] work\n")

    def test_cli_output_clearly_not_operational_approval(self):
        p = subprocess.run(
            [sys.executable, str(REPO / "scripts/roadmap_progress.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("M1_PENDING_ITEMS=", p.stdout)
        self.assertIn("DEPLOYMENT_APPROVED=false", p.stdout)
        self.assertIn("NOT_AN_OPERATIONAL_READINESS_SCORE=true", p.stdout)

    def test_json_output_has_remaining_labels(self):
        p = subprocess.run(
            [sys.executable, str(REPO / "scripts/roadmap_progress.py"), "--format", "json"],
            capture_output=True, text=True,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(len(data["m1"]["remaining_labels"]), data["m1"]["pending"])


if __name__ == "__main__":
    unittest.main()
