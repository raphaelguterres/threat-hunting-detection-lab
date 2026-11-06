#!/usr/bin/env python3
"""Read-only status for the historical lab and active M1 roadmap checklists.

Counts only top-level Markdown checkboxes in ROADMAP.md, not issue closure,
CI success, human attestations, or operational deployment approvals.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[1]
HISTORICAL_SECTIONS = tuple(f"Fase {i}" for i in range(1, 7))
SECTION_RE = re.compile(r"^## (Fase [1-6]|M1)(?:\s|\b)")
CHECKBOX_RE = re.compile(r"^- \[([ xX])\] (.+)$")


def summarize(text: str) -> dict:
    sections = {}
    section = None
    for line in text.splitlines():
        if line.startswith("## "):
            match = SECTION_RE.match(line)
            section = match.group(1) if match else None
            if section is not None:
                if section in sections:
                    raise ValueError("duplicate roadmap section")
                sections[section] = {"done": [], "pending": []}
            continue
        if section is None:
            continue
        match = CHECKBOX_RE.match(line)
        if match:
            target = "pending" if match.group(1) == " " else "done"
            sections[section][target].append(match.group(2))
    if any(x not in sections for x in HISTORICAL_SECTIONS + ("M1",)):
        raise ValueError("missing expected roadmap phases")
    historical_done = sum(len(sections[x]["done"]) for x in HISTORICAL_SECTIONS)
    historical_pending = sum(len(sections[x]["pending"]) for x in HISTORICAL_SECTIONS)
    m1_done = len(sections["M1"]["done"])
    m1_pending = len(sections["M1"]["pending"])
    if historical_done + historical_pending == 0 or m1_done + m1_pending == 0:
        raise ValueError("empty roadmap checklist")
    return {
        "basis": "ROADMAP.md top-level checkboxes only",
        "historical": {"phases": len(HISTORICAL_SECTIONS),
                       "done": historical_done, "pending": historical_pending,
                       "total": historical_done + historical_pending},
        "m1": {"done": m1_done, "pending": m1_pending,
               "total": m1_done + m1_pending,
               "percent_marked": round(100 * m1_done / (m1_done + m1_pending), 1),
               "remaining_labels": sections["M1"]["pending"]},
        "operational_deployment_authorized": False,
        "human_review_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    report = summarize((REPO / "ROADMAP.md").read_text(encoding="utf-8-sig"))
    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        historical = report["historical"]
        m1 = report["m1"]
        print(f"HISTORICAL_CHECKLIST={historical['done']}/{historical['total']}")
        print(f"HISTORICAL_PHASES={historical['phases']}")
        print(f"M1_CHECKLIST={m1['done']}/{m1['total']}")
        print(f"M1_PENDING_ITEMS={m1['pending']}")
        print(f"M1_CHECKLIST_PERCENT={m1['percent_marked']}")
        print("DEPLOYMENT_APPROVED=false")
        print("HUMAN_REVIEW_VERIFIED=false")
        print("NOT_AN_OPERATIONAL_READINESS_SCORE=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
