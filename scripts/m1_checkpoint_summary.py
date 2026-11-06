#!/usr/bin/env python3
"""Offline, read-only M1 checkpoint using only private operator-provided evidence.

No GitHub, Wazuh, VM or network access. Never authorizes an operational change.
Outputs aggregate counts and states, not paths, IDs, hosts, IPs or raw evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import m1_evidence_gate as evidence
import m1_observed_agents_triage as observations
import roadmap_progress as roadmap
from m1_import_authorized_inventory import contained

REPO = Path(__file__).resolve().parents[1]
SNAPSHOT = REPO / ".lab/m1-dashboard-observations-20261103.json"
MANIFEST = REPO / ".lab/m1-evidence.json"


def read_observations(path: Path) -> dict | None:
    try:
        if not contained(path) or not path.is_file() or path.stat().st_size > 32768:
            return None
        with path.open(encoding="utf-8-sig") as stream:
            doc = json.load(stream, object_pairs_hook=observations._unique_keys,
                            parse_constant=observations._invalid_constant)
        return observations.summarize(doc)
    except (ValueError, OSError, UnicodeError, RuntimeError, RecursionError, TypeError, OverflowError):
        return None


def read_manifest(path: Path) -> tuple[str, int | None]:
    try:
        if not evidence.private_or_fixture(path, False):
            return "UNAVAILABLE_OR_INVALID", None
        doc = json.loads(path.read_text(encoding="utf-8-sig"),
                         object_pairs_hook=evidence.reject_duplicate_keys,
                         parse_constant=evidence.reject_nonfinite_constant)
        complete, missing = evidence.assess(doc, "prechange")
        return ("DOCUMENT_COMPLETE_UNATTESTED" if complete else "INCOMPLETE", len(missing))
    except (ValueError, OSError, UnicodeError, RuntimeError, RecursionError, TypeError, OverflowError):
        return "UNAVAILABLE_OR_INVALID", None


def report(snapshot: Path, manifest: Path) -> dict:
    observations_data = read_observations(snapshot)
    manifest_state, missing_count = read_manifest(manifest)
    try:
        milestone = roadmap.summarize((REPO / "ROADMAP.md").read_text(encoding="utf-8-sig"))["m1"]
    except (OSError, UnicodeError, ValueError, TypeError):
        milestone = None
    return {
        "checkpoint_type": "PRIVATE_OFFLINE_STATUS_ONLY",
        "roadmap_done": milestone["done"] if milestone else None,
        "roadmap_total": milestone["total"] if milestone else None,
        "roadmap_percent_documentary": milestone["percent_marked"] if milestone else None,
        "observation_state": "PRELIMINARY_UNATTESTED" if observations_data else "UNAVAILABLE_OR_INVALID",
        "observed_agents": observations_data["OBSERVED_ROWS"] if observations_data else None,
        "active_observed": observations_data["STATUS_ACTIVE"] if observations_data else None,
        "disconnected_observed": observations_data["STATUS_DISCONNECTED"] if observations_data else None,
        "group_memberships_unknown": observations_data["GROUP_MEMBERSHIP_UNKNOWN"] if observations_data else None,
        "group_sync_unknown": observations_data["GROUP_SYNC_UNKNOWN"] if observations_data else None,
        "keepalive_unknown": observations_data["LAST_KEEPALIVE_UNKNOWN"] if observations_data else None,
        "manifest_state": manifest_state,
        "manifest_missing_fields": missing_count,
        "manager_runtime": "NOT_CHECKED_BY_THIS_SCRIPT",
        "github_reviews": "NOT_CHECKED_BY_THIS_SCRIPT",
        "next_evidence": "AUTHORIZED_DASHBOARD_DEFAULT_MEMBERS_AND_DISCONNECTED_AGENT_KEEPALIVE",
        "operational_deployment_gate": "BLOCKED",
        "writes_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args()
    result = report(args.snapshot, args.manifest)
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for key, value in result.items():
            shown = "UNKNOWN" if value is None else str(value).lower() if isinstance(value, bool) else value
            print(f"{key.upper()}={shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
