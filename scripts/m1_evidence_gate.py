#!/usr/bin/env python3
"""Fail-closed, read-only M1 evidence completeness check. Never authorizes deployment."""
import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PRECHANGE = (
    "inventory_review", "os_impact_review", "baseline_integrity",
    "parser_staging", "backup_integrity_real", "rollback_rehearsal_real",
    "change_approval", "approved_window",
)
POSTCHANGE = (
    "agents_resynced", "windows_fim", "linux_fim",
    "manager_ingestion", "indexer_ingestion", "discover_visibility",
)


def assess(data, stage="prechange"):
    """Returns (complete, list of *field labels*, no private evidence content)."""
    missing = []
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return False, ["schema_version"]
    if data.get("change_id") != "M1-FIM-OS-SCOPE":
        missing.append("change_id")
    agents = data.get("agents")
    if not isinstance(agents, list) or len(agents) != 4:
        missing.append("agents_exactly_four")
        agents = []
    seen = set()
    for idx, agent in enumerate(agents):
        key = "agent_" + str(idx + 1)
        if not isinstance(agent, dict):
            missing.append(key)
            continue
        ident = agent.get("id")
        if not isinstance(ident, str) or not re.fullmatch(r"[0-9]{3,6}", ident) or ident in seen:
            missing.append(key + "_unique_id")
        else:
            seen.add(ident)
        os_name = agent.get("os")
        if not isinstance(os_name, str) or not os_name.startswith(("Windows", "Linux", "macOS")):
            missing.append(key + "_os")
        if ident == "004" and isinstance(os_name, str) and not os_name.startswith("Windows"):
            missing.append("agent_004_windows_expected")
        if not isinstance(agent.get("groups"), list) or "default" not in agent["groups"]:
            missing.append(key + "_default_group")
        if agent.get("sync") != "synced":
            missing.append(key + "_sync")
        if not isinstance(agent.get("evidence_ref"), str) or not agent["evidence_ref"].strip():
            missing.append(key + "_evidence")
    if len(agents) == 4 and "004" not in seen:
        missing.append("agent_004_not_reconciled")
    checks = data.get("checks")
    if not isinstance(checks, dict):
        checks = {}
    needed = PRECHANGE + (POSTCHANGE if stage == "postchange" else ())
    for name in needed:
        entry = checks.get(name)
        if (not isinstance(entry, dict) or entry.get("status") != "verified"
                or not isinstance(entry.get("evidence_ref"), str)
                or not entry["evidence_ref"].strip()):
            missing.append(name)
    return len(missing) == 0, missing


def private_or_fixture(path, fixture):
    """Only read explicitly allowed repo-local evidence locations."""
    resolved = path.resolve()
    parent = (REPO / ("tests/fixtures" if fixture else ".lab")).resolve()
    if not resolved.is_relative_to(parent):
        return False
    return not fixture or "synthetic" in resolved.name.lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--stage", choices=("prechange", "postchange"), default="prechange")
    parser.add_argument("--fixture", action="store_true", help="Synthetic CI fixture only")
    args = parser.parse_args()
    if args.manifest is None or not private_or_fixture(args.manifest, args.fixture):
        print("EVIDENCE=UNAVAILABLE_OR_DISALLOWED")
        print("DEPLOYMENT_GATE=BLOCKED")
        return 2
    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("EVIDENCE=UNREADABLE")
        print("DEPLOYMENT_GATE=BLOCKED")
        return 2
    complete, missing = assess(data, args.stage)
    print("STAGE=" + args.stage)
    print("EVIDENCE_COMPLETENESS=" + ("REVIEW_READY" if complete else "INCOMPLETE"))
    print("MISSING_OR_UNVERIFIED=" + (",".join(missing) if missing else "none"))
    print("DEPLOYMENT_GATE=BLOCKED")
    print("MANUAL_INDEPENDENT_APPROVAL_REQUIRED=true")
    print("NO_REMOTE_CONNECTION_NO_CONFIGURATION_CHANGE=true")
    # Success indicates document completeness only, NEVER deploy authorization.
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
