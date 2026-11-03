#!/usr/bin/env python3
"""Fail-closed, read-only M1 evidence completeness check. Never authorizes deployment."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MAX_MANIFEST_BYTES = 65536
PRECHANGE = (
    "inventory_review", "os_impact_review", "group_precedence_review", "baseline_integrity",
    "parser_staging", "backup_integrity_real", "rollback_rehearsal_real",
    "change_approval", "approved_window",
)
POSTCHANGE = (
    "agents_resynced", "windows_fim", "linux_fim",
    "manager_ingestion", "indexer_ingestion", "discover_visibility",
)


def reject_duplicate_keys(pairs):
    """Reject ambiguous JSON objects rather than silently accepting the last key."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite_constant(value):
    """JSON must not silently accept Python's NaN/Infinity extensions."""
    raise ValueError("nonfinite JSON constant")


def os_display_family(label):
    """Dashboard OS display parsing, never an agent_config OS regex test."""
    if (not isinstance(label, str) or len(label) > 160
            or any(ord(char) < 32 or ord(char) == 127 for char in label)
            or re.search(r"(?i)(?:unknown|unverified|pending|placeholder|tbd)", label)):
        return None
    for prefix, family in (
        ("Microsoft Windows ", "Windows"), ("Windows ", "Windows"),
        ("Amazon Linux ", "Linux"), ("Kali GNU/Linux ", "Linux"),
        ("Linux ", "Linux"), ("macOS ", "macOS"),
    ):
        if label.startswith(prefix) and re.search(r"[0-9]", label[len(prefix):]):
            return family
    return None


def assess(data, stage="prechange"):
    """Returns (complete, list of *field labels*, no private evidence content)."""
    missing = []
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        return False, ["schema_version"]
    if data.get("change_id") != "M1-FIM-OS-SCOPE":
        missing.append("change_id")
    agents = data.get("agents")
    if not isinstance(agents, list) or len(agents) != 4:
        missing.append("agents_exactly_four")
        agents = []
    seen = set()
    checked_at = datetime.now(timezone.utc)
    observed_times = []
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
        family = os_display_family(os_name)
        if family is None:
            missing.append(key + "_os_version")
        if ident == "004" and family != "Windows":
            missing.append("agent_004_windows_expected")
        groups = agent.get("groups")
        if (not isinstance(groups, list) or not groups
                or not all(isinstance(g, str) and g and g.strip() == g and len(g) <= 128
                           and all(ord(c) >= 32 and ord(c) != 127 for c in g) for g in groups)
                or len(groups) != len(set(groups)) or "default" not in groups):
            missing.append(key + "_groups_valid_unique_default")
        if agent.get("sync") != "synced":
            missing.append(key + "_sync")
        if agent.get("status") != "active":
            missing.append(key + "_status")
        observed = agent.get("observed_at")
        try:
            if not isinstance(observed, str):
                raise ValueError("missing observation timestamp")
            observed_dt = datetime.fromisoformat(observed)
            if observed_dt.tzinfo is None or observed_dt.utcoffset() is None:
                raise ValueError("timestamp without timezone")
            age = checked_at - observed_dt.astimezone(timezone.utc)
            if age > timedelta(hours=24) or age < -timedelta(minutes=5):
                raise ValueError("stale or future observation")
            observed_times.append(observed_dt.astimezone(timezone.utc))
        except (TypeError, ValueError, OverflowError):
            missing.append(key + "_observation_freshness")
        evidence = agent.get("evidence_ref")
        if (not isinstance(evidence, str) or not evidence.strip() or len(evidence.strip()) > 256
                or any(ord(c) < 32 or ord(c) == 127 for c in evidence)
                or re.search(r"(?i)(?:unknown|unverified|pending|placeholder|tbd)", evidence)):
            missing.append(key + "_evidence")
    if len(agents) == 4 and "004" not in seen:
        missing.append("agent_004_not_reconciled")
    if len(observed_times) == 4 and max(observed_times) - min(observed_times) > timedelta(minutes=30):
        missing.append("inventory_time_coherence")
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
    """Accept only small regular files in the allowed private/fixture directory."""
    try:
        candidate = path.absolute()
        if any(part.is_symlink() for part in (candidate, *candidate.parents)):
            return False
        resolved = candidate.resolve(strict=True)
        parent = (REPO / ("tests/fixtures" if fixture else ".lab")).resolve()
        if not resolved.is_relative_to(parent) or not resolved.is_file():
            return False
        if resolved.stat().st_size > MAX_MANIFEST_BYTES:
            return False
        return not fixture or "synthetic" in resolved.name.lower()
    except (OSError, RuntimeError):
        return False


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
        data = json.loads(args.manifest.read_text(encoding="utf-8-sig"),
                          object_pairs_hook=reject_duplicate_keys,
                          parse_constant=reject_nonfinite_constant)
    except (OSError, UnicodeError, ValueError, RecursionError):
        print("EVIDENCE=UNREADABLE")
        print("DEPLOYMENT_GATE=BLOCKED")
        return 2
    complete, missing = assess(data, args.stage)
    print("STAGE=" + args.stage)
    if args.fixture:
        print("EVIDENCE_SOURCE=SYNTHETIC_FIXTURE")
        completeness = "SYNTHETIC_VALIDATED" if complete else "SYNTHETIC_INCOMPLETE"
    else:
        print("EVIDENCE_SOURCE=PRIVATE_UNATTESTED")
        completeness = "REVIEW_READY" if complete else "INCOMPLETE"
    print("EVIDENCE_COMPLETENESS=" + completeness)
    print("MISSING_OR_UNVERIFIED=" + (",".join(missing) if missing else "none"))
    print("DEPLOYMENT_GATE=BLOCKED")
    print("MANUAL_INDEPENDENT_APPROVAL_REQUIRED=true")
    print("NO_REMOTE_CONNECTION_NO_CONFIGURATION_CHANGE=true")
    # Success indicates document completeness only, NEVER deploy authorization.
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
