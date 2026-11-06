#!/usr/bin/env python3
"""Fail-closed, read-only M1 evidence completeness check. Never authorizes deployment."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MAX_MANIFEST_BYTES = 65536
EXPECTED_DEFAULT_AGENT_IDS = frozenset(("002", "004", "005"))
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


def valid_review_reference(value):
    """Refuse blank, placeholder and unsafe labels in manual review references.

    This is a *format* check, not authentication of a human review.
    """
    return (isinstance(value, str)
            and value == value.strip()
            and 1 <= len(value) <= 256
            and all(ord(c) >= 32 and ord(c) != 127 for c in value)
            and not re.search(r"(?i)(?:unknown|unverified|pending|placeholder|tbd)", value))


def assess(data, stage="prechange"):
    """Returns (complete, list of *field labels*, no private evidence content)."""
    missing = []
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        return False, ["schema_version"]
    if data.get("change_id") != "M1-FIM-OS-SCOPE":
        missing.append("change_id")
    agents = data.get("agents")
    if not isinstance(agents, list) or len(agents) != len(EXPECTED_DEFAULT_AGENT_IDS):
        missing.append("agents_exactly_three")
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
    if len(agents) == len(EXPECTED_DEFAULT_AGENT_IDS) and "004" not in seen:
        missing.append("agent_004_not_reconciled")
    if len(agents) == len(EXPECTED_DEFAULT_AGENT_IDS) and seen != EXPECTED_DEFAULT_AGENT_IDS:
        missing.append("default_scope_expected_ids")
    if len(observed_times) == len(EXPECTED_DEFAULT_AGENT_IDS) and max(observed_times) - min(observed_times) > timedelta(minutes=30):
        missing.append("inventory_time_coherence")
    checks = data.get("checks")
    if not isinstance(checks, dict):
        checks = {}
    needed = PRECHANGE + (POSTCHANGE if stage == "postchange" else ())
    for name in needed:
        entry = checks.get(name)
        if (not isinstance(entry, dict) or entry.get("status") != "verified"
                or not valid_review_reference(entry.get("evidence_ref"))):
            missing.append(name)
    return len(missing) == 0, missing


LAB_CONTINUATION_SCOPE = "isolated_lab_offline_and_readonly_continuation"
WAIVABLE_ONLY = frozenset(("manager_ingestion",))


def valid_owner_continuation(waiver, missing, checked_at=None):
    """Owner's *declared* risk exception: never claims final change acceptance.

    This is not proof of identity or an independent review. It is a scoped
    workflow continuation decision, not permission to deploy/restart services.
    """
    if not isinstance(waiver, dict) or set(missing) != WAIVABLE_ONLY:
        return False
    expected = {
        "schema_version": 1,
        "change_id": "M1-FIM-OS-SCOPE",
        "scope": LAB_CONTINUATION_SCOPE,
        "authorized_by": "project_owner_in_chat",
        "source": "explicit_owner_instruction_2026-11-05",
        "environment": "local_isolated_lab",
        "pending_checks": ["manager_ingestion"],
        "manager_ingestion_verified": False,
        "independent_review_verified": False,
        "rollback_preserved": True,
        "configuration_changes_authorized": False,
        "production_deployment_authorized": False,
    }
    if any(type(waiver.get(k)) is not type(v) or waiver.get(k) != v
           for k, v in expected.items()):
        return False
    try:
        start = datetime.fromisoformat(waiver["approved_at"])
        end = datetime.fromisoformat(waiver["expires_at"])
        if (start.tzinfo is None or start.utcoffset() is None
                or end.tzinfo is None or end.utcoffset() is None):
            return False
        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)
        now = checked_at or datetime.now(timezone.utc)
        return (start <= now <= end and timedelta(0) < end - start <= timedelta(hours=48))
    except (ValueError, KeyError, TypeError, OverflowError):
        return False


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
    parser.add_argument("--owner-continuation", type=Path,
                        help="Private, time-limited owner exception for isolated-lab continuation; not acceptance")
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
    continuation = False
    if args.owner_continuation is not None and not args.fixture:
        if private_or_fixture(args.owner_continuation, False):
            try:
                waiver = json.loads(args.owner_continuation.read_text(encoding="utf-8-sig"),
                                    object_pairs_hook=reject_duplicate_keys,
                                    parse_constant=reject_nonfinite_constant)
                continuation = valid_owner_continuation(waiver, missing)
            except (OSError, UnicodeError, ValueError, RecursionError):
                continuation = False
    if continuation:
        print("DEPLOYMENT_GATE=OWNER_SCOPED_LAB_CONTINUATION")
        print("PROJECT_CONTINUATION_GATE=OPEN")
        print("CHANGE_A_FINAL_ACCEPTANCE=PENDING_MANAGER_AND_REVIEW")
        print("PRODUCTION_DEPLOYMENT_GATE=BLOCKED")
        print("LIVE_CONFIGURATION_CHANGE_GATE=BLOCKED")
    else:
        print("DEPLOYMENT_GATE=BLOCKED")
        print("PROJECT_CONTINUATION_GATE=BLOCKED" if not complete else "PROJECT_CONTINUATION_GATE=REVIEW_READY_ONLY")
    print("MANUAL_INDEPENDENT_APPROVAL_REQUIRED=true")
    print("NO_REMOTE_CONNECTION_NO_CONFIGURATION_CHANGE=true")
    # This bypasses ONLY the workflow block for lab documentation/offline/read-only
    # continuation. It never turns an unverified check into verified evidence.
    return 0 if complete or continuation else 2


if __name__ == "__main__":
    raise SystemExit(main())
