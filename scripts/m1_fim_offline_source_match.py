#!/usr/bin/env python3
"""Compare already-authorized private Wazuh Manager and Indexer FIM exports offline.

No network, Docker, VM, data collection, deployment, or changes to Wazuh.
Output is aggregates only. Even a complete match is NOT independent attestation.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[1]
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_ROWS = 5000
AGENTS = ("002", "004", "005")
EVENTS = frozenset(("added", "modified", "deleted"))
TZ_OFFSET = re.compile(r"([+-]\\d{2})(\\d{2})$")


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise ValueError("nonfinite JSON number")


def decode_json(raw):
    return json.loads(raw, object_pairs_hook=unique_keys, parse_constant=reject_nonfinite)


def timestamp(value):
    if not isinstance(value, str) or len(value) > 48:
        raise ValueError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(TZ_OFFSET.sub(r"\\1:\\2", value.replace("Z", "+00:00")))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def safe_file(path: Path, fixture: bool) -> Path:
    base = (REPO / ("tests/fixtures" if fixture else ".lab")).resolve(strict=True)
    candidate = path if path.is_absolute() else REPO / path
    absolute = candidate.absolute()
    if any(part.is_symlink() for part in (absolute, *absolute.parents)):
        raise ValueError("symbolic link not allowed")
    resolved = absolute.resolve(strict=True)
    if not resolved.is_relative_to(base) or not resolved.is_file():
        raise ValueError("source outside authorized private directory")
    if not 0 < resolved.stat().st_size <= MAX_INPUT_BYTES:
        raise ValueError("file missing, empty, or too large")
    if fixture and "synthetic" not in resolved.name.lower():
        raise ValueError("fixture must be labelled synthetic")
    return resolved


def clean_string(value, max_length: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= max_length:
        raise ValueError("missing or oversized event identity")
    if value != value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("ambiguous identity")
    return value


def scoped_path(path: str, agent: str) -> str:
    # Only Windows path comparison is case insensitive.
    return path.casefold() if agent == "004" else path


def load_scope(path: Path) -> dict[str, str]:
    scope = decode_json(path.read_text(encoding="utf-8-sig"))
    if not isinstance(scope, dict) or set(scope) != set(AGENTS):
        raise ValueError("scope must define the three expected agents")
    return {agent: scoped_path(clean_string(scope[agent], 1024), agent)
            for agent in AGENTS}


@dataclass(frozen=True)
class Event:
    event_id: str
    agent_id: str
    event_type: str
    path: str
    rule_id: str
    moment: datetime


def parse_event(value, scope) -> Event | None:
    if not isinstance(value, dict):
        raise ValueError("invalid event envelope")
    source = value.get("_source", value)
    if not isinstance(source, dict):
        raise ValueError("invalid source")
    syscheck = source.get("syscheck")
    if syscheck is None:  # unrelated alerts can occur in a bounded export
        return None
    if not isinstance(syscheck, dict):
        raise ValueError("invalid syscheck object")
    agent = source.get("agent")
    rule = source.get("rule")
    if not isinstance(agent, dict) or not isinstance(rule, dict):
        raise ValueError("invalid agent or rule")
    agent_id = clean_string(agent.get("id"), 6)
    if agent_id not in AGENTS:
        return None
    path = scoped_path(clean_string(syscheck.get("path"), 1024), agent_id)
    if path != scope[agent_id]:
        return None
    kind = clean_string(syscheck.get("event"), 32)
    if kind not in EVENTS:
        raise ValueError("unexpected scoped FIM operation")
    event_id = clean_string(source.get("id"), 128)
    rule_id = clean_string(str(rule.get("id")), 12)
    if not re.fullmatch(r"[0-9]+", rule_id):
        raise ValueError("invalid rule identity")
    return Event(event_id, agent_id, kind, path, rule_id, timestamp(source.get("timestamp")))


def load_events(path: Path, scope) -> list[Event]:
    records = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            if not line.strip():
                continue
            if len(line) > 65536:
                raise ValueError("oversized JSONL record")
            if len(records) >= MAX_ROWS:
                raise ValueError("too many scoped events")
            record = parse_event(decode_json(line), scope)
            if record is not None:
                records.append(record)
    if len({record.event_id for record in records}) != len(records):
        raise ValueError("duplicate event ids in one source")
    return records


def compare(manager: list[Event], indexer: list[Event], tolerance_seconds: int = 90):
    def group(rows):
        return {(e.agent_id, e.event_type, e.path, e.event_id): e for e in rows}

    left, right = group(manager), group(indexer)
    common = left.keys() & right.keys()
    consistent = {key for key in common
                  if left[key].rule_id == right[key].rule_id
                  and abs((left[key].moment - right[key].moment).total_seconds()) <= tolerance_seconds}
    results = {}
    for agent in AGENTS:
        left_events = {e.event_type for e in manager if e.agent_id == agent}
        right_events = {e.event_type for e in indexer if e.agent_id == agent}
        complete = (left_events == EVENTS and right_events == EVENTS
                    and sum(e.agent_id == agent for e in manager) == 3
                    and sum(e.agent_id == agent for e in indexer) == 3
                    and sum(key[0] == agent for key in consistent) == 3)
        results[agent] = {"manager_count": sum(e.agent_id == agent for e in manager),
                          "indexer_count": sum(e.agent_id == agent for e in indexer),
                          "matched_exact": sum(key[0] == agent for key in consistent),
                          "complete_three_operations": complete}
    approved = len(manager) == 9 and len(indexer) == 9 and len(consistent) == 9 and all(
        item["complete_three_operations"] for item in results.values())
    return {
        "comparison": "MATCHED_PRIVATE_EXPORTS" if approved else "MISMATCH_OR_INCOMPLETE",
        "manager_export_events": len(manager),
        "indexer_export_events": len(indexer),
        "exact_identity_matches": len(consistent),
        "unmatched_or_inconsistent_manager": len(left) - len(consistent),
        "unmatched_or_inconsistent_indexer": len(right) - len(consistent),
        "per_agent": results,
        "scope": "three_benign_fim_probes",
        "method": "offline_exact_event_id_agent_operation_artifact_rule_and_time",
        "input_provenance": "operator_supplied_not_independently_attested",
        "independent_manager_attestation": False,
        "independent_reviewer_verified": False,
        "final_change_acceptance": "PENDING_INDEPENDENT_REVIEW",
        "no_live_actions": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manager", type=Path, required=True)
    parser.add_argument("--indexer", type=Path, required=True)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--fixture", action="store_true",
                        help="Synthetic test files only, under tests/fixtures/")
    args = parser.parse_args(argv)
    try:
        manager = safe_file(args.manager, args.fixture)
        indexer = safe_file(args.indexer, args.fixture)
        scope = safe_file(args.scope, args.fixture)
        if len({manager, indexer, scope}) != 3:
            raise ValueError("sources must be different")
        selected = load_scope(scope)
        outcome = compare(load_events(manager, selected), load_events(indexer, selected))
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        print("OFFLINE_FIM_MATCH=INPUT_REJECTED", file=sys.stderr)
        print("MANAGER_INGESTION_EVIDENCE=NOT_VERIFIED", file=sys.stderr)
        return 2
    outcome["sample_type"] = "SYNTHETIC_ONLY" if args.fixture else "PRIVATE_OPERATOR_EXPORTS"
    print(json.dumps(outcome, sort_keys=True, indent=2))
    return 0 if outcome["comparison"] == "MATCHED_PRIVATE_EXPORTS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
