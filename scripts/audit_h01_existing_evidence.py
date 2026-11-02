#!/usr/bin/env python3
"""Read-only temporal triage of the earlier six-event Manager identity export.

This script checks ONLY whether the observed PowerShell and schtasks rule IDs
could fit H01's temporal direction/window. Event identity exports have no
command line, actor, process tree or proof that a scheduled task was created.
Output is sanitized; never emits full alert IDs, agents or paths.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_BYTES = 65536
MAX_RECORDS = 100
RULE_PS = "110100"
RULE_TASK = "110120"
MAX_WINDOW = timedelta(minutes=15)


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    elif len(value) >= 5 and value[-5] in "+-" and value[-4:].isdigit():
        value = value[:-2] + ":" + value[-2:]
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp must carry a timezone")
    return result.astimezone(timezone.utc)


def read_identity_export(path: Path) -> list[tuple[str, str, datetime]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or linked identity export")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("identity export exceeds limited size")
    records = []
    seen = set()
    with path.open("r", encoding="utf-8-sig") as stream:
        for line in stream:
            if not line.strip():
                continue
            if len(records) >= MAX_RECORDS:
                raise ValueError("unexpected number of records")
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or not all(
                    field in item for field in ("id", "rule", "agent", "timestamp")
                ):
                    raise ValueError("expected four identity fields")
                if not isinstance(item["rule"], dict) or not isinstance(item["agent"], dict):
                    raise ValueError("invalid identity envelopes")
                event_id = item["id"]
                rule_id = item["rule"]["id"]
                agent_id = item["agent"]["id"]
                if not all(isinstance(x, str) and x.strip() for x in
                           (event_id, rule_id, agent_id)):
                    raise ValueError("empty identity field")
                if event_id in seen:
                    raise ValueError("duplicate original event identity")
                seen.add(event_id)
                records.append((rule_id, agent_id, parse_time(item["timestamp"])))
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError("malformed identity export") from exc
    return records


def audit(records: list[tuple[str, str, datetime]]) -> dict:
    ps = [(agent, ts) for rule, agent, ts in records if rule == RULE_PS]
    tasks = [(agent, ts) for rule, agent, ts in records if rule == RULE_TASK]
    answer = {
        "sample_events": len(records),
        "powershell_rule_events": len(ps),
        "schtasks_rule_events": len(tasks),
        "scope": "identity-only six-event sample; not a complete hunt",
        "actor_process_and_task_creation_verified": False,
        "incident_determined": False,
    }
    if len(ps) != 1 or len(tasks) != 1:
        answer["temporal_result"] = "inconclusive_event_count"
        return answer
    ps_agent, ps_time = ps[0]
    task_agent, task_time = tasks[0]
    if ps_agent != task_agent:
        answer["temporal_result"] = "different_agents_not_correlated"
        return answer
    gap = task_time - ps_time
    answer["absolute_separation_seconds"] = round(abs(gap.total_seconds()), 3)
    answer["order"] = (
        "powershell_then_task" if gap.total_seconds() > 0
        else "task_then_powershell" if gap.total_seconds() < 0
        else "simultaneous"
    )
    if timedelta(0) < gap <= MAX_WINDOW:
        answer["temporal_result"] = "candidate_requires_actor_and_task_creation_proof"
    else:
        answer["temporal_result"] = "h01_not_supported_by_this_bounded_sample"
    return answer


def is_private_input(path: Path, repo: Path, fixture: bool) -> bool:
    if path.is_symlink():
        return False
    fixture_root = repo / "tests" / "fixtures"
    if fixture:
        return not fixture_root.is_symlink() and fixture_root.resolve() in path.resolve().parents
    # The sibling project's six-event export is the ONLY authorized real-input
    # location; don't accept arbitrary paths, exports or system logs.
    allowed = repo.parent / "detection-engineering-blue-team" / ".lab"
    if allowed.is_symlink() or not allowed.is_dir():
        return False
    return allowed.resolve() in path.resolve().parents


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="../detection-engineering-blue-team/.lab/phase3-manager.jsonl")
    parser.add_argument("--fixture", action="store_true",
                        help="explicit synthetic fixture mode for tests only")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    path = Path(args.input)
    if not path.is_absolute():
        path = repo / path
    try:
        if not is_private_input(path, repo, args.fixture):
            raise ValueError("input outside approved private/fixture scope")
        result = audit(read_identity_export(path))
    except (OSError, ValueError, UnicodeError):
        print("H01_AUDIT_UNAVAILABLE_OR_INVALID_INPUT", file=sys.stderr)
        return 2
    result["provenance"] = (
        "synthetic_fixture" if args.fixture
        else "previously_captured_private_manager_identity_export"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
