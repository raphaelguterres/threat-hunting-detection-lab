#!/usr/bin/env python3
"""M1: deterministic offline hunt triage of explicitly normalized, scoped events.

No network access, no live endpoint actions and no raw identity/event output.
Correlation creates review candidates, never a verdict that a threat occurred.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_EVENTS = 1000
MAX_CANDIDATES = 5000
KINDS = {
    "powershell_process": frozenset({"sysmon_eid1", "wazuh_rule110100"}),
    "task_created": frozenset({"security_eid4698", "wazuh_rule110120"}),
    "account_created": frozenset({"security_eid4720"}),
    "privileged_logon": frozenset({"security_eid4672"}),
    "file_change": frozenset({"wazuh_fim"}),
    "file_execution": frozenset({"sysmon_eid1"}),
}
IDENTITY_FIELDS = ("event_ref", "asset_key", "actor_key", "object_key")
FIELDS = set(IDENTITY_FIELDS) | {"timestamp", "kind", "source"}
OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")
TZ_SUFFIX = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


@dataclass(frozen=True)
class Hypothesis:
    name: str
    first: str
    second: str
    minutes: int
    join_on: tuple[str, ...]


HYPOTHESES = (
    Hypothesis("H01_POWERSHELL_TASK", "powershell_process", "task_created", 15,
               ("asset_key", "actor_key")),
    Hypothesis("H02_ACCOUNT_PRIVILEGE", "account_created", "privileged_logon", 30,
               ("asset_key", "object_key")),
    Hypothesis("H03_FIM_EXECUTION", "file_change", "file_execution", 20,
               ("asset_key", "object_key")),
)


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    kind: str
    source: str
    event_ref: str
    asset_key: str
    actor_key: str
    object_key: str


def parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not TZ_SUFFIX.search(value):
        raise ValueError("timestamp must be ISO 8601 with explicit timezone")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    else:
        value = OFFSET.sub(r"\1:\2", value)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp missing timezone")
    return parsed.astimezone(timezone.utc)


def parse_event(obj: object) -> Event:
    if not isinstance(obj, dict) or set(obj) != FIELDS:
        raise ValueError("expected exactly the seven normalized event fields")
    for field in IDENTITY_FIELDS:
        value = obj[field]
        if not isinstance(value, str) or not (1 <= len(value.strip()) <= 128):
            raise ValueError("missing or oversized identity field")
        if value != value.strip():
            raise ValueError("whitespace around identity field")
    kind, source = obj["kind"], obj["source"]
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError("unsupported event kind")
    if not isinstance(source, str) or source not in KINDS[kind]:
        raise ValueError("event kind/source pairing is not approved")
    return Event(
        timestamp=parse_time(obj["timestamp"]), kind=kind, source=source,
        event_ref=obj["event_ref"], asset_key=obj["asset_key"],
        actor_key=obj["actor_key"], object_key=obj["object_key"],
    )


def _unique_pairs(pairs: list[tuple[str, str]]) -> int:
    unique = set(pairs)
    if len(unique) > MAX_CANDIDATES:
        raise ValueError("candidate limit exceeded")
    return len(unique)


def correlate(events: list[Event]) -> dict:
    refs = [event.event_ref for event in events]
    if len(set(refs)) != len(refs):
        raise ValueError("duplicate event_ref: one event must not count twice")
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_ref))
    results = {}
    for hypothesis in HYPOTHESES:
        earlier = [event for event in ordered if event.kind == hypothesis.first]
        later = [event for event in ordered if event.kind == hypothesis.second]
        pairs = []
        for start in earlier:
            for end in later:
                if end.timestamp <= start.timestamp:
                    continue
                if end.timestamp - start.timestamp > timedelta(minutes=hypothesis.minutes):
                    continue
                if any(getattr(start, field) != getattr(end, field)
                       for field in hypothesis.join_on):
                    continue
                pairs.append((start.event_ref, end.event_ref))
        results[hypothesis.name] = {
            "candidate_pairs": _unique_pairs(pairs),
            "window_minutes": hypothesis.minutes,
            "status": "triage_candidate" if pairs else "no_candidate_in_supplied_sample",
        }
    return {
        "input_events": len(events),
        "hypotheses": results,
        "verdict": "not_an_incident_determination",
    }


def _reject_duplicate_json_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def load_events(path: Path) -> list[Event]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("input file missing, not a regular file or symbolic link")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("input file exceeds private sample limit")
    events = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line in stream:
            if not line.strip():
                continue
            if len(events) >= MAX_EVENTS:
                raise ValueError("event count limit exceeded")
            try:
                obj = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSONL input") from exc
            events.append(parse_event(obj))
    return events


def allowed_input(path: Path, repository: Path, fixture: bool) -> bool:
    resolved = path.resolve()
    private = (repository / ".lab").resolve()
    fixture_dir = (repository / "tests" / "fixtures").resolve()
    if private not in resolved.parents and resolved != private:
        if not fixture or fixture_dir not in resolved.parents:
            return False
    if path.is_symlink():
        return False
    return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=".lab/m1-normalized-events.jsonl",
                        help="private, independently normalized JSONL under .lab/")
    parser.add_argument("--fixture", action="store_true",
                        help="allow files in tests/fixtures for synthetic CI only")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    path = Path(args.input)
    if not path.is_absolute():
        path = repo / path
    try:
        if not allowed_input(path, repo, args.fixture):
            raise ValueError("input must be under .lab/ (or tests/fixtures with --fixture)")
        result = correlate(load_events(path))
    except (OSError, UnicodeError, ValueError) as exc:
        # Never echo paths, event IDs, or raw data into CI logs.
        print("M1_INPUT_REJECTED: " + str(exc), file=sys.stderr)
        return 2
    result["sample_provenance"] = (
        "synthetic_fixture" if args.fixture else "user_supplied_normalized_not_independently_verified"
    )
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
