#!/usr/bin/env python3
"""Read-only aggregate of a single Wazuh Manager alerts JSONL file for M1/H03.

Prints counts and UTC window only: never paths, users, events, hashes or raw logs.
An active file is not seven-day evidence and this audit is not a correlation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import re
from pathlib import Path


FILE_RULES = frozenset({"550", "553", "554"})
REGISTRY_RULES = frozenset({"594", "597", "598", "750", "751", "752"})
COUNTER_NAMES = (
    "agent_alerts", "syscheck_objects", "syscheck_paths", "registry_paths",
    "nonregistry_paths", "fim_file_rules", "fim_registry_rules",
    "sysmon_events", "sysmon_eid1", "security_events",
    "invalid_json_lines", "invalid_timestamp",
)


def obj(value):
    return value if isinstance(value, dict) else {}


def parse_utc(value):
    if not isinstance(value, str):
        return None
    try:
        normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.replace("Z", "+00:00"))
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def audit_alerts(path: Path, agent_id: str = "004"):
    counters = Counter()
    seen_times = []
    target = str(agent_id).zfill(3)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                counters["invalid_json_lines"] += 1
                continue
            event = obj(event)
            agent = obj(event.get("agent"))
            if str(agent.get("id", "")).zfill(3) != target:
                continue
            counters["agent_alerts"] += 1
            if "syscheck" in event:
                counters["syscheck_objects"] += 1
            syscheck_path = obj(event.get("syscheck")).get("path")
            if isinstance(syscheck_path, str) and syscheck_path:
                counters["syscheck_paths"] += 1
                key = ("registry_paths" if syscheck_path.casefold().startswith("hkey")
                       else "nonregistry_paths")
                counters[key] += 1
            rule_id = str(obj(event.get("rule")).get("id", ""))
            if rule_id in FILE_RULES:
                counters["fim_file_rules"] += 1
            elif rule_id in REGISTRY_RULES:
                counters["fim_registry_rules"] += 1
            system = obj(obj(obj(event.get("data")).get("win")).get("system"))
            channel = str(system.get("channel", "")).casefold()
            if "sysmon" in channel:
                counters["sysmon_events"] += 1
                if str(system.get("eventID", "")) == "1":
                    counters["sysmon_eid1"] += 1
            elif "security" in channel:
                counters["security_events"] += 1
            stamp = parse_utc(event.get("timestamp"))
            if stamp is None:
                counters["invalid_timestamp"] += 1
            else:
                seen_times.append(stamp)
    return {
        "scope": "single_active_manager_alerts_file",
        "agent_id": target,
        "first_timestamp_utc": min(seen_times).isoformat() if seen_times else "none",
        "last_timestamp_utc": max(seen_times).isoformat() if seen_times else "none",
        "counts": {key: counters[key] for key in COUNTER_NAMES},
        "h03_real_pair": "not_assessed",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--agent-id", default="004")
    args = parser.parse_args(argv)
    try:
        result = audit_alerts(args.input, args.agent_id)
    except (OSError, UnicodeError):
        print("ERROR=INPUT_UNAVAILABLE")
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
