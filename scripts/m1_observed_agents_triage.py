#!/usr/bin/env python3
"""Summarize incomplete operator-observed agents without ever authorizing a change.

Input must be an operator-created JSON snapshot inside ignored .lab/.
Never connects to Wazuh, reveals identifiers or writes input/output files.
This preliminary workflow is deliberately separate from the stricter M1 inventory gate.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

from m1_import_authorized_inventory import contained, os_display_family


STATUS = {"active", "disconnected", "never connected", "pending"}
SYNC = {"synced", "not_synced", "unverified"}


def _unique_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError("duplicate JSON key")
        data[key] = value
    return data


def _invalid_constant(value):
    raise ValueError("invalid JSON constant")


def _parse_timestamp(value, now):
    """Return aware UTC time or None; never infer a missing Dashboard timestamp."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string or null")
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise ValueError("timestamp without timezone")
    instant = stamp.astimezone(timezone.utc)
    if instant > now + timedelta(minutes=5):
        raise ValueError("future-dated Dashboard timestamp")
    return instant


def summarize(data):
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("invalid snapshot schema")
    agents = data.get("agents")
    if not isinstance(agents, list) or len(agents) != 4:
        raise ValueError("expected four observed rows, not four verified group members")
    seen, statuses = set(), {name: 0 for name in STATUS}
    linux = windows = other = groups_unknown = sync_unknown = 0
    keepalive_unknown = time_unknown = default_observed = 0
    now = datetime.now(timezone.utc)
    for row in agents:
        if not isinstance(row, dict):
            raise ValueError("invalid agent row")
        ident = row.get("id")
        if not isinstance(ident, str) or not re.fullmatch(r"[0-9]{3,6}", ident) or ident in seen:
            raise ValueError("invalid or duplicate ID")
        seen.add(ident)
        family = os_display_family(row.get("os"))
        if family == "Linux":
            linux += 1
        elif family == "Windows":
            windows += 1
        else:
            other += 1
        status = row.get("status")
        if status not in STATUS:
            raise ValueError("unsupported observed connection status")
        statuses[status] += 1
        group_order = row.get("groups_ordered")
        if group_order is None:
            groups_unknown += 1
        elif (not isinstance(group_order, list)
              or not group_order
              or not all(isinstance(g, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", g)
                         for g in group_order)
              or len(group_order) != len(set(group_order))):
            raise ValueError("invalid ordered group list")
        elif "default" in group_order:
            default_observed += 1
        sync = row.get("group_sync")
        if sync not in SYNC:
            raise ValueError("unsupported or missing group sync state")
        if sync == "unverified":
            sync_unknown += 1
        keepalive = _parse_timestamp(row.get("last_keepalive"), now)
        observed = _parse_timestamp(row.get("observed_at"), now)
        if keepalive is None:
            keepalive_unknown += 1
        if observed is None:
            time_unknown += 1
        if keepalive is not None and observed is not None and keepalive > observed + timedelta(minutes=5):
            raise ValueError("keepalive newer than Dashboard observation")
        evidence = row.get("evidence_ref")
        if (not isinstance(evidence, str) or not evidence or len(evidence) > 256
                or any(ord(c) < 32 or ord(c) == 127 for c in evidence)):
            raise ValueError("invalid operator snapshot reference")
    return {
        "SNAPSHOT_CLASS": "PRELIMINARY_UNATTESTED",
        "OBSERVED_ROWS": len(agents),
        "LINUX_FAMILY_OBSERVED": linux,
        "WINDOWS_FAMILY_OBSERVED": windows,
        "OTHER_FAMILY_OBSERVED": other,
        "STATUS_ACTIVE": statuses["active"],
        "STATUS_DISCONNECTED": statuses["disconnected"],
        "STATUS_NEVER_CONNECTED": statuses["never connected"],
        "STATUS_PENDING": statuses["pending"],
        "DEFAULT_MEMBERSHIP_OBSERVED": default_observed,
        "GROUP_MEMBERSHIP_UNKNOWN": groups_unknown,
        "GROUP_SYNC_UNKNOWN": sync_unknown,
        "LAST_KEEPALIVE_UNKNOWN": keepalive_unknown,
        "OBSERVATION_TIMESTAMP_UNKNOWN": time_unknown,
        "AGENT_CONFIG_OS_REGEX_CHECKED": False,
        "GROUP_MEMBERSHIP_ATTESTED": False,
        "DEPLOYMENT_GATE": "BLOCKED",
        "WRITES_PERFORMED": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    try:
        path = args.snapshot
        if not contained(path) or not path.is_file() or path.stat().st_size > 32768:
            raise ValueError("unauthorized or oversized snapshot")
        with path.open(encoding="utf-8-sig") as stream:
            data = json.load(stream, object_pairs_hook=_unique_keys,
                             parse_constant=_invalid_constant)
        result = summarize(data)
    except (OSError, UnicodeError, ValueError, RuntimeError, RecursionError, TypeError):
        print("OBSERVATION_SNAPSHOT=INVALID_OR_UNREADABLE")
        print("DEPLOYMENT_GATE=BLOCKED")
        print("WRITES_PERFORMED=false")
        return 2
    for key, value in result.items():
        print(f"{key}={str(value).lower() if isinstance(value, bool) else value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
