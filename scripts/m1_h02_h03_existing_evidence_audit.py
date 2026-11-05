#!/usr/bin/env python3
"""M1 H02/H03: bounded, offline assessment of pre-existing private evidence.

Never invokes Wazuh, PowerShell, Windows, network, or executable probe files.
Output is counts and limitations only; historical summaries are not independent
attestation or a substitute for raw source correlation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
H02_KEYS = (
    "account_created_events",
    "account_events_with_target_sid",
    "privileged_logons_same_sid_30m",
    "successful_logons_same_sid_30m",
    "matching_4624_4672_logon_id_chains",
)
MAX_SOURCE_BYTES = 64 * 1024


def safe_file(path: Path, base: Path) -> Path:
    root = base.resolve(strict=True)
    absolute = (path if path.is_absolute() else ROOT / path).absolute()
    if any(parent.is_symlink() for parent in (absolute, *absolute.parents)):
        raise ValueError("symlinks are not evidence")
    target = absolute.resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError("evidence is outside private scope")
    if not 0 < target.stat().st_size <= MAX_SOURCE_BYTES:
        raise ValueError("evidence size invalid")
    return target


def json_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def invalid_nonfinite(_):
    raise ValueError("non-finite number")


def parse_h02(content: str) -> dict:
    lines = content.splitlines()
    expected_header = "M1_H02_SECURITY_AUDIT 2026-10-31T00:00Z_TO_2026-11-03T00:00Z"
    if not lines or lines[0].strip() != expected_header:
        raise ValueError("unexpected H02 historical window")
    values = {}
    for line in lines[1:]:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in H02_KEYS:
            if key in values or not re.fullmatch(r"(0|[1-9][0-9]{0,7})", value):
                raise ValueError("duplicate or invalid H02 count")
            values[key] = int(value)
    if set(values) != set(H02_KEYS):
        raise ValueError("incomplete H02 counts")
    if values["account_events_with_target_sid"] > values["account_created_events"]:
        raise ValueError("impossible SID count")
    return values


def parse_json(content: str) -> dict:
    value = json.loads(content, object_pairs_hook=json_unique, parse_constant=invalid_nonfinite)
    if not isinstance(value, dict):
        raise ValueError("evidence must be object")
    return value


def audit(h02: dict, fim: dict, h03: dict) -> dict:
    if fim.get("agent_id") != "004" or h03.get("agent_id") != "004":
        raise ValueError("agent scope drift")
    operations = fim.get("event_counts")
    if not isinstance(operations, dict):
        raise ValueError("missing FIM operation counts")
    if set(operations) != {"added", "modified", "deleted"}:
        raise ValueError("unexpected FIM operations")
    if any(type(operations[k]) is not int or operations[k] != 1 for k in operations):
        raise ValueError("FIM operation counts invalid")
    if (type(fim.get("exact_artifact_hits")) is not int
            or fim["exact_artifact_hits"] != 3):
        raise ValueError("FIM artifact hit count invalid")
    if fim.get("file_extension") != ".m1probe":
        raise ValueError("FIM non-executable scope drift")
    for name in ("guest_cleanup_verified", "config_changes",
                 "service_restart", "auditpol_changed",
                 "local_manager_log_independently_verified"):
        expected = name == "guest_cleanup_verified"
        if fim.get(name) is not expected:
            raise ValueError("FIM safety context changed")
    if (h03.get("status") != "READONLY_PARTIAL"
            or h03.get("target_exists") is not False
            or h03.get("parent_exists") is not False
            or h03.get("security_gate") != "NO_GO"
            or h03.get("operator_review_required") is not True
            or h03.get("effective_fim_coverage_of_future_target")
            != "not_present_currently"):
        raise ValueError("historical H03 safety gate drift")
    if (type(h03.get("local_directories")) is not int or
            type(h03.get("local_realtime_directories")) is not int or
            h03["local_directories"] < 1 or
            h03["local_realtime_directories"] > h03["local_directories"]):
        raise ValueError("H03 baseline invalid")
    h02_matches = (h02["privileged_logons_same_sid_30m"],
                   h02["successful_logons_same_sid_30m"],
                   h02["matching_4624_4672_logon_id_chains"])
    # A nonzero value is not a validated correlation without source Logon IDs.
    h02_status = ("NO_SAME_SID_CHAIN_IN_HISTORICAL_SAMPLE"
                  if h02["account_created_events"] > 0 and
                  h02["account_events_with_target_sid"] > 0 and
                  h02_matches == (0, 0, 0)
                  else "H02_REQUIRES_IDENTITY_LEVEL_INDEPENDENT_REVIEW")
    return {
        "result": "HISTORICAL_EVIDENCE_REVIEW_NOT_FULL_CORRELATION",
        "h02": {
            "window_utc": "2026-10-31T00:00:00Z..2026-11-03T00:00:00Z",
            **h02,
            "status": h02_status,
            "negative_scope": "30_minutes_only",
            "account_compromise_assessed": False,
        },
        "h03": {
            "agent": "004",
            "benign_fim_added_modified_deleted": [operations[k]
                                                     for k in ("added", "modified", "deleted")],
            "fim_indexer_events_same_artifact": 3,
            "fim_probe_executable": False,
            "cleanup_verified": True,
            "change_c_baseline_date": "2026-11-04",
            "change_c_target_existed_on_baseline": False,
            "change_c_gate_on_baseline": "NO_GO",
            "same_artifact_execution_attested": False,
            "fim_then_same_executable_pair_verified": False,
            "status": "FIM_CONFIRMED_EXECUTION_SOURCE_NOT_CORRELATED",
        },
        "review_limitations": {
            "inputs": "pre_existing_private_summary_not_independent_raw_events",
            "h02_source_identity_revalidated": False,
            "h03_sysmon_same_artifact_verified": False,
            "manager_alert_json_accessed": False,
            "active_lab_changes": False,
            "new_test_events_generated": False,
            "production_or_change_a_approval": False,
            "m1_checklist": "15/17",
        }
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--h02", type=Path, default=Path(".lab/m1-native-bridge/m1-h02-summary.txt"))
    parser.add_argument("--fim", type=Path, default=Path(".lab/m1-fim004-windows-discover-20261105-private.json"))
    parser.add_argument("--h03", type=Path, default=Path(".lab/m1-change-prep/H03_CHANGE_C_BASELINE_SUMMARY_PRIVATE_20261104.json"))
    parser.add_argument("--fixture", action="store_true", help="tests/fixtures only: synthetic input")
    args = parser.parse_args(argv)
    try:
        base = ROOT / ("tests/fixtures" if args.fixture else ".lab")
        paths = [safe_file(p, base) for p in (args.h02, args.fim, args.h03)]
        if len(set(paths)) != 3 or (args.fixture and
                                    any("synthetic" not in p.name.lower() for p in paths)):
            raise ValueError("sources must be distinct and fixture labelled")
        source = [p.read_text(encoding="utf-8-sig") for p in paths]
        report = audit(parse_h02(source[0]), parse_json(source[1]), parse_json(source[2]))
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        print("H02_H03_EVIDENCE=INPUT_REJECTED_NO_ACCEPTANCE", file=sys.stderr)
        return 2
    report["evidence_mode"] = "SYNTHETIC_FIXTURES" if args.fixture else "PRIVATE_HISTORICAL"
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
