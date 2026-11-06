#!/usr/bin/env python3
"""Offline H01 rule-scope contract check. Never contacts Wazuh or executes a probe.

Input is an authorized private XML snapshot of the Manager's custom rule 110100.
Checks policy drift and synthetic command-line matching; NOT event ingestion.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 16 * 1024
EXPECTED_FIELDS = {
    "win.system.providerName": "^Microsoft-Windows-Sysmon$",
    "win.system.eventID": "^1$",
    "win.eventdata.image": r"(?i)\\(powershell|pwsh)\.exe$",
    "win.eventdata.commandLine": r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+",
}


def safe_rule_file(value: Path, fixture=False) -> Path:
    base = (ROOT / ("tests/fixtures" if fixture else ".lab")).resolve(strict=True)
    candidate = value if value.is_absolute() else ROOT / value
    absolute = candidate.absolute()
    if any(part.is_symlink() for part in (absolute, *absolute.parents)):
        raise ValueError("symlinks not permitted")
    path = absolute.resolve(strict=True)
    if not path.is_file() or not path.is_relative_to(base):
        raise ValueError("rule file outside permitted directory")
    if not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError("invalid rule snapshot size")
    if fixture and "synthetic" not in path.name.lower():
        raise ValueError("synthetic fixtures must be clearly named")
    return path


def check_scope(xml_bytes: bytes) -> dict:
    if b"<!DOCTYPE" in xml_bytes.upper() or b"<!ENTITY" in xml_bytes.upper():
        raise ValueError("DTD and entities are not accepted")
    root = ET.fromstring(xml_bytes)
    if root.tag != "group":
        raise ValueError("unexpected XML root")
    rules = [element for element in root.iter("rule")
             if element.attrib.get("id") == "110100"]
    if len(rules) != 1:
        raise ValueError("expected exactly one rule 110100")
    rule = rules[0]
    if rule.attrib.get("level") != "12":
        raise ValueError("rule severity drift")
    parents = rule.findtext("if_sid", "").split(",")
    if [value.strip() for value in parents] != ["61603", "92057"]:
        raise ValueError("parent rules drift")
    fields = rule.findall("field")
    if len(fields) != len(EXPECTED_FIELDS):
        raise ValueError("unexpected field count")
    actual = {}
    for field in fields:
        name = field.attrib.get("name")
        if name in actual or name not in EXPECTED_FIELDS:
            raise ValueError("unexpected/duplicate field")
        if name in ("win.eventdata.image", "win.eventdata.commandLine"):
            if field.attrib.get("type") != "pcre2":
                raise ValueError("PCRE matcher type drift")
        actual[name] = field.text or ""
    if actual != EXPECTED_FIELDS:
        raise ValueError("rule matcher drift")
    image = re.compile(actual["win.eventdata.image"])
    command = re.compile(actual["win.eventdata.commandLine"])
    cases = (
        ("prior_benign_file", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         r"powershell.exe -NoLogo -NoProfile -NonInteractive -File C:\Lab\M1_H01_CONTROLLED_TEST_20261105.ps1", False),
        ("encoded_full", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABl", True),
        ("encoded_short", r"C:\Program Files\PowerShell\7\pwsh.exe",
         "pwsh.exe -enc VwByAGkAdABl", True),
        ("benign_command", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "powershell.exe -NoProfile -Command Write-Output hello", False),
        ("other_process", r"C:\Windows\System32\cmd.exe",
         "cmd.exe -EncodedCommand VwByAGkAdABl", False),
    )
    for _, binary, invocation, expected in cases:
        actual_match = bool(image.search(binary) and command.search(invocation))
        if actual_match != expected:
            raise ValueError("synthetic H01 matching contract mismatch")
    return {
        "rule_id": "110100",
        "scope": "encoded_powershell_only",
        "rule_level": 12,
        "default_sysmon_level": "not_verified_by_this_xml_snapshot",
        "prior_benign_file_matches": False,
        "encoded_invocations_match": True,
        "synthetic_vectors_passed": len(cases),
        "policy_drift": False,
        "runtime_rule_loading_attested": False,
        "manager_raw_event_inspected": False,
        "event_ingestion_verified": False,
        "safe_operational_action": "no_active_change_required_to_explain_prior_non_alert",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", required=True, type=Path)
    parser.add_argument("--fixture", action="store_true",
                        help="synthetic test XML within tests/fixtures only")
    args = parser.parse_args(argv)
    try:
        path = safe_rule_file(args.rule, args.fixture)
        report = check_scope(path.read_bytes())
    except (ValueError, OSError, ET.ParseError, RecursionError):
        print("H01_RULE_SCOPE=UNVERIFIED_OR_DRIFTED", file=sys.stderr)
        return 2
    report["sample_provenance"] = ("SYNTHETIC_FIXTURE_ONLY" if args.fixture
                                   else "PRIVATE_AUTHORIZED_MANAGER_RULE_SNAPSHOT")
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
