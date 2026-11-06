#!/usr/bin/env python3
"""Fail-closed, offline diff gate for the proposed Windows agent 004 H03 FIM change.

Compares two private XML files (baseline and proposed), or two explicitly
synthetic fixtures. NEVER edits XML, ACL, VM, Wazuh, or executes a probe.

Success means only that the candidate adds one isolated real-time FIM
directory. It is never change authorization or evidence of active coverage.
"""
from __future__ import annotations

import argparse
import json
import ntpath
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = r"C:\SecurityLab\H03"
MAX_XML_BYTES = 256 * 1024


def protected_file(path: Path, fixture: bool) -> Path:
    base = (ROOT / ("tests/fixtures" if fixture else ".lab")).resolve(strict=True)
    candidate = (path if path.is_absolute() else ROOT / path).absolute()
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        raise ValueError("symlink input prohibited")
    target = candidate.resolve(strict=True)
    if (not target.is_file() or not target.is_relative_to(base) or
            not 0 < target.stat().st_size <= MAX_XML_BYTES):
        raise ValueError("file outside private input scope or invalid size")
    if fixture and "synthetic" not in target.name.lower():
        raise ValueError("fixture filenames must say synthetic")
    return target


def parse_xml(raw: bytes) -> ET.Element:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("DTD/entities not permitted")
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    root = ET.fromstring(raw, parser=parser)
    if root.tag != "ossec_config":
        raise ValueError("unexpected ossec.conf root")
    return root


def find_single_syscheck(root: ET.Element) -> ET.Element:
    nodes = root.findall("./syscheck")
    if len(nodes) != 1:
        raise ValueError("expected exactly one syscheck block")
    return nodes[0]


def normalized_path(value: str) -> str:
    if not value or "\x00" in value or "," in value:
        raise ValueError("invalid monitored path")
    return ntpath.normcase(ntpath.normpath(value.strip()))


def compare(baseline_raw: bytes, proposal_raw: bytes) -> dict:
    old = parse_xml(baseline_raw)
    new = parse_xml(proposal_raw)
    old_sys = find_single_syscheck(old)
    new_sys = find_single_syscheck(new)
    expected_path = normalized_path(EXPECTED)

    # Do not mistake an existing directory for an authorized new directive.
    for node in old_sys.findall("./directories"):
        # Wazuh permits comma-separated pre-existing directory paths.
        # Preserve those nodes intact; only reject if they already cover
        # the exact proposed target.
        existing_paths = [p.strip() for p in (node.text or "").split(",") if p.strip()]
        if any(normalized_path(p) == expected_path for p in existing_paths):
            raise ValueError("target already monitored in baseline")

    new_matches = [
        node for node in new_sys.findall("./directories")
        if node.text and "," not in node.text
        and normalized_path(node.text) == expected_path
    ]
    if len(new_matches) != 1:
        raise ValueError("candidate must add exactly one target directive")
    addition = new_matches[0]
    if (addition.attrib != {"realtime": "yes", "check_all": "yes"} or
            list(addition) or len(new_matches) != 1):
        raise ValueError("target monitoring attributes out of scope")

    # After removing the one permitted addition, every other node, field,
    # attribute, comment and effective setting must be identical to baseline.
    new_sys.remove(addition)
    canonical_old = ET.canonicalize(
        ET.tostring(old, encoding="unicode"), with_comments=True, strip_text=True)
    canonical_new = ET.canonicalize(
        ET.tostring(new, encoding="unicode"), with_comments=True, strip_text=True)
    if canonical_old != canonical_new:
        raise ValueError("config diff exceeds the one allowed addition")

    return {
        "change": "H03_CHANGE_C_WINDOWS_AGENT_004_PROPOSAL_ONLY",
        "result": "ONE_FIM_REALTIME_DIRECTORY_ADD_ONLY",
        "target": "ISOLATED_WINDOWS_H03_LAB",
        "directive_count_added": 1,
        "realtime": True,
        "check_all": True,
        "shared_group_config_changed": False,
        "existing_fim_directives_changed": False,
        "rule_or_log_settings_changed": False,
        "acl_effective_verified": False,
        "target_exists_on_guest_verified": False,
        "agent_active_config_verified": False,
        "guest_files_written": False,
        "agent_restarted": False,
        "binary_executed": False,
        "go_for_change": False,
        "m1_checklist": "15/17",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--fixture", action="store_true",
                        help="accept labelled synthetic fixtures only under tests/fixtures")
    args = parser.parse_args(argv)
    try:
        before = protected_file(args.baseline, args.fixture)
        after = protected_file(args.candidate, args.fixture)
        if before == after:
            raise ValueError("baseline and candidate must differ")
        report = compare(before.read_bytes(), after.read_bytes())
    except (OSError, ValueError, ET.ParseError, RecursionError, TypeError):
        print("H03_CHANGE_C_OFFLINE_DIFF=NO_GO_UNVERIFIED", file=sys.stderr)
        return 2

    report["evidence"] = "SYNTHETIC_FIXTURE" if args.fixture else "PRIVATE_OFFLINE_XML_DIFF"
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
