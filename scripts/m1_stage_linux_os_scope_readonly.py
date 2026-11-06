#!/usr/bin/env python3
"""Stage EXACTLY ONE Linux OS selector in a PRIVATE local copy of Wazuh agent.conf.

Never connects to Wazuh, writes to the VM, changes agent.conf, restarts
services, approves a change, or validates runtime distribution. This gate
deliberately fails closed if the active central block changes shape.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from m1_import_authorized_inventory import contained
from validate_fim_os_scope import validate

MAX_BYTES = 65536
OPENING = b"<agent_config>"
REPLACEMENT = b'<agent_config os="^Linux">'


def stage_linux_only(original: bytes) -> tuple[bytes, dict[str, object]]:
    if not original or len(original) > MAX_BYTES:
        raise ValueError("missing or oversized original")
    upper = original.upper()
    if b"<!ENTITY" in upper or b"<!DOCTYPE" in upper:
        raise ValueError("entity and DTD declarations forbidden")
    try:
        text = original.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("not UTF-8") from exc
    if original.count(OPENING) != 1 or original.count(b"</agent_config>") != 1:
        raise ValueError("unexpected number or form of agent_config blocks")
    if re.search(r"<agent_config\s+[^>]+>", text):
        raise ValueError("already scoped or other attributes present")
    try:
        root = ET.fromstring("<fragment>" + text + "</fragment>")
    except ET.ParseError as exc:
        raise ValueError("invalid XML") from exc
    if len(root) != 1 or root[0].tag != "agent_config":
        raise ValueError("expected one central agent_config block")
    block = root[0]
    if block.attrib:
        raise ValueError("unexpected attributes")
    directories = block.findall("./syscheck/directories")
    locations = block.findall("./localfile/location")
    if len(directories) != 1 or len(locations) != 1:
        raise ValueError("expected one Linux FIM directory and one Linux log source")
    if directories[0].get("realtime") != "yes":
        raise ValueError("FIM realtime baseline changed")
    if not (directories[0].text or "").strip().startswith("/"):
        raise ValueError("non-Unix FIM path")
    if not (locations[0].text or "").strip().startswith("/"):
        raise ValueError("non-Unix log source")
    staged = original.replace(OPENING, REPLACEMENT, 1)
    if staged.replace(REPLACEMENT, OPENING, 1) != original:
        raise ValueError("unexpected diff after replacement")
    result = validate(staged.decode("utf-8-sig"))
    if any(result[key] != expected for key, expected in (
        ("linux_blocks", 1), ("windows_blocks", 0),
        ("linux_directories", 1), ("linux_log_sources", 1),
    )):
        raise ValueError("stage failed structural checks")
    return staged, {
        "mode": "offline_private_staging_only",
        "only_diff": 'add os="^Linux" to opening agent_config tag',
        "source_length": len(original),
        "staged_length": len(staged),
        "linux_agent_config_blocks": 1,
        "linux_realtime_directories_preserved": 1,
        "linux_log_sources_preserved": 1,
        "manager_parser_staged_verified": False,
        "runtime_os_selection_confirmed": False,
        "effective_fim_coverage_verified": False,
        "operator_review_required": True,
        "change_approved": False,
        "deployed": False,
        "deployment_gate": "BLOCKED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if (not contained(args.source) or not contained(args.output)
            or args.source == args.output or not args.source.is_file()
            or args.source.stat().st_size > MAX_BYTES or args.output.exists()
            or not args.output.parent.is_dir()):
            raise ValueError("private source/output invalid or output exists")
        staged, summary = stage_linux_only(args.source.read_bytes())
        with args.output.open("xb") as stream:
            stream.write(staged)
        if args.output.read_bytes() != staged:
            raise ValueError("staged file did not round trip")
        print(json.dumps(summary, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError, ET.ParseError):
        print("M1_LINUX_STAGING=REJECTED", file=sys.stderr)
        print("DEPLOYMENT_GATE=BLOCKED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
