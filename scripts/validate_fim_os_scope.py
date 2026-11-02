#!/usr/bin/env python3
"""Offline structural guard for PROPOSED Wazuh agent.conf OS targeting.

This is NOT Wazuh's verify-agent-conf, does not apply settings and does not
authenticate or communicate with an endpoint. It only checks synthetic/staged
XML fragments for broad, obvious cross-platform targeting mistakes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

MAX_SIZE = 65536
OS_SCOPES = {"^Linux": "Linux", "^Windows": "Windows"}
DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
ENV_PATH = re.compile(r"^%[A-Za-z_][A-Za-z_0-9]*%[\\/]")


def classify_path(value: str) -> str:
    if value.startswith("/"):
        return "unix"
    if DRIVE.match(value) or ENV_PATH.match(value):
        return "windows"
    if value.startswith("\\\\"):
        return "network"
    return "unknown"


def validate(text: str) -> dict[str, object]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("DTD and entity declarations are not allowed")
    if text.lstrip().startswith("<?xml"):
        raise ValueError("use agent_config fragments without XML declaration")
    try:
        root = ET.fromstring("<fragment>" + text + "</fragment>")
    except ET.ParseError as exc:
        raise ValueError("malformed agent.conf XML fragment") from exc
    blocks = list(root)
    if not blocks:
        raise ValueError("no agent_config blocks")
    totals = {"Linux": 0, "Windows": 0}
    dirs = {"Linux": 0, "Windows": 0}
    logs = {"Linux": 0, "Windows": 0}
    for block in blocks:
        if block.tag != "agent_config":
            raise ValueError("top-level element is not agent_config")
        os_regex = block.get("os")
        if os_regex not in OS_SCOPES or len(block.attrib) != 1:
            raise ValueError("OS must be explicitly anchored to ^Linux or ^Windows")
        os_family = OS_SCOPES[os_regex]
        totals[os_family] += 1
        for node in block.findall("./syscheck/directories"):
            items = [x.strip() for x in (node.text or "").split(",")]
            if not items or any(not item for item in items):
                raise ValueError("empty FIM directory")
            for item in items:
                kind = classify_path(item)
                if kind == "network":
                    raise ValueError("network path is not supported in this example")
                if kind.lower() != os_family.lower():
                    raise ValueError("FIM directory does not match its OS scope")
                dirs[os_family] += 1
        for node in block.findall("./localfile/location"):
            location = (node.text or "").strip()
            kind = classify_path(location)
            if kind.lower() != os_family.lower():
                raise ValueError("log location does not match its OS scope")
            logs[os_family] += 1
    return {
        "validation": "synthetic_structural_checks_only",
        "linux_blocks": totals["Linux"],
        "windows_blocks": totals["Windows"],
        "linux_directories": dirs["Linux"],
        "windows_directories": dirs["Windows"],
        "linux_log_sources": logs["Linux"],
        "windows_log_sources": logs["Windows"],
        "wazuh_parser_verified": False,
        "deployed": False,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, help="local proposed non-production XML fragment")
    args = p.parse_args(argv)
    path = Path(args.input)
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_SIZE:
            raise ValueError("file missing, linked or oversized")
        summary = validate(path.read_text(encoding="utf-8-sig"))
    except (ValueError, OSError, UnicodeError):
        print("M1_OS_SCOPE_REJECTED", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
