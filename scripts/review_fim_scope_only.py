#!/usr/bin/env python3
"""Review an offline, STAGED agent.conf update, without applying it.

Only an addition of os="^Linux" to an originally unscoped agent_config
that refers exclusively to Unix FIM/log paths can pass. All other XML
elements, attributes, values, and comments must remain identical.

This structural comparison is NOT Wazuh's verify-agent-conf. It never
reads Manager files or prints the private content. It makes no writes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

MAX_BYTES = 65536
FORBIDDEN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b|<\?xml\b", re.I)
WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/]|%[A-Za-z_][A-Za-z_0-9]*%[\\/]|\\\\")
WINDOWS_EVENT_FORMATS = frozenset({"eventchannel", "eventlog"})


def _parse(text: str) -> ET.Element:
    if FORBIDDEN.search(text):
        raise ValueError("declarations not allowed")
    try:
        root = ET.fromstring("<review>" + text + "</review>",
                             parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
    except ET.ParseError as exc:
        raise ValueError("invalid XML fragment") from exc
    if not any(c.tag == "agent_config" for c in root):
        raise ValueError("no agent_config blocks")
    if any(c.tag not in ("agent_config", ET.Comment) for c in root):
        raise ValueError("unexpected top level")
    return root


def _value(text: str | None) -> str:
    """Ignore indentation-only whitespace, not meaningful element values."""
    return "" if text is None or not text.strip() else text


def _unix_only(block: ET.Element) -> bool:
    # Inspect the entire staged block, not just recognized FIM/log locations.
    # Mixed-platform settings must never be silently classified as Unix-only.
    for node in block.iter():
        if not isinstance(node.tag, str):
            continue
        tag = node.tag.lower()
        if "registry" in tag or tag.startswith("windows_"):
            return False
        if tag == "log_format" and (node.text or "").strip().lower() in WINDOWS_EVENT_FORMATS:
            return False
        if WINDOWS_PATH.search(node.text or ""):
            return False
        if any(WINDOWS_PATH.search(value) for value in node.attrib.values()):
            return False
    locations = []
    for dirs in block.findall("./syscheck/directories"):
        locations.extend(x.strip() for x in (dirs.text or "").split(","))
    for loc in block.findall("./localfile/location"):
        locations.append((loc.text or "").strip())
    return bool(locations) and all(p.startswith("/") and not p.startswith("//") for p in locations)


def compare(original: str, proposed: str) -> dict:
    before = _parse(original)
    after = _parse(proposed)
    changes = 0
    examined = 0

    def visit(a: ET.Element, b: ET.Element) -> None:
        nonlocal changes, examined
        if a.tag != b.tag or _value(a.text) != _value(b.text) or _value(a.tail) != _value(b.tail):
            raise ValueError("elements or values changed")
        if len(a) != len(b):
            raise ValueError("element count changed")
        old_attrs, new_attrs = dict(a.attrib), dict(b.attrib)
        if a.tag == "agent_config":
            examined += 1
            expected = dict(old_attrs)
            if old_attrs.get("os") is None and _unix_only(a):
                expected["os"] = "^Linux"
                if new_attrs == expected:
                    changes += 1
                else:
                    raise ValueError("Linux block was not correctly scoped")
            elif new_attrs != expected:
                raise ValueError("non-Linux block or existing scope changed")
        elif old_attrs != new_attrs:
            raise ValueError("nested element attributes changed")
        for aa, bb in zip(a, b):
            visit(aa, bb)

    visit(before, after)
    if changes == 0:
        raise ValueError("no eligible OS-only change")
    return {
        "result": "scope_only_structural_match",
        "blocks_checked": examined,
        "linux_scope_additions": changes,
        "payload_structure_unchanged": True,
        "wazuh_parser_verified": False,
        "deployment_performed": False,
    }


def _input_allowed(path: Path, repo: Path, fixture: bool) -> bool:
    base = repo / ("tests/fixtures" if fixture else ".lab")
    if path.is_symlink() or base.is_symlink():
        return False
    return base.resolve() in path.resolve().parents


def _read(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("missing or oversized input")
    return path.read_text(encoding="utf-8-sig")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--original", required=True)
    ap.add_argument("--proposed", required=True)
    ap.add_argument("--fixture", action="store_true",
                    help="allow synthetic fixtures in tests/fixtures instead of private .lab")
    args = ap.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    original, proposed = Path(args.original), Path(args.proposed)
    if not original.is_absolute():
        original = repo / original
    if not proposed.is_absolute():
        proposed = repo / proposed
    try:
        if not _input_allowed(original, repo, args.fixture) or not _input_allowed(
                proposed, repo, args.fixture):
            raise ValueError("input not in approved private/fixture directory")
        answer = compare(_read(original), _read(proposed))
    except (OSError, UnicodeError, ValueError):
        print("M1_SCOPE_CHANGE_REJECTED", file=sys.stderr)
        return 2
    answer["input_provenance"] = (
        "synthetic_fixture" if args.fixture else "private_staged_unverified"
    )
    print(json.dumps(answer, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
