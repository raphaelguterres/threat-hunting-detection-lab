#!/usr/bin/env python3
"""Offline fail-closed H03 candidate path screening (not deployment approval).

This heuristic prevents unsafe test-target selection. It does not read the
endpoint, prove Syscheck coverage, evaluate Wazuh ignore regexes, or authorize
executing/modifying an artifact. Paths are never printed.
"""
from __future__ import annotations

import argparse
import json
import ntpath
from pathlib import PureWindowsPath


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part.casefold() for part in PureWindowsPath(path).parts)


def classify_candidate(root: str, candidate: str, mode: str) -> dict[str, str]:
    result = {
        "status": "REVIEW_REQUIRED",
        "reason": "coverage_exclusions_approval_not_verified",
        "test_approved": "false",
        "effective_fim_coverage": "unverified",
    }
    if not root or not candidate:
        result.update(status="NO_GO", reason="missing_root_or_candidate")
        return result

    root_parts = _parts(root)
    candidate_parts = _parts(candidate)
    all_parts = root_parts + candidate_parts

    # Any startup or autostart folder is prohibited for an executable probe.
    if "startup" in all_parts and "start menu" in all_parts:
        result.update(status="NO_GO", reason="autostart_startup_folder")
        return result
    if "startup" in root_parts:
        result.update(status="NO_GO", reason="autostart_folder")
        return result

    for unsafe in ("windows", "program files", "program files (x86)"):
        if unsafe in root_parts:
            result.update(status="NO_GO", reason="operating_system_or_program_directory")
            return result

    if not ntpath.isabs(root) or not ntpath.isabs(candidate):
        result.update(status="NO_GO", reason="unresolved_or_relative_path")
        return result

    norm_root = ntpath.normcase(ntpath.normpath(root))
    norm_candidate = ntpath.normcase(ntpath.normpath(candidate))
    drive_root, drive_candidate = ntpath.splitdrive(norm_root)[0], ntpath.splitdrive(norm_candidate)[0]
    if not drive_root or drive_root != drive_candidate:
        result.update(status="NO_GO", reason="different_or_missing_drive")
        return result
    if ntpath.dirname(norm_root) == drive_root + "\\":
        result.update(status="NO_GO", reason="volume_root_or_direct_child")
        return result
    try:
        inside = ntpath.commonpath([norm_root, norm_candidate]) == norm_root
    except ValueError:
        inside = False
    if not inside or norm_candidate == norm_root:
        result.update(status="NO_GO", reason="candidate_not_beneath_monitored_root")
        return result

    if ntpath.splitext(norm_candidate)[1] != ".exe":
        result.update(status="NO_GO", reason="candidate_not_executable")
        return result

    if mode != "realtime":
        result.update(status="REVIEW_REQUIRED", reason="scheduled_scan_may_exceed_h03_window")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="private FIM root; never printed")
    parser.add_argument("--candidate", required=True, help="private candidate; never printed")
    parser.add_argument("--mode", choices=("realtime", "scheduled", "whodata"), required=True)
    args = parser.parse_args(argv)
    print(json.dumps(classify_candidate(args.root, args.candidate, args.mode), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
