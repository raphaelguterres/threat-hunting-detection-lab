#!/usr/bin/env python3
"""Import an operator-collected Wazuh inventory CSV into a PRIVATE, non-authorizing M1 manifest.

Requires explicit --apply; default is validation-only. NEVER queries agents or the Manager.
All CSV and manifest paths must be inside the ignored .lab/ directory.
"""
import argparse
import csv
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import tempfile

REPO = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = (REPO / ".lab").resolve()
COLUMNS = ("id", "os", "groups", "status", "sync", "observed_at", "evidence_ref")


def contained(path):
    return path.resolve().is_relative_to(PRIVATE_ROOT)


def parse_rows(path):
    if not contained(path) or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("inventory file unavailable or outside private directory")
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or tuple(reader.fieldnames) != COLUMNS:
            raise ValueError("inventory CSV header missing or changed")
        rows = list(reader)
    if len(rows) != 4:
        raise ValueError("expected exactly four member rows")
    agents, ids = [], set()
    for row in rows:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("inventory row missing or surplus fields")
        ident, operating_system = row["id"].strip(), row["os"].strip()
        if not re.fullmatch(r"[0-9]{3,6}", ident) or ident in ids:
            raise ValueError("duplicate or invalid agent ID")
        ids.add(ident)
        if not operating_system.startswith(("Windows", "Linux", "macOS")):
            raise ValueError("unsupported or unknown OS")
        if ident == "004" and not operating_system.startswith("Windows"):
            raise ValueError("agent 004 OS conflicts with corroborated Windows baseline")
        groups = [group.strip() for group in row["groups"].split(";")]
        if not groups or any(not group for group in groups) or "default" not in groups:
            raise ValueError("agent does not belong to default")
        if row["status"].strip().lower() != "active" or row["sync"].strip().lower() != "synced":
            raise ValueError("agent active/sync state not confirmed")
        evidence = row["evidence_ref"].strip()
        if not evidence or len(evidence) > 256:
            raise ValueError("missing or invalid evidence reference")
        observed = row["observed_at"].strip()
        try:
            timestamp = datetime.fromisoformat(observed)
        except ValueError as exc:
            raise ValueError("invalid evidence timestamp") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("evidence timestamp missing timezone")
        age = datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)
        if age > timedelta(hours=24) or age < -timedelta(minutes=5):
            raise ValueError("stale or future-dated inventory evidence")
        agents.append({
            "id": ident, "os": operating_system, "groups": groups,
            "status": "active", "sync": "synced",
            "observed_at": observed, "evidence_ref": evidence,
        })
    if "004" not in ids:
        raise ValueError("agent 004 missing from group default")
    return agents


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest JSON key")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise ValueError("nonfinite manifest value")


def prepare_manifest(path, agents):
    if not contained(path):
        raise ValueError("manifest must remain private")
    if path.exists():
        if not path.is_file() or path.stat().st_size > 65536:
            raise ValueError("manifest is not a readable local file")
        old = json.loads(path.read_text(encoding="utf-8-sig"),
                         object_pairs_hook=strict_pairs,
                         parse_constant=reject_nonfinite)
        if (not isinstance(old, dict) or type(old.get("schema_version")) is not int
                or old["schema_version"] != 1 or old.get("change_id") != "M1-FIM-OS-SCOPE"):
            raise ValueError("unexpected manifest schema")
    else:
        old = {"schema_version": 1, "change_id": "M1-FIM-OS-SCOPE", "checks": {}}
    # A changed inventory invalidates dependent reviews/approvals/post-change claims.
    # Preserve unrelated baseline/backup evidence, never auto-upgrade any gate.
    if old.get("agents") != agents:
        checks = old.get("checks")
        if not isinstance(checks, dict):
            raise ValueError("invalid checks section")
        dependent = (
            "inventory_review", "os_impact_review", "change_approval",
            "approved_window", "agents_resynced", "windows_fim", "linux_fim",
            "manager_ingestion", "indexer_ingestion", "discover_visibility",
        )
        for name in dependent:
            if name in checks:
                checks[name] = {"status": "pending", "evidence_ref": ""}
    old["agents"] = agents
    return old


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=REPO / ".lab/m1-evidence.json")
    parser.add_argument("--apply", action="store_true", help="Explicitly update the private manifest")
    args = parser.parse_args()
    try:
        agents = parse_rows(args.csv)
        manifest = prepare_manifest(args.manifest, agents)
        if args.apply:
            path = args.manifest.resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".m1-inventory-", suffix=".tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    json.dump(manifest, stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        print("CSV_STRUCTURE=VALID")
        print("MANIFEST_UPDATED=" + str(args.apply))
        print("INDEPENDENT_EVIDENCE_REVIEW_REQUIRED=true")
        print("DEPLOYMENT_GATE=BLOCKED")
        print("NO_REMOTE_CONNECTION_NO_CONFIGURATION_CHANGE=true")
        return 0
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        print("CSV_STRUCTURE=INVALID_OR_UNREADABLE")
        print("MANIFEST_UPDATED=False")
        print("DEPLOYMENT_GATE=BLOCKED")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
