#!/usr/bin/env python3
"""Offline FIM OS-scope impact preview for manually authorized Wazuh inventory.

Never contacts a manager, never modifies a Wazuh config and never grants approval.
Aggregated output intentionally avoids agent IDs, OS versions or evidence references.
"""
import argparse
import json
from pathlib import Path
import re

from m1_import_authorized_inventory import parse_rows, contained

SELECTOR = re.compile(r"^Linux")


def preview(agents):
    """Summarize hypothetical selector effect; not a Wazuh runtime assertion."""
    if len(agents) != 4:
        raise ValueError("exactly four default agents required")
    affected = [a for a in agents if SELECTOR.search(a["os"])]
    excluded = [a for a in agents if not SELECTOR.search(a["os"])]
    multi_groups = [a for a in agents if len(a["groups"]) > 1]
    non_last_default = [a for a in agents if a["groups"][-1] != "default"]
    return {
        "schema_version": 1,
        "scope_expression": "^Linux",
        "agents_in_default": len(agents),
        "potential_linux_matches": len(affected),
        "potential_non_linux_exclusions": len(excluded),
        "multi_group_agents": len(multi_groups),
        "default_not_last_in_group_order": len(non_last_default),
        "requires_precedence_review": True,
        "requires_human_inventory_attestation": True,
        "wazuh_runtime_selection_confirmed": False,
        "deploy_approved": False,
        "deployment_gate": "BLOCKED",
        "read_only": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, required=True, help="Manually collected inventory inside .lab")
    parser.add_argument("--output", type=Path, help="Optional aggregate JSON output inside .lab")
    args = parser.parse_args()
    try:
        agents = parse_rows(args.csv)
        result = preview(agents)
        if args.output:
            if not contained(args.output) or args.output.exists():
                raise ValueError("private destination must not exist")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            # Create-new: do not overwrite any existing evidence/report.
            with args.output.open("x", encoding="utf-8") as output:
                json.dump(result, output, indent=2, sort_keys=True)
                output.write("\n")
        print("INVENTORY_CSV_STRUCTURE=VALID")
        for key, value in result.items():
            print(f"{key.upper()}={str(value).lower() if isinstance(value, bool) else value}")
        print("NO_REMOTE_CONNECTION_NO_CONFIGURATION_CHANGE=true")
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        print("INVENTORY_CSV_STRUCTURE=INVALID_OR_UNREADABLE")
        print("DEPLOYMENT_GATE=BLOCKED")
        print("NO_REMOTE_CONNECTION_NO_CONFIGURATION_CHANGE=true")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
