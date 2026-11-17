#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/snmp_footprints.py
Purpose: Verify a community or lab wordlist, then record an SNMP inventory.
"""

from pathlib import Path
import re
import tempfile
from modules.tools import artifact_output, execute

SHORT_LIST = "/usr/share/doc/onesixtyone/dict.txt"
LONG_LIST = "/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt"


def run_snmp_enum(ctx, ip, community="public", wordlist=None):
    """onesixtyone -c expects a FILE, including for a single community string."""
    with tempfile.TemporaryDirectory(prefix="scanroids-snmp-") as temporary:
        if wordlist:
            path = Path(wordlist).expanduser().resolve()
            if not path.is_file():
                raise ValueError(f"Community wordlist not found: {path}")
        else:
            if "\n" in community or "\r" in community:
                raise ValueError("Community must be one line")
            path = Path(temporary) / "communities.txt"
            path.write_text(community + "\n")
        result = execute(
            ctx,
            ["onesixtyone", "-c", str(path), ip],
            ip,
            timeout=120,
            display_command=f"onesixtyone -c <community-list> {ip}",
        )
        artifact_output(ctx, result, "snmp_discovery", f"TARGET: {ip}\n")
        if not result or result["status"] != "completed":
            return None
        matches = re.findall(
            r"^" + re.escape(ip) + r"\s+\[([^\]]+)\]",
            result["log"].read_text(errors="replace"),
            re.MULTILINE,
        )
        if not matches:
            return None
        found = matches[0]
        inventory = execute(
            ctx,
            ["snmp-check", ip, "-c", found],
            ip,
            timeout=120,
            display_command=f"snmp-check {ip} -c <redacted>",
        )
        return artifact_output(ctx, inventory, "snmp_inventory", f"TARGET: {ip}\n")


"""
INPUT: Confirmed UDP/161 target and one community or operator-selected wordlist.
OUTPUT: Community verification evidence and SNMP inventory report.
"""
