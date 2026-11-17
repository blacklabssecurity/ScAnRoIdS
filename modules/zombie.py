#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/zombie.py
Purpose: Recheck an idle-scan candidate without adding it to discovery/audit scope.
"""

from core.parser import xml_records
from core.runner import identifier, packet_capture, run_command


def validate_zombie(ctx, ip, port):
    stem = f"zombie_check_{ctx.customer}_{identifier()}"
    output = ctx.dirs["artifacts"] / stem
    command = [
        "nmap",
        "-Pn",
        "-n",
        "-sS",
        "-p",
        str(port),
        "--script",
        "ipidseq",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "--reason",
        "-oA",
        str(output),
        ip,
    ]
    with packet_capture(ctx, stem, f"host {ip}"):
        result = run_command(ctx, command, tool="nmap", phase="zombie validation", timeout=45)
    if result["status"] != "completed":
        return False
    records = xml_records(output.with_suffix(".xml"))
    return any(
        host["ip"] == ip
        and host["zombies"]
        and any(
            s["protocol"] == "tcp" and s["port"] == int(port) and s["state"] == "open"
            for s in host["services"]
        )
        for host in records
    )


"""
INPUT: A lab zombie candidate IPv4 address and probe port.
OUTPUT: Suitability evidence as separate artifacts; candidate does not expand audit scope.
"""
