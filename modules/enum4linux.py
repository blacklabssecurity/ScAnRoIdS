#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/enum4linux.py
Purpose: Select SMB/NetBIOS enumeration arguments from observed protocol-specific ports.
"""

from modules.tools import artifact_output, execute, services


def enum_flags(tcp, udp, greedy=False):
    if not (tcp.intersection({135, 139, 445}) or 137 in udp):
        return []
    if greedy:
        return ["-A", "-v"]
    if 137 in udp and not tcp.intersection({135, 139, 445}):
        return ["-n", "-v"]
    if {135, 139}.issubset(tcp) and 445 not in tcp and 137 not in udp:
        return ["-U", "-G", "-P", "-o", "-v"]
    if 445 in tcp and not tcp.intersection({135, 139}) and 137 not in udp:
        return ["-S", "-M", "-v"]
    return ["-A", "-v"]


def run_enum4linux(ctx, ip, choice=None, interface=None):
    rows = [r for r in services(ctx) if r["ip"] == ip]
    tcp = {r["port"] for r in rows if r["protocol"] == "tcp"}
    udp = {r["port"] for r in rows if r["protocol"] == "udp"}
    flags = enum_flags(tcp, udp, ctx.greedy)
    if not flags:
        return None
    result = execute(ctx, ["enum4linux", *flags, ip], ip, timeout=600)
    return artifact_output(ctx, result, "enum4linux", f"TARGET: {ip}\n")


"""
INPUT: A target address and confirmed SMB/NetBIOS ports.
OUTPUT: Enumeration report, execution log and target-filtered packet capture.
"""
