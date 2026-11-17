#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/planner.py
Purpose: Build deterministic, protocol-aware audit plans from confirmed open services.
"""

import ipaddress
from config import SCADA_TCP, SCADA_UDP
from core.database import connect, init_db


def audit_plan(ctx, include_industrial=False, all_ports=False):
    """Each host/transport gets a separate job; no TCP/UDP/SCTP port conflation."""
    with connect(init_db(ctx)) as conn:
        rows = conn.execute("""SELECT s.ip,s.port,s.protocol FROM scan_results s
            JOIN hosts h ON h.ip=s.ip WHERE s.state='open' AND h.state='up'
            ORDER BY s.ip,s.protocol,s.port""").fetchall()
    grouped = {}
    for row in rows:
        industrial = SCADA_UDP if row["protocol"] == "udp" else SCADA_TCP
        if row["port"] in industrial and not include_industrial:
            continue
        grouped.setdefault((row["ip"], row["protocol"]), set()).add(row["port"])
    plan = [
        dict(ip=ip, protocol=protocol, ports=sorted(ports), all_ports=all_ports)
        for (ip, protocol), ports in grouped.items()
    ]
    return sorted(
        plan,
        key=lambda j: (
            ipaddress.ip_address(j["ip"]).version,
            int(ipaddress.ip_address(j["ip"])),
            j["protocol"],
        ),
    )


def audit_flags(job, flags):
    """Keep planner-owned transport/ports even for an audit template."""
    import shlex

    args = shlex.split(flags)
    result = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-sS", "-sT", "-sU", "-sY", "-sZ", "-6"):
            index += 1
            continue
        if arg.startswith("-p") and arg != "-p":
            index += 1
            continue
        if arg in ("-p", "--top-ports", "--port-ratio"):
            index += 2
            continue
        if arg in ("-sS", "-sT", "-sU", "-sY", "-sZ", "-6") or arg.startswith("-p"):
            index += 1
            continue
        result.append(arg)
        index += 1
    transport = {"tcp": "-sS", "udp": "-sU", "sctp": "-sY"}[job["protocol"]]
    if job["protocol"] == "tcp" and "-sT" in args:
        transport = "-sT"
    result += [transport, "-p-" if job["all_ports"] else "-p"]
    if not job["all_ports"]:
        result.append(",".join(map(str, job["ports"])))
    if ":" in job["ip"]:
        result.append("-6")
    return result


"""
INPUT: Current session database and an audit template.
OUTPUT: Host-by-host jobs and exact protocol-specific Nmap arguments.
"""
