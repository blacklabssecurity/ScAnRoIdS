#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/analysis.py
Purpose: Generate capture teaching notes and optional offline protocol reports.
"""

import shlex
from modules.tools import artifact_output, execute


def analyze_capture(ctx, path):
    path = path.expanduser().resolve()
    if not path.is_file() or path.suffix not in (".pcap", ".pcapng"):
        raise ValueError("Select an existing .pcap or .pcapng file")
    reports = []
    for command in (
        ["capinfos", str(path)],
        ["tshark", "-r", str(path), "-n", "-q", "-z", "io,phs", "-z", "conv,ip"],
    ):
        report = artifact_output(ctx, execute(ctx, command, timeout=120), "packet_analysis")
        if report:
            reports.append(report)
    return reports


def capture_guide(ctx):
    lines = [
        "# Packet capture teaching guide",
        "",
        "These commands read existing captures. They do not launch scans.",
        "",
    ]
    for path in sorted(ctx.dirs["pcap"].glob("*.pcapng")):
        quoted = shlex.quote(str(path))
        lines += [
            f"## {path.name}",
            "",
            f"`capinfos {quoted}`",
            "",
            f"`tshark -r {quoted} -n -q -z io,phs -z conv,ip`",
            "",
            f'`tshark -r {quoted} -n -Y "dns || arp || icmp || icmpv6"`',
            "",
        ]
    output = ctx.dirs["artifacts"] / "capture_guide.md"
    output.write_text("\n".join(lines) + "\n")
    return output


"""
INPUT: Existing PCAP files and the active session directory.
OUTPUT: Offline analysis reports and reproducible capture teaching notes.
"""
