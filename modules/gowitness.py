#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/gowitness.py
Purpose: Capture known web endpoints with Gowitness and retain its screenshot/database artifacts.
"""

import xml.etree.ElementTree as ET
from config import WEB_PORTS
from core.runner import identifier
from modules.tools import execute, services


def run_gowitness_scan(ctx, xml_path=None):
    # A filtered XML prevents Gowitness from sweeping unrelated ports in the
    # original Nmap file. The adapter targets only confirmed HTTP(S) services.
    rows = [
        r
        for r in services(ctx)
        if r["protocol"] == "tcp"
        and (r["port"] in WEB_PORTS or "http" in (r["service"] or "").lower())
    ]
    if not rows:
        return None
    root = ET.Element("nmaprun")
    grouped = {}
    for row in rows:
        grouped.setdefault(row["ip"], []).append(row)
    for ip, host_rows in grouped.items():
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "status", state="up")
        ET.SubElement(host, "address", addr=ip, addrtype="ipv6" if ":" in ip else "ipv4")
        ports = ET.SubElement(host, "ports")
        for row in host_rows:
            port = ET.SubElement(ports, "port", protocol="tcp", portid=str(row["port"]))
            ET.SubElement(port, "state", state="open")
            # Unknown services on registered web ports get an explicit scheme hint.
            attrs = {"name": "http"}
            if "ssl" in row["service"] or row["port"] in (443, 4443, 8443, 9443):
                attrs["tunnel"] = "ssl"
            ET.SubElement(port, "service", **attrs)
    source = ctx.dirs["artifacts"] / f"gowitness_targets_{identifier()}.xml"
    ET.ElementTree(root).write(source, encoding="utf-8", xml_declaration=True)
    snapshots = ctx.dirs["artifacts"] / "screenshots"
    snapshots.mkdir(exist_ok=True)
    command = [
        "gowitness",
        "scan",
        "nmap",
        "-f",
        str(source),
        "-s",
        str(snapshots),
        "--write-db",
        "--write-db-uri",
        "sqlite://gowitness.sqlite3",
        "--threads",
        "4",
    ]
    # Gowitness 3.x syntax supplied in the design. An incompatible version
    # produces a failed job and its diagnostic output, rather than false success.
    return execute(ctx, command, ip=list(grouped), timeout=900, cwd=ctx.dirs["artifacts"])


"""
INPUT: Confirmed web services from the session database.
OUTPUT: Gowitness SQLite database, screenshot directory and execution log.
"""
