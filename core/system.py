#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/system.py
Purpose: Query local network state on demand and validate target/capture scope.
"""

import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess


def get_operator():
    return os.environ.get("SUDO_USER") or getpass.getuser()


def _ip_json(*args):
    try:
        return json.loads(subprocess.check_output(["ip", "-j", *args], text=True, timeout=5))
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def get_local_ips():
    return sorted(
        {
            info["local"]
            for item in _ip_json("address", "show")
            for info in item.get("addr_info", [])
            if "local" in info
        }
    )


def get_default_interface():
    routes = _ip_json("route", "show", "default")
    return next((r["dev"] for r in routes if "dev" in r), None)


def get_interface_ip(interface):
    return next(
        (
            info["local"]
            for item in _ip_json("address", "show", "dev", interface)
            for info in item.get("addr_info", [])
            if info.get("family") == "inet"
        ),
        "127.0.0.1",
    )


def check_vpn_state(interface, ips=()):
    return bool(interface and interface.startswith(("tun", "tap", "wg", "ppp")))


def target_tokens(text):
    """Treat input files as data, never command arguments. Reject nested options."""
    tokens = shlex.split(text) if isinstance(text, str) else list(text)
    if tokens[:1] == ["-iL"]:
        if len(tokens) != 2:
            raise ValueError("Use -iL followed by one target file")
        path = Path(tokens[1]).expanduser()
        if path.stat().st_size > 2_000_000:
            raise ValueError("Target file exceeds 2 MB")
        tokens = [
            word for line in path.read_text().splitlines() for word in line.split("#", 1)[0].split()
        ]
    if not tokens:
        raise ValueError("Provide at least one target")
    for value in tokens:
        if value.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:/,%\-]+", value):
            raise ValueError(f"Invalid target: {value}")
        # CIDRs and addresses get strict validation; Nmap last-octet ranges and DNS names remain supported.
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        elif ":" in value:
            ipaddress.ip_address(value.split("%")[0])
        elif re.fullmatch(r"[\d.]+", value):
            ipaddress.ip_address(value)
        elif re.fullmatch(r"[\d.]+[\d,\-]+", value):
            expand_range(value)
    return list(dict.fromkeys(tokens))


def expand_range(value):
    prefix, suffix = value.rsplit(".", 1)
    ipaddress.IPv4Address(prefix + ".0")
    result = []
    for part in suffix.split(","):
        bounds = part.split("-")
        start, end = (int(bounds[0]), int(bounds[-1]))
        if len(bounds) > 2 or not 0 <= start <= end <= 255:
            raise ValueError(f"Invalid IPv4 range: {value}")
        result.extend(f"{prefix}.{i}" for i in range(start, end + 1))
    return result


def nmap_to_bpf(targets):
    """Build a bounded BPF filter. Unsupported shorthand fails instead of capturing everything."""
    terms = []
    for value in target_tokens(targets):
        if "/" in value:
            terms.append("net " + str(ipaddress.ip_network(value, strict=False)))
        elif re.fullmatch(r"[\d.]+[\d,\-]+", value) and ("," in value or "-" in value):
            terms.extend("host " + ip for ip in expand_range(value))
        else:
            terms.append("host " + value.split("%")[0])
    if len(terms) > 1024:
        raise ValueError(
            "Capture scope exceeds 1024 terms; use CIDRs or explicitly disable capture"
        )
    return "(" + " or ".join(terms) + ")"


def dependencies():
    commands = (
        "nmap",
        "dumpcap",
        "tshark",
        "ip",
        "gowitness",
        "searchsploit",
        "enum4linux",
        "smbget",
        "rpcinfo",
        "showmount",
        "snmp-check",
        "onesixtyone",
        "gobuster",
        "capinfos",
        "tcpdump",
    )
    return {name: shutil.which(name) for name in commands}


"""
INPUT: Local iproute2 output, operator target expressions or host-list files.
OUTPUT: Validated target arguments, scoped BPF expressions and dependency availability.
"""
