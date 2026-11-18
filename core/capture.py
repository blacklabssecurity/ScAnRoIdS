#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/capture.py
Purpose: Select capture interfaces using explicit choices and local route diagnostics.
"""

import ipaddress
import json
import subprocess
from core.system import target_tokens, expand_range


def route_diagnostics(targets):
    """Inspect bounded route samples without transmitting probes to a target."""
    records = []
    for target in target_tokens(targets)[:32]:
        sample = target.split("%")[0]
        try:
            if "/" in sample:
                sample = str(ipaddress.ip_network(sample, strict=False).network_address)
            elif "-" in sample or "," in sample:
                sample = expand_range(sample)[0]
            address = ipaddress.ip_address(sample)
        except ValueError:
            records.append(dict(target=target, status="not-resolved"))
            continue
        command = [
            "ip",
            "-j",
            *(["-6"] if address.version == 6 else []),
            "route",
            "get",
            str(address),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=3)
            routes = json.loads(result.stdout) if result.returncode == 0 else []
            route = routes[0] if routes else {}
            records.append(
                dict(
                    target=target,
                    interface=route.get("dev"),
                    source=route.get("prefsrc") or route.get("src"),
                    gateway=route.get("gateway"),
                    status="known" if route.get("dev") else "unavailable",
                )
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):
            records.append(dict(target=target, status="unavailable"))
    return records


def capture_plan(ctx, targets, *, local=False):
    """Routed scans default to Linux 'any'; explicit wrong-NIC choices fail early.

    This changes capture selection only. It never changes scanner self-exclusions,
    IP configuration or OS routing. Local/multicast discovery retains its NIC.
    """
    selected = ctx.interface
    explicit = getattr(ctx, "interface_explicit", False)
    if local:
        if not selected or selected == "any":
            raise ValueError("Local/multicast discovery needs a physical --interface, not any")
        return selected, []
    routes = route_diagnostics(targets)
    interface = selected if explicit else "any"
    if not interface:
        interface = "any"
    mismatches = [r for r in routes if r.get("interface") and r["interface"] != interface]
    if interface != "any" and mismatches:
        details = ", ".join(f"{r['target']} via {r['interface']}" for r in mismatches)
        raise ValueError(
            f"Capture interface {interface} does not match the OS route: {details}. Use --interface any to capture routed scan traffic, or choose the routed interface."
        )
    return interface, routes


"""
INPUT: Validated target scope and explicit/default interface selection.
OUTPUT: Capture interface and route evidence; no scan packets or routing changes.
"""
