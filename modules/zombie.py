#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/zombie.py
Purpose: Configure candidate hunting and freshly validate a selected IPv4 zombie.
"""

import ipaddress
import xml.etree.ElementTree as ET
from core.capture import capture_plan
from core.database import connect, event
from core.parser import xml_records
from core.runner import identifier, packet_capture, run_command
from core.scanner import build_command, preflight
from core.system import get_local_ips, target_tokens, expand_range
from core.zombies import record_check


def endpoint(value):
    ip, separator, port = value.strip().partition(":")
    ip = str(ipaddress.IPv4Address(ip))
    port = int(port or "80")
    if not 1 <= port <= 65535:
        raise ValueError("Zombie probe port must be 1..65535")
    return ip, port


def ensure_separate_zombie(ip, targets):
    if ip in get_local_ips():
        raise ValueError("The scanner itself cannot be selected as the zombie")
    address = ipaddress.IPv4Address(ip)
    for target in target_tokens(targets):
        try:
            if "/" in target:
                contains = address in ipaddress.IPv4Network(target, strict=False)
            elif "-" in target or "," in target:
                contains = ip in expand_range(target)
            else:
                contains = address == ipaddress.IPv4Address(target)
        except ValueError:
            raise ValueError("Idle scan targets must be IPv4 addresses, ranges or CIDRs") from None
        if contains:
            raise ValueError(
                "The zombie is inside the target scope. Choose a different candidate or narrow the target scope."
            )


def hunter_flags(port=80, os_detection=False):
    if not 1 <= int(port) <= 65535:
        raise ValueError("Probe port must be 1..65535")
    return (
        f"-n -vv -sS -p {int(port)} --script ipidseq --script-args ipidseq.probeport={int(port)}"
        + (" -O" if os_detection else "")
    )


def validate_candidate(ctx, ip, port=80, checks=2):
    """Require a fresh incremental classification; do not require an open port.

    The NSE script elicits sequence replies on open or closed probe ports.
    Multiple short checks can expose unstable candidates; they cannot guarantee
    successful idle scanning through a particular routed/spoof-filtering path.
    """
    ip = str(ipaddress.IPv4Address(ip))
    port = int(port)
    checks = int(checks)
    if not 1 <= port <= 65535 or not 1 <= checks <= 3:
        raise ValueError("Invalid probe port or check count (1..3)")
    outcomes = []
    for index in range(1, checks + 1):
        stem = f"zombie_check_{ctx.customer}_{identifier()}_{index}"
        output = ctx.dirs["artifacts"] / stem
        status, reason, classification, port_state = (
            "error",
            "Validation did not complete.",
            "",
            None,
        )
        try:
            flags = [
                "-Pn",
                "-n",
                "-sS",
                "-p",
                str(port),
                "--script",
                "ipidseq",
                "--script-args",
                f"ipidseq.probeport={port}",
                "--max-retries",
                "1",
                "--host-timeout",
                "30s",
            ]
            preflight(flags, ctx, ["ipidseq"])
            command = build_command(flags, [ip], output, get_local_ips())
            interface, routes = capture_plan(ctx, [ip]) if ctx.capture else (None, [])
            with packet_capture(
                ctx,
                stem,
                f"host {ip}",
                interface=interface,
                metadata={"targets": [ip], "routes": routes},
            ):
                result = run_command(
                    ctx,
                    command,
                    tool="nmap",
                    phase=f"zombie validation {index}/{checks}",
                    timeout=45,
                )
            if result["status"] != "completed":
                reason = f"Nmap validation {result['status']}; inspect the associated job log."
            else:
                host = next(
                    (h for h in xml_records(output.with_suffix(".xml")) if h["ip"] == ip), None
                )
                evidence = next(
                    (e for e in (host or {}).get("ipid", []) if e["method"] == "ipidseq"), None
                )
                if not host or host["state"] != "up":
                    status, reason = "rejected", "Candidate did not produce a live-host result."
                elif not evidence:
                    status, reason = (
                        "rejected",
                        "No ipidseq result; check probe reachability, script availability and privileges.",
                    )
                else:
                    classification = evidence["classification"]
                    port_state = evidence.get("port_state")
                    status = "validated" if evidence["incremental"] else "rejected"
                    reason = (
                        "Fresh incremental IPID replies observed; suitability for the final idle scan is not guaranteed."
                        if evidence["incremental"]
                        else "Non-incremental or unstable IPID sequence."
                    )
                captured = getattr(ctx, "capture_result", None)
                if captured and captured.get("status") in (
                    "failed",
                    "startup_failed",
                    "empty",
                    "unverified",
                ):
                    status, reason = (
                        "error",
                        "Validation capture failed or was empty; inspect capture diagnostics before using this candidate.",
                    )
        except KeyboardInterrupt:
            with connect(ctx.db_path) as conn:
                record_check(
                    conn,
                    ip=ip,
                    port=port,
                    classification=classification,
                    status="cancelled",
                    reason="Instructor interrupted validation.",
                    method="ipidseq-validation",
                    source=stem,
                )
            raise
        except (OSError, ValueError, RuntimeError, ET.ParseError) as exc:
            reason = str(exc)
        detail = dict(
            ip=ip,
            probe_port=port,
            classification=classification,
            port_state=port_state,
            status=status,
            reason=reason,
            check=index,
            total=checks,
            source=output.with_suffix(".xml").name,
        )
        with connect(ctx.db_path) as conn:
            record_check(
                conn,
                ip=ip,
                port=port,
                classification=classification,
                status=status,
                reason=reason,
                method="ipidseq-validation",
                source=stem,
                port_state=port_state,
                details=detail,
            )
        outcomes.append(detail)
        event(ctx.db_path, f"Zombie {ip}:{port}, check {index}/{checks}: {status}: {reason}")
        if status != "validated":
            break
    final = outcomes[-1]
    return dict(
        status=final["status"], reason=final["reason"], checks=outcomes, ip=ip, probe_port=port
    )


def validate_zombie(ctx, ip, port):
    """Compatibility entry point; the instructor workflow uses two fresh checks."""
    return validate_candidate(ctx, ip, port, checks=1)["status"] == "validated"


"""
INPUT: Explicit IPv4 candidate, probe port and bounded validation count.
OUTPUT: Fresh suitability result, timestamped history and independent evidence/captures.
"""
