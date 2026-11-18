#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/tools.py
Purpose: Shared adapter execution, tool prerequisites and service-driven selections.
"""

from pathlib import Path
from contextlib import nullcontext as _no_capture
import shutil
from core.database import connect, event
from core.runner import identifier, packet_capture, run_command
from core.system import nmap_to_bpf
from core.capture import capture_plan


def services(ctx):
    with connect(ctx.db_path) as conn:
        return [
            dict(r)
            for r in conn.execute("""SELECT s.* FROM scan_results s JOIN hosts h
             ON h.ip=s.ip WHERE s.state='open' AND h.state='up'""")
        ]


def execute(ctx, command, ip=None, timeout=300, cwd=None, display_command=None):
    """Optional tool failure never prevents viewing already collected evidence."""
    tool = Path(command[0]).name
    if not shutil.which(command[0]):
        event(ctx.db_path, f"{tool} unavailable; skipped (run --doctor)")
        print(f"[i] {tool} unavailable; skipped")
        return None
    stem = f"{tool}_{ctx.customer}_{identifier()}"
    interface, routes = capture_plan(ctx, ip) if ip and ctx.capture else (None, [])
    with (
        packet_capture(
            ctx,
            stem,
            nmap_to_bpf(ip),
            interface=interface,
            metadata={"targets": ip, "routes": routes},
        )
        if ip
        else _no_capture()
    ):
        return run_command(
            ctx,
            command,
            tool=tool,
            phase="external tools",
            timeout=timeout,
            cwd=cwd,
            display_command=display_command,
        )


def artifact_output(ctx, result, tool, header=""):
    if not result:
        return None
    path = ctx.dirs["artifacts"] / f"{tool}_{ctx.customer}_{result['id']}.txt"
    logs = [result["log"].with_name(result["log"].name + f".{index}") for index in (3, 2, 1)]
    logs.append(result["log"])
    path.write_text(header + "".join(p.read_text(errors="replace") for p in logs if p.exists()))
    return path


"""
INPUT: Session context, explicit adapter command and observed service records.
OUTPUT: Tool execution status, captures and downloadable tool artifacts.
"""
