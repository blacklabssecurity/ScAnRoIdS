#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/smbget.py
Purpose: Download an explicitly selected guest-readable training share into its own directory.
"""

from urllib.parse import quote
from core.context import slug
from core.runner import identifier
from modules.tools import artifact_output, execute


def run_smbget(ctx, ip, share="Public"):
    if not share or "/" in share or "\\" in share or share in (".", ".."):
        raise ValueError("Provide a share name, not a path")
    directory = ctx.dirs["artifacts"] / f"smb_{slug(ip)}_{slug(share)}_{identifier()}"
    directory.mkdir()
    host = f"[{ip}]" if ":" in ip else ip
    result = execute(
        ctx,
        ["smbget", "--recursive", "--guest", f"smb://{host}/{quote(share, safe='$')}"],
        ip,
        timeout=300,
        cwd=directory,
    )
    return artifact_output(ctx, result, "smbget", f"OUTPUT DIRECTORY: {directory.name}\n")


"""
INPUT: Explicit target and share selected at the instructor terminal.
OUTPUT: Downloaded lab files, execution report and packet capture.
"""
