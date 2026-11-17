#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/nfs_enum.py
Purpose: Query observed RPC/NFS services and optionally inspect read-only lab exports.
"""

import os
from modules.tools import artifact_output, execute, services
from core.runner import identifier


def run_nfs_enum(ctx, ip, choice=None):
    ports = {r["port"] for r in services(ctx) if r["ip"] == ip and r["protocol"] == "tcp"}
    reports = []
    # NFSv4 can exist without a portmapper; querying it must not depend on port 111.
    commands = []
    if 111 in ports:
        commands.append(["rpcinfo", "-p", ip])
    if ports.intersection({111, 2049, 20048}):
        commands.append(["showmount", "-e", ip])
    for command in commands:
        result = execute(ctx, command, ip, timeout=30)
        report = artifact_output(ctx, result, "nfs", f"TARGET: {ip}\n")
        if report:
            reports.append(report)
    return reports


def inspect_export(ctx, ip, export):
    """Explicit terminal action only. Always unmount even on error/cancellation."""
    if not export.startswith("/") or any(c.isspace() for c in export):
        raise ValueError("Provide a single absolute export path")
    destination = ctx.base_path / ".mounts" / f"nfs_mount_{identifier()}"
    destination.mkdir(parents=True)
    target = f"[{ip}]:{export}" if ":" in ip else f"{ip}:{export}"
    try:
        result = execute(
            ctx,
            [
                "mount",
                "-t",
                "nfs",
                "-o",
                "ro,nosuid,nodev,noexec,soft,timeo=50,retrans=1",
                target,
                str(destination),
            ],
            ip,
            timeout=30,
        )
        if not result or result["status"] != "completed":
            return None
        listing = []
        for index, path in enumerate(destination.iterdir()):
            if index >= 1000:
                break
            listing.append(path.name)
        report = ctx.dirs["artifacts"] / f"nfs_export_{identifier()}.txt"
        report.write_text(f"{target}\n" + "\n".join(listing) + "\n")
        return report
    finally:
        # Mount can finish immediately before cancellation is raised by the
        # runner, so cleanup must cover the mount command itself as well.
        if os.path.ismount(destination):
            cleanup = execute(ctx, ["umount", str(destination)], timeout=30)
            if not cleanup or cleanup["status"] != "completed":
                raise RuntimeError(f"Unmount failed; manually unmount {destination}")


"""
INPUT: Confirmed RPC/NFS service or an explicitly selected lab export.
OUTPUT: RPC/export inventory; optional bounded read-only directory listing.
"""
