#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/analysis.py
Purpose: Probe offline-analysis readiness and generate usable capture teaching notes.
"""

from functools import lru_cache
import shlex
import shutil
import subprocess
import time
from core.database import event
from modules.tools import artifact_output, execute


@lru_cache(maxsize=2)
def _tshark_probe(bucket):
    """Version startup loads plugins too. Some plugin errors still exit zero."""
    binary = shutil.which("tshark")
    if not binary:
        return "missing", "Tshark is not installed on the instructor host."
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "error", f"Tshark startup check failed: {exc}"
    output = result.stderr + "\n" + result.stdout
    if any(
        marker in output.lower()
        for marker in ("couldn't load plugin", "undefined symbol", "failed to load plugin")
    ):
        return (
            "plugin_error",
            "A Tshark plugin/shared-library mismatch was detected; align or repair the Wireshark and plugin packages.",
        )
    if result.returncode:
        return "error", f"Tshark startup check exited {result.returncode}."
    return "ready", "Tshark startup check passed."


def analysis_status():
    state, detail = _tshark_probe(int(time.monotonic() // 30))
    return dict(
        tshark=state,
        detail=detail,
        capinfos=bool(shutil.which("capinfos")),
        tcpdump=bool(shutil.which("tcpdump")),
    )


def analyze_capture(ctx, path):
    path = path.expanduser().resolve()
    if not path.is_file() or path.suffix not in (".pcap", ".pcapng"):
        raise ValueError("Select an existing .pcap or .pcapng file")
    reports = []
    status = analysis_status()
    commands = [["capinfos", str(path)]]
    if status["tshark"] == "ready":
        commands.append(["tshark", "-r", str(path), "-n", "-q", "-z", "io,phs", "-z", "conv,ip"])
    else:
        event(ctx.db_path, status["detail"] + " Tshark analysis skipped.")
        print("[i] " + status["detail"])
        if status["tcpdump"]:
            commands.append(["tcpdump", "-nn", "-r", str(path), "-c", "200"])
    for command in commands:
        report = artifact_output(ctx, execute(ctx, command, timeout=120), "packet_analysis")
        if report:
            reports.append(report)
    return reports


def capture_guide(ctx):
    status = analysis_status()
    lines = [
        "# Packet capture teaching guide",
        "",
        "These commands read saved captures. They do not launch scans.",
        "",
        "Download the capture from the dashboard, then run these examples in the download directory as your normal user. "
        "Examples use the downloaded filename, not a root-owned session path.",
        "",
        "Start with capinfos. If it reports zero packets, there is no traffic to decode: "
        "check target scope, self-exclusions, interface and capture filter. Changing display filters cannot recover uncaptured traffic.",
        "",
        "## Analysis tool readiness",
        "",
        status["detail"],
        "",
    ]
    if status["tshark"] != "ready":
        lines += [
            "Tshark recipes are withheld until its startup check passes. "
            "A Falco/undefined-symbol error is a package/library compatibility issue, not an Nmap scan result or display-filter problem. "
            "Repair/align Wireshark, the optional plugin and their libraries from consistent repositories. "
            "If that optional plugin is not required, your package manager can remove its owning package after checking dependencies. "
            "No packages or plugin files are changed automatically.",
            "",
        ]
    for path in sorted(ctx.dirs["pcap"].glob("*.pcapng")):
        quoted = shlex.quote(path.name)
        lines += [
            f"## {path.name}",
            "",
            f"Original instructor capture: `{path}`",
            "",
            f"`capinfos {quoted}`",
            "",
        ]
        if status["tshark"] == "ready":
            lines += [
                f"`tshark -r {quoted} -n -q -z io,phs -z conv,ip`",
                "",
                "tshark does not repair empty captures or file permissions.",
                "",
                f'`tshark -r {quoted} -n -Y "dns || arp || icmp || icmpv6"`',
                "",
            ]
        elif status["tcpdump"]:
            lines += [
                "Basic packet preview without Tshark protocol plugins:",
                "",
                f"`tcpdump -nn -r {quoted} -c 200`",
                "",
            ]
    output = ctx.dirs["artifacts"] / "capture_guide.md"
    output.write_text("\n".join(lines) + "\n")
    return output


"""
INPUT: Existing PCAP files, local analysis tool readiness and the active session.
OUTPUT: Readiness-aware recipes/reports; no package changes or new scan traffic.
"""
