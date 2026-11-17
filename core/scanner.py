#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/scanner.py
Purpose: Validate Nmap jobs, pair scans with capture, import results and run scoped audits.
"""

import ipaddress
import os
import shlex
import shutil
import subprocess
from core.database import event, set_status
from core.parser import parse_results
from core.planner import audit_plan, audit_flags
from core.runner import identifier, packet_capture, run_command
from core.system import get_local_ips, nmap_to_bpf, target_tokens


def validate_flags(flags):
    args = shlex.split(flags) if isinstance(flags, str) else list(flags)
    # Output paths and targets belong to the session controller. Prevent an
    # accidental custom flag from overwriting an arbitrary file or changing scope.
    forbidden = ("-oA", "-oX", "-oN", "-oG", "-oS", "-iL", "-iR")
    value_options = {
        "-p",
        "-g",
        "-D",
        "-S",
        "-e",
        "-b",
        "-sI",
        "--source-port",
        "--source",
        "--interface",
        "--script",
        "--script-args",
        "--script-args-file",
        "--script-timeout",
        "--scanflags",
        "--spoof-mac",
        "--dns-servers",
        "--top-ports",
        "--port-ratio",
        "--max-retries",
        "--host-timeout",
        "--scan-delay",
        "--max-scan-delay",
        "--min-rate",
        "--max-rate",
        "--min-hostgroup",
        "--max-hostgroup",
        "--min-parallelism",
        "--max-parallelism",
        "--initial-rtt-timeout",
        "--min-rtt-timeout",
        "--max-rtt-timeout",
        "--data-length",
        "--data",
        "--data-string",
        "--ttl",
        "--mtu",
        "--ip-options",
        "--max-os-tries",
        "--version-intensity",
        "--stats-every",
        "--proxies",
        "--stylesheet",
        "--servicedb",
        "--versiondb",
    }
    takes_value = False
    for arg in args:
        if takes_value:
            if arg.startswith("-") and arg != "-":
                raise ValueError("Missing value before " + arg)
            takes_value = False
            continue
        if arg.startswith(forbidden) or arg.split("=", 1)[0] in (
            "--resume",
            "--append-output",
            "--excludefile",
            "--exclude",
            "--datadir",
        ):
            raise ValueError(f"{arg} is managed by ScAnRoIdS; supply scan flags only")
        if arg == "--" or not arg.startswith("-"):
            raise ValueError("Supply targets through the target prompt, not custom flags")
        if arg in value_options:
            takes_value = True
    if takes_value:
        raise ValueError("Missing value for " + args[-1])
    return args


def preflight(flags, ctx, scripts=(), proxy=False):
    if not shutil.which("nmap"):
        raise ValueError("Nmap is missing; run --doctor for required tools")
    if ctx.capture and not shutil.which("dumpcap"):
        raise ValueError(
            "dumpcap is missing; install wireshark-common or explicitly use --no-capture"
        )
    raw = any(
        arg in ("-sS", "-sU", "-sY", "-sZ", "-sI", "-sN", "-sX", "-sF", "-O", "-f", "-PR")
        or arg.startswith(("-D", "--spoof-mac", "--scanflags"))
        for arg in flags
    )
    if raw and os.geteuid() != 0:
        raise ValueError(
            "This profile needs root/raw-socket privileges; invoke the virtualenv Python with sudo"
        )
    if proxy:
        if not shutil.which("proxychains4"):
            raise ValueError("proxychains4 is not installed")
        if "-sT" not in flags or raw or "-Pn" not in flags or "-n" not in flags:
            raise ValueError("Proxy mode requires -sT -Pn -n and forbids raw scan techniques")
    if scripts:
        try:
            result = subprocess.run(
                ["nmap", "--script-help", ",".join(scripts)],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            raise ValueError(
                "NSE availability check timed out; inspect the local Nmap installation"
            ) from None
        if result.returncode or "failed to initialize" in (result.stderr + result.stdout).lower():
            raise ValueError("NSE preflight failed: " + (result.stderr or result.stdout)[-1500:])


def build_command(flags, targets, output, local_ips=(), proxy=False):
    args = validate_flags(flags)
    targets = target_tokens(targets)
    ipv6 = "-6" in args
    if any(":" in t for t in targets) and not ipv6:
        raise ValueError("IPv6 targets require -6; scan address families separately")
    excludes = [
        ip
        for ip in local_ips
        if ipaddress.ip_address(ip.split("%")[0]).version == (6 if ipv6 else 4)
    ]
    command = (["proxychains4", "-q"] if proxy else []) + ["nmap", *args]
    if excludes:
        command += ["--exclude", ",".join(excludes)]
    # --stats-every produces useful progress during otherwise quiet scans.
    return command + ["-oA", str(output), "--reason", "--stats-every", "5s", *targets]


def capture_filter(profile, targets, flags):
    mode = profile.get("capture", "scope")
    if mode == "arp":
        return "arp"
    if mode == "dns":
        return "port 53"
    if mode == "icmp6":
        return "icmp6"
    if mode == "eigrp":
        return "ip proto 88"
    if mode == "ospf":
        return "ip proto 89"
    if mode == "zombie":
        try:
            zombie = flags[flags.index("-sI") + 1].split(":")[0]
            ipaddress.IPv4Address(zombie)
        except (ValueError, IndexError):
            raise ValueError("Idle scan requires -sI IPv4-zombie[:port]") from None
        return f"host {zombie}"
    scope = nmap_to_bpf(targets)
    if mode == "sctp":
        return f"{scope} and (sctp or icmp or icmp6)"
    ports = None
    for index, argument in enumerate(flags):
        if argument == "-p" and index + 1 < len(flags):
            ports = flags[index + 1]
        elif argument.startswith("-p") and argument != "-p":
            ports = argument[2:]
    if ports and ports != "-":
        protocol = (
            "udp"
            if "-sU" in flags and not any(v in flags for v in ("-sS", "-sT"))
            else "sctp"
            if any(v in flags for v in ("-sY", "-sZ"))
            else "tcp"
        )
        terms = []
        for spec in ports.split(","):
            if ":" in spec:
                marker, spec = spec.split(":", 1)
                protocol = {"T": "tcp", "U": "udp", "S": "sctp"}.get(marker)
                if not protocol:
                    raise ValueError("Unknown port protocol marker")
            if not spec or not all(c in "0123456789-" for c in spec):
                # Nmap supports service-name port expressions; capture the host
                # scope rather than invent a wrong numeric filter.
                return scope
            bounds = spec.split("-")
            if not 1 <= int(bounds[0]) <= int(bounds[-1]) <= 65535:
                raise ValueError("Port out of range")
            terms.append(f"{protocol} " + ("portrange " + spec if "-" in spec else "port " + spec))
        if len(terms) > 256:
            return scope
        return f"{scope} and (" + " or ".join(terms + ["icmp", "icmp6"]) + ")"
    return scope


def deploy_scan(ctx, targets, scan_meta, phase_num, choice, flags=None):
    """Every execution gets its own ID; repeated menu choices cannot overwrite artifacts."""
    args = validate_flags(flags if flags is not None else scan_meta["flags"])
    proxy = getattr(ctx, "proxy", False)
    # Pull script names from the final argv, including operator-provided scripts.
    scripts = list(scan_meta.get("scripts", []))
    for index, arg in enumerate(args):
        if arg == "--script" and index + 1 < len(args):
            scripts.append(args[index + 1])
        elif arg.startswith("--script="):
            scripts.append(arg.split("=", 1)[1])
    preflight(args, ctx, scripts, proxy)
    targets = target_tokens(targets)
    kind = "audit" if phase_num == 2 else "discovery"
    stem = f"{kind}_{ctx.customer}_{identifier()}_{choice}"
    output = ctx.dirs["artifacts"] / stem
    command = build_command(args, targets, output, get_local_ips(), proxy)
    bpf = capture_filter(scan_meta, targets, args) if ctx.capture else ""
    if proxy and ctx.capture:
        endpoint = getattr(ctx, "proxy_endpoint", None)
        if not endpoint:
            raise ValueError("Proxy capture requires --proxy-endpoint IP:port of the first proxy")
        host, separator, port = endpoint.rpartition(":")
        host = host.strip("[]")
        ipaddress.ip_address(host)
        if not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid proxy endpoint; use IP:port")
        bpf = f"host {host} and tcp port {port}"

    result = None
    try:
        with packet_capture(ctx, stem, bpf):
            phase_label = f"{phase_num} / {kind}" + (
                " · " + scan_meta["progress"] if scan_meta.get("progress") else ""
            )
            result = run_command(ctx, command, phase=phase_label, tool="nmap")
    finally:
        # Interrupted Nmap may leave usable GNMAP even when XML is incomplete.
        if output.with_suffix(".xml").exists() or output.with_suffix(".gnmap").exists():
            ok, hosts, services = parse_results(
                output.with_suffix(".xml"), output.with_suffix(".gnmap"), ctx
            )
            event(
                ctx.db_path,
                f"Imported {hosts} live hosts / {services} open services"
                if ok
                else "Scan artifacts could not be parsed",
            )
    return bool(result and result["status"] == "completed")


def deploy_audit_loop(
    ctx, scan_meta, phase_num=2, choice="50", include_industrial=False, all_ports=False
):
    jobs = audit_plan(ctx, include_industrial, all_ports)
    if not jobs:
        event(
            ctx.db_path,
            "No confirmed open services available for audit; run port discovery first",
        )
        print("[i] No confirmed open services. Run port discovery before auditing.")
        return False
    success = True
    for index, job in enumerate(jobs, 1):
        description = f"Audit {index}/{len(jobs)}: {job['ip']} / {job['protocol']}"
        print(description, flush=True)
        event(ctx.db_path, description)
        flags = audit_flags(job, scan_meta["flags"])
        current = dict(scan_meta, progress=f"{index}/{len(jobs)} · {job['ip']}/{job['protocol']}")
        ok = deploy_scan(ctx, [job["ip"]], current, phase_num, choice, flags)
        success = ok and success
    set_status(ctx.db_path, "Audit completed" if success else "Audit finished with failures")
    return success


"""
INPUT: Validated targets, declarative scan profile and optional audit plan.
OUTPUT: Nmap -oA artifacts, scoped PCAP, persisted results and truthful execution status.
"""
