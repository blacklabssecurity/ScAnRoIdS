#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: main.py
Purpose: Instructor terminal controller for sessions, scans, tools and LAN viewing.

Quick start: .venv/bin/python main.py --doctor
             sudo .venv/bin/python main.py --customer CourseLab --interface any
"""

import argparse
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import sqlite3
import sys

from config import SCAN_LIBRARY, get_banner
from core.context import DEFAULT_ROOT, ScanContext
from core.database import init_db, recover_jobs, set_status
from core.parser import import_scan, pre_flight_check
from core.planner import audit_flags, audit_plan
from core.scanner import (
    build_command,
    capture_filter,
    deploy_audit_loop,
    deploy_scan,
    validate_flags,
)
from core.system import (
    dependencies,
    get_default_interface,
    get_interface_ip,
    get_local_ips,
    target_tokens,
)
from core.ui import attach_log, log_error, log_note, log_question, log_success, log_warn
from modules.analysis import capture_guide


_BATCH = False
_SESSION_NAVIGATION = ContextVar("session_navigation", default=False)


class BackToMenu(Exception):
    """Cancel the remaining prompted workflow and return to the session menu."""


class ExitSession(Exception):
    """Request normal session shutdown from any nested instructor prompt."""


def ask(prompt, *, navigation=True):
    if _BATCH:
        raise ValueError("This operation needs an interactive terminal: " + prompt)
    enabled = navigation and _SESSION_NAVIGATION.get()
    answer = log_question(prompt + (" [b=back, q=exit]" if enabled else ""))
    if enabled:
        command = answer.strip().lower()
        if command in ("b", "back"):
            raise BackToMenu
        if command in ("q", "quit", "exit"):
            raise ExitSession
    return answer


def yes(prompt):
    if _BATCH:
        return False
    return ask(prompt + " [y/N]:").lower() in ("y", "yes")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description="ScAnRoIdS — terminal scans, shared LAN results")
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="List required and optional executable availability",
    )
    parser.add_argument("--list-scans", action="store_true")
    parser.add_argument("--customer")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--resume", type=Path, help="Adopt an existing session directory")
    parser.add_argument(
        "--import",
        dest="imports",
        type=Path,
        action="append",
        default=[],
        help="Import Nmap XML or GNMAP; repeatable",
    )
    parser.add_argument("--scan", choices=SCAN_LIBRARY)
    parser.add_argument("--targets", help='IP, CIDR, IPv4 last-octet range, or quoted "-iL path"')
    parser.add_argument("--flags", help="Nmap flags for scan 99")
    parser.add_argument(
        "--phase", type=int, choices=[1, 2], default=1, help="Phase for custom scan 99"
    )
    parser.add_argument(
        "--interface",
        help="Capture interface (use any for routed scans); local discovery needs a physical NIC",
    )
    parser.add_argument("--no-capture", action="store_true")
    parser.add_argument("--no-dashboard", action="store_true")
    parser.add_argument(
        "--view-only",
        action="store_true",
        help="View/import results without launching scans",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Dashboard bind address")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--timeout", type=int, default=3600, help="Maximum seconds per Nmap job")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print command/PCAP plans without launching any tools",
    )
    parser.add_argument(
        "--exit-after",
        action="store_true",
        help="Exit after the requested operation instead of holding the viewer",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; skip optional actions unless explicitly enabled",
    )
    parser.add_argument(
        "--audit", action="store_true", help="Continue into an audit after discovery"
    )
    parser.add_argument(
        "--include-industrial", action="store_true", help="Include observed ICS ports in phase 2"
    )
    parser.add_argument(
        "--expand-all-ports", action="store_true", help="Explicit scope expansion for scan 52"
    )
    parser.add_argument(
        "--greedy",
        action="store_true",
        help="Run applicable enumeration adapters without individual prompts",
    )
    parser.add_argument(
        "--tools",
        action="store_true",
        help="Offer service-driven tools after the requested scan/import",
    )
    parser.add_argument(
        "--proxy-endpoint", help="IP:port of the first proxy, for accurate packet capture"
    )
    parser.add_argument(
        "--proxychains",
        action="store_true",
        help="Use proxychains4 for explicit -sT -Pn -n profiles",
    )
    parser.add_argument("--profile", type=Path, help="Load a saved course profile JSON")
    parser.add_argument(
        "--compare", type=Path, help="Write a service comparison with another session"
    )
    parser.add_argument(
        "--zombie-scope",
        choices=["unknown", "all", "manual"],
        help="Candidate-hunt scope for scan 60",
    )
    parser.add_argument("--zombie", help="Selected candidate IPv4[:probe-port] for scan 05/71")
    parser.add_argument("--zombie-probe-port", type=int, default=80)
    parser.add_argument(
        "--zombie-os", action="store_true", help="Add optional OS detection to candidate hunting"
    )
    parser.add_argument(
        "--zombie-checks",
        type=int,
        choices=[1, 2, 3],
        default=2,
        help="Fresh suitability checks immediately before idle scanning",
    )
    parser.add_argument("--idle-ports", help="Target port list for idle scanning")
    parser.add_argument("--firewalk-protocol", choices=["tcp", "udp", "both"])
    parser.add_argument("--firewalk-tcp-ports")
    parser.add_argument("--firewalk-udp-ports")
    parser.add_argument(
        "--firewalk-gateway", help="Observed gateway IP to focus the report, or all"
    )
    parser.add_argument("--firewalk-max-ports", type=int)
    parser.add_argument("--firewalk-retries", type=int)
    parser.add_argument("--firewalk-parallel", type=int)
    parser.add_argument("--firewalk-probe-ms", type=int)
    parser.add_argument("--firewalk-recv-ms", type=int)
    args = parser.parse_args(argv)
    if args.profile:
        profile = json.loads(args.profile.read_text())
        allowed = {
            "scan",
            "targets",
            "flags",
            "phase",
            "interface",
            "no_capture",
            "timeout",
            "tools",
            "audit",
            "zombie_scope",
            "zombie",
            "zombie_probe_port",
            "zombie_os",
            "zombie_checks",
            "idle_ports",
            "firewalk_protocol",
            "firewalk_tcp_ports",
            "firewalk_udp_ports",
            "firewalk_gateway",
            "firewalk_max_ports",
            "firewalk_retries",
            "firewalk_parallel",
            "firewalk_probe_ms",
            "firewalk_recv_ms",
        }
        if not isinstance(profile, dict) or set(profile) - allowed:
            parser.error("Course profile has unsupported fields")
        supplied = {a.split("=", 1)[0] for a in (sys.argv[1:] if argv is None else argv)}
        for key, value in profile.items():
            switch = "--" + key.replace("_", "-")
            if switch not in supplied:
                setattr(args, key, value)
    if args.scan is not None and args.scan not in SCAN_LIBRARY:
        parser.error("Invalid scan ID in profile")
    if args.phase not in (1, 2) or isinstance(args.phase, bool):
        parser.error("Phase must be 1 or 2")
    if not isinstance(args.timeout, int) or args.timeout <= 0:
        parser.error("Timeout must be positive")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be 1..65535")
    return args


@contextmanager
def session_lock(ctx):
    """One instructor controller per session; other sessions may still be viewed."""
    with (ctx.base_path / ".controller.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another instructor controller already owns this session") from None
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def import_file(ctx, path):
    path = path.expanduser().resolve()
    if path.suffix.lower() not in (".xml", ".gnmap"):
        raise ValueError("Imports must be Nmap .xml or .gnmap files")
    if not path.is_file():
        raise ValueError("Import source does not exist")
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Scan import exceeds 256 MB")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    destination = ctx.dirs["artifacts"] / f"imported_{digest}_{path.name}"
    # Parse first: malformed input does not poison the permanent scan directory.
    hosts, services = import_scan(path, ctx)
    if path != destination:
        shutil.copyfile(path, destination)
    log_success(f"Imported {hosts} live hosts and {services} open services from {path.name}")


def select_session(root):
    if not root.exists():
        raise ValueError(f"No sessions under {root}")
    sessions = sorted(
        (p for p in root.iterdir() if p.is_dir() and (p / "artifacts").is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not sessions:
        raise ValueError("No saved sessions found")
    for index, path in enumerate(sessions, 1):
        print(f"{index:>3}. {path.name}")
    choice = int(ask("Session number:"))
    if not 1 <= choice <= len(sessions):
        raise ValueError("Session number out of range")
    return sessions[choice - 1]


def select_zombie(ctx, args):
    from core.zombies import candidate_rows
    from modules.zombie import endpoint

    if args.zombie:
        return endpoint(args.zombie)
    rows = candidate_rows(ctx, only_candidates=True)
    if rows:
        print("Saved candidates — each selection is freshly revalidated before use:")
        for index, row in enumerate(rows, 1):
            print(
                f"{index}. {row['ip']}:{row['probe_port'] or '?'} | {row['classification']} | {row['status']} | {row['checked']} | {row['method']}"
            )
        value = ask("Candidate number, IPv4[:port], or m for manual entry:")
        if value.isdigit():
            index = int(value) - 1
            if not 0 <= index < len(rows):
                raise ValueError("Candidate number out of range")
            row = rows[index]
            port = row["probe_port"] or int(
                ask("Probe port for this candidate (default 80):") or "80"
            )
            return endpoint(f"{row['ip']}:{port}")
        if value.lower() != "m":
            return endpoint(value)
    return endpoint(ask("Zombie IPv4[:port] (default probe port 80):"))


def select_hunt_scope(ctx, args):
    from core.zombies import hunt_scope

    mode = args.zombie_scope
    if mode is None:
        if _BATCH:
            mode = "manual" if args.targets else "unknown"
        else:
            print(
                "Zombie hunt scope: 1=OS-unknown discovered hosts, 2=all discovered IPv4 hosts, 3=manual"
            )
            value = ask("Scope [1/2/3] (default 1):") or "1"
            mode = {"1": "unknown", "2": "all", "3": "manual"}.get(value, value)
    manual = args.targets
    if mode == "manual" and not manual:
        manual = ask("Candidate IPv4 scope (IP, CIDR, range or -iL file):")
    targets = hunt_scope(ctx, mode, manual)
    log_note(
        f"Zombie hunt scope: {mode}; {len(targets)} target expression(s). OS-unknown is a selection hint, not proof of suitability."
    )
    return targets


def configure_firewalk(args):
    from modules.firewalker import options, DEFAULT_TCP, DEFAULT_UDP

    protocol = args.firewalk_protocol or (
        "tcp"
        if _BATCH
        else (ask("Firewalk protocol [tcp/udp/both] (default tcp):") or "tcp").lower()
    )
    tcp = args.firewalk_tcp_ports or DEFAULT_TCP
    udp = args.firewalk_udp_ports or DEFAULT_UDP
    if not _BATCH:
        if protocol in ("tcp", "both") and not args.firewalk_tcp_ports:
            tcp = ask(f"TCP probe ports (default {tcp}):") or tcp
        if protocol in ("udp", "both") and not args.firewalk_udp_ports:
            udp = ask(f"UDP probe ports (default {udp}):") or udp
    values = dict(
        max_ports=args.firewalk_max_ports if args.firewalk_max_ports is not None else 7,
        retries=args.firewalk_retries if args.firewalk_retries is not None else 1,
        parallel=args.firewalk_parallel if args.firewalk_parallel is not None else 4,
        probe_ms=args.firewalk_probe_ms if args.firewalk_probe_ms is not None else 1000,
        recv_ms=args.firewalk_recv_ms if args.firewalk_recv_ms is not None else 1000,
    )
    if not _BATCH and yes("Adjust Firewalk retry, concurrency and timeout limits?"):
        for key, label in [
            ("max_ports", "Max eligible ports per protocol (-1 means all)"),
            ("retries", "Retries per probe"),
            ("parallel", "Parallel probes"),
            ("probe_ms", "Probe timeout (ms)"),
            ("recv_ms", "Receive loop timeout (ms)"),
        ]:
            values[key] = int(ask(f"{label} (default {values[key]}):") or str(values[key]))
    return options(protocol, tcp, udp, gateway=args.firewalk_gateway, **values)


def select_gateway(gateways):
    print("Observed intermediate gateways:")
    for index, hop in enumerate(gateways, 1):
        print(f"{index}. hop {hop['ttl']} — {hop['ip']}")
    log_note(
        "Gateway selection focuses the report. Nmap Firewalk probes the routed path; it has no gateway-only option."
    )
    value = ask("Gateway number, observed IP, or a for all (default last gateway):")
    if not value:
        return gateways[-1]["ip"]
    if value.lower() in ("a", "all"):
        return "all"
    if value.isdigit():
        index = int(value) - 1
        if not 0 <= index < len(gateways):
            raise ValueError("Gateway number out of range")
        return gateways[index]["ip"]
    return str(ipaddress.ip_address(value))


def prepare_profile(ctx, choice, args, targets):
    profile = SCAN_LIBRARY[choice].copy()
    flags = profile["flags"]
    if choice == "99":
        flags = args.flags or ask("Custom Nmap flags (targets/output are managed separately):")
        profile["phases"] = [args.phase]
    elif choice in ("05", "71"):
        from modules.zombie import ensure_separate_zombie, validate_candidate

        host, port = select_zombie(ctx, args)
        ensure_separate_zombie(host, targets)
        ports = args.idle_ports or ask("Target ports (e.g. 80,443 or 1-1024):")
        from core.parser import numeric_ports

        numeric_ports(ports)
        flags += f" -sI {host}:{port} -p {ports}"
        if not args.dry_run:
            result = validate_candidate(ctx, host, port, args.zombie_checks)
            log_note(f"Zombie {host}:{port}: {result['status']} — {result['reason']}")
            if result["status"] != "validated":
                raise ValueError(result["reason"])
        else:
            log_note("Dry run: fresh candidate validation will occur before real idle scanning.")
    elif choice == "60":
        from modules.zombie import hunter_flags

        port = args.zombie_probe_port
        if not _BATCH and port == 80:
            port = int(ask("Candidate TCP probe port (default 80):") or "80")
        detect_os = args.zombie_os or (
            not _BATCH and yes("Also perform OS detection on candidate hosts?")
        )
        flags = hunter_flags(port, detect_os)
    elif choice == "04":
        dns = ask("DNS server IP (blank uses system DNS):")
        if dns:
            ipaddress.ip_address(dns)
            flags += " --dns-servers " + dns
        else:
            flags += " --system-dns"
    elif choice == "14":
        values = ask("TCP flags (comma-separated SYN,ACK,FIN,RST,PSH,URG):").upper().split(",")
        if not values or not set(values) <= {"SYN", "ACK", "FIN", "RST", "PSH", "URG"}:
            raise ValueError("Unknown TCP flag")
        flags += " --scanflags " + ",".join(values)
    elif choice == "72":
        port = int(ask("Source port:"))
        if not 1 <= port <= 65535:
            raise ValueError("Source port out of range")
        flags += " -g " + str(port)
    if ctx.proxy and choice in ("41", "42", "43", "45"):
        flags += " -Pn"
    if profile.get("local"):
        if not ctx.interface or ctx.interface == "any":
            raise ValueError("This local discovery requires a physical --interface")
        flags += " -e " + ctx.interface
        if choice == "20":
            targets = ["ff02::1"]
    if choice == "46":
        if not yes("Proceed with ICS discovery against the training scope?"):
            return None, None
    profile["flags"] = shlex.join(validate_flags(flags))
    return profile, targets


def print_plan(ctx, choice, profile, targets):
    if profile["phases"] == [2]:
        jobs = audit_plan(ctx)
        print(json.dumps(jobs, indent=2))
        for job in jobs:
            flags = audit_flags(job, profile["flags"])
            print(
                shlex.join(build_command(flags, [job["ip"]], ctx.dirs["artifacts"] / "audit_PLAN"))
            )
    else:
        flags = validate_flags(profile["flags"])
        print(shlex.join(build_command(flags, targets, ctx.dirs["artifacts"] / "discovery_PLAN")))
        if ctx.capture:
            print("PCAP filter:", capture_filter(profile, targets, flags))


def external_tools(ctx):
    from modules.tools import services
    from modules.gowitness import run_gowitness_scan
    from modules.searchsploit import run_searchsploit
    from modules.enum4linux import run_enum4linux
    from modules.nfs_enum import run_nfs_enum, inspect_export
    from modules.snmp_footprints import run_snmp_enum, SHORT_LIST, LONG_LIST
    from modules.smbget import run_smbget
    from config import WEB_PORTS

    rows = services(ctx)

    def offer(prompt):
        return ctx.greedy or yes(prompt)

    def invoke(function, *values):
        try:
            return function(ctx, *values)
        except (OSError, ValueError, RuntimeError) as exc:
            log_error(str(exc))

    if any(
        r["protocol"] == "tcp" and (r["port"] in WEB_PORTS or "http" in r["service"]) for r in rows
    ):
        if offer("Capture discovered web surfaces with Gowitness?"):
            invoke(run_gowitness_scan)
    if any(r["product"] for r in rows):
        if offer("Look up service-version references with SearchSploit?"):
            invoke(run_searchsploit)
    for ip in sorted({r["ip"] for r in rows}):
        tcp = {r["port"] for r in rows if r["ip"] == ip and r["protocol"] == "tcp"}
        udp = {r["port"] for r in rows if r["ip"] == ip and r["protocol"] == "udp"}
        if tcp.intersection({135, 139, 445}) or 137 in udp:
            if offer(f"Enumerate SMB/NetBIOS on {ip}?"):
                invoke(run_enum4linux, ip)
            if 445 in tcp and yes(f"Download a guest-readable training share from {ip}?"):
                share = ask("Share name (default Public):") or "Public"
                invoke(run_smbget, ip, share)
        if tcp.intersection({111, 2049, 20048}):
            if offer(f"Enumerate RPC/NFS on {ip}?"):
                invoke(run_nfs_enum, ip)
            if 2049 in tcp and yes(f"Inspect a training export read-only on {ip}?"):
                invoke(inspect_export, ip, ask("Absolute export path:"))
        if 161 in udp:
            if not offer(f"Enumerate SNMP on {ip}?"):
                continue
            if ctx.greedy:
                invoke(run_snmp_enum, ip, "public", LONG_LIST)
            else:
                community = ask("Community (default public):") or "public"
                report = invoke(run_snmp_enum, ip, community)
                if report is None and yes("Try a lab community wordlist?"):
                    print(f"1. {SHORT_LIST}\n2. {LONG_LIST}\n3. Custom path")
                    choice = ask("Wordlist option:")
                    path = (
                        SHORT_LIST
                        if choice == "1"
                        else LONG_LIST
                        if choice == "2"
                        else ask("Wordlist path:")
                    )
                    invoke(run_snmp_enum, ip, "public", path)
    if yes("Run optional bounded HTTP directory discovery?"):
        from modules.web_enum import run_web_enum

        invoke(
            run_web_enum,
            ask("Lab HTTP(S) URL:"),
            ask("Wordlist path:"),
        )


def execute_selection(ctx, choice, args):
    profile = SCAN_LIBRARY[choice]
    if choice == "61":
        from modules.firewalker import run_firewalk, scan_flags

        targets = target_tokens(args.targets or ask("Single routed Firewalk target IP:"))
        if len(targets) != 1:
            raise ValueError("Firewalk requires one literal target IP")
        target = str(ipaddress.ip_address(targets[0]))
        settings = configure_firewalk(args)
        if args.dry_run:
            for label, final in (("Preflight", False), ("Firewalk after prerequisites", True)):
                command = build_command(
                    scan_flags(target, settings, final),
                    [target],
                    ctx.dirs["artifacts"] / ("firewalk_PLAN" if final else "trace_PLAN"),
                    get_local_ips(),
                )
                print(label + ":", shlex.join(command))
            if ctx.capture:
                print("PCAP filter:", capture_filter(profile, [target], []))
            print(
                "Gateway report focus:",
                settings["gateway"] or "selected after measured route preflight",
            )
            return True
        report = run_firewalk(
            ctx, target, settings, gateway_selector=None if _BATCH else select_gateway
        )
        log_note(f"Firewalk {report['status']}: {report.get('summary', '')}")
        log_note("Report: " + report["artifact"])
        capture_guide(ctx)
        return report["status"] in ("completed", "no_blocking_inferred", "no_eligible_ports")
    phase = args.phase if choice == "99" else profile["phases"][0]
    if choice == "60":
        targets = select_hunt_scope(ctx, args)
    elif phase == 1:
        text = args.targets or ask("Targets (IP, CIDR, last-octet range or -iL file):")
        targets = target_tokens(text)
    else:
        targets = []
    profile, targets = prepare_profile(ctx, choice, args, targets)
    if profile is None:
        return
    if args.dry_run:
        print_plan(ctx, choice, profile, targets)
        return True
    if phase == 2:
        industrial = args.include_industrial or yes(
            "Include discovered industrial/ICS ports in this audit?"
        )
        all_ports = choice == "52" and (
            args.expand_all_ports or yes("Expand this audit to ALL ports on discovered hosts?")
        )
        if choice == "52" and not all_ports:
            return
        success = deploy_audit_loop(
            ctx,
            profile,
            choice=choice,
            include_industrial=industrial,
            all_ports=all_ports,
        )
    else:
        success = deploy_scan(ctx, targets, profile, 1, choice)
        if choice == "60":
            from core.zombies import candidate_rows

            rows = candidate_rows(ctx, only_candidates=True)
            log_note(
                f"{len(rows)} saved candidate record(s). Select Scan 05 to pick and freshly validate one."
            )
            set_status(
                ctx.db_path,
                "Zombie hunt completed" if success else "Zombie hunt finished with failures",
            )
            capture_guide(ctx)
            return success
        if success and (
            args.audit or yes("Continue into a host-by-host audit of confirmed open ports?")
        ):
            if not audit_plan(ctx):
                log_note(
                    "Host discovery found no confirmed open ports. First run a port-discovery profile (40–46)."
                )
            else:
                audit = SCAN_LIBRARY["50"].copy()
                if len({j["ip"] for j in audit_plan(ctx)}) > 15 and yes(
                    "Use high-performance timing for this lab audit?"
                ):
                    audit["flags"] += " --min-hostgroup 64 --min-parallelism 100 --min-rate 1000"
                success = deploy_audit_loop(ctx, audit, include_industrial=args.include_industrial)
    set_status(ctx.db_path, "Finished" if success else "Finished with failures")
    if args.tools or (success and yes("Review applicable external tools?")):
        external_tools(ctx)
    capture_guide(ctx)
    return success


def run(args):
    if args.doctor:
        for name, path in dependencies().items():
            print(f"{name:16} {path or 'NOT INSTALLED'}")
        print(
            "\nRequired for scanning: nmap; for capture: dumpcap + iproute2.\nPython requirements: requirements.txt. Optional tools: docs/TOOLS.md."
        )
        return 0
    if args.list_scans:
        print(get_banner())
        return 0
    global _BATCH
    _BATCH = args.non_interactive
    if args.view_only and args.scan:
        raise ValueError("--view-only cannot be combined with --scan")
    if args.resume:
        ctx = ScanContext(resume_path=args.resume)
    elif args.customer:
        ctx = ScanContext(args.customer, root=args.data_dir)
    elif not args.imports and yes("Resume an existing training session?"):
        ctx = ScanContext(resume_path=select_session(args.data_dir))
    else:
        ctx = ScanContext(ask("Customer / course name:"), root=args.data_dir)
    ctx.capture = not args.no_capture
    ctx.interface = args.interface or (None if args.view_only else get_default_interface())
    ctx.interface_explicit = args.interface is not None
    ctx.greedy = args.greedy
    ctx.timeout = args.timeout
    ctx.proxy = args.proxychains
    ctx.proxy_endpoint = args.proxy_endpoint
    with session_lock(ctx):
        ctx.db_path = init_db(ctx)
        recover_jobs(ctx.db_path)
        attach_log(ctx.db_path)
        server = None
        navigation_token = None
        try:
            log_note(f"Session directory: {ctx.base_path}")
            if args.resume:
                pre_flight_check(ctx)
            # Refresh the managed guide on resume; do not leave stale recipes
            # from a previous installation/tool-health state in the viewer.
            capture_guide(ctx)
            for path in args.imports:
                import_file(ctx, path)
            if args.compare:
                from core.comparison import compare_sessions

                log_success(f"Comparison: {compare_sessions(ctx, args.compare)}")
            if not args.no_dashboard and not args.dry_run:
                from core.dashboard import start_dashboard

                password = (
                    os.environ.get("SCANROIDS_PASSWORD") or f"{ctx.customer}_{datetime.now().year}"
                )
                server = start_dashboard(ctx, args.host, args.port, password)
                address = (
                    args.host
                    if args.host not in ("0.0.0.0", "::")
                    else get_interface_ip(
                        (get_default_interface() or "lo")
                        if ctx.interface == "any"
                        else ctx.interface
                    )
                    if ctx.interface
                    else "127.0.0.1"
                )
                log_success(f"Viewer: http://{address}:{args.port} | Username: operator")
                # Keep the credential out of the shared dashboard/event log.
                print(f"[i] Viewer password: {password}", flush=True)
            navigation_token = _SESSION_NAVIGATION.set(True)
            if args.scan:
                try:
                    succeeded = execute_selection(ctx, args.scan, args)
                except BackToMenu:
                    log_note("Returned to main menu. Completed work and artifacts are preserved.")
                    succeeded = None
                else:
                    if args.exit_after or args.dry_run:
                        return 0 if succeeded else 1
                    print(
                        "[i] Requested scan finished. Dashboard remains available; Ctrl+C to exit."
                    )
            if args.exit_after:
                return 0
            while True:
                if not args.view_only:
                    print(get_banner())
                commands = "i=import, p=audit plan, c=compare, a=PCAP analysis"
                if not args.view_only:
                    commands += ", t=external tools"
                print("Session commands: " + commands + ", b=back, q=exit")
                choice = ask(
                    "View session / select scan ID:"
                    if not args.view_only
                    else "View-only session command:",
                    navigation=False,
                ).lower()
                try:
                    if choice in ("q", "quit", "exit"):
                        break
                    if choice in ("b", "back"):
                        log_note("Already at the main session menu.")
                        continue
                    if choice == "i":
                        import_file(ctx, Path(ask("Nmap XML/GNMAP path:")))
                    elif choice == "p":
                        print(json.dumps(audit_plan(ctx), indent=2))
                    elif choice == "c":
                        from core.comparison import compare_sessions

                        log_success(str(compare_sessions(ctx, ask("Other session directory:"))))
                    elif choice == "a":
                        from modules.analysis import analyze_capture

                        analyze_capture(ctx, Path(ask("PCAP path:")))
                    elif choice == "t" and not args.view_only:
                        external_tools(ctx)
                    elif choice in SCAN_LIBRARY and not args.view_only:
                        execute_selection(ctx, choice, args)
                    else:
                        log_warn("Unknown command for this session mode")
                except BackToMenu:
                    log_note("Returned to main menu. Completed work and artifacts are preserved.")
                except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
                    log_error(str(exc))
        except ExitSession:
            log_note("Instructor exited the session; closing the dashboard.")
        except KeyboardInterrupt:
            log_note("Instructor stopped the session; finalizing captures and dashboard.")
        finally:
            try:
                set_status(ctx.db_path, "Controller stopped")
                capture_guide(ctx)
            finally:
                try:
                    if server:
                        server.close()
                finally:
                    attach_log(None)
                    if navigation_token is not None:
                        _SESSION_NAVIGATION.reset(navigation_token)
    return 0


def main(argv=None):
    try:
        return run(arguments(argv))
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except EOFError:
        return 0


if __name__ == "__main__":

    def stop_requested(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop_requested)
    raise SystemExit(main())


"""
INPUT: Instructor terminal commands, CLI/course profiles and optional previous scan files.
OUTPUT: Managed training session, scan/tool artifacts and a viewing-only LAN dashboard.
"""
