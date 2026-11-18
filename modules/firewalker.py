#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/firewalker.py
Purpose: Validate routed Firewalk exercises, run bounded TCP/UDP probes and retain reports.
"""

import ipaddress
import json
import shlex
import xml.etree.ElementTree as ET
from core.database import connect, event, now, set_status
from core.parser import numeric_ports, xml_records
from core.runner import identifier
from core.scanner import deploy_scan
from core.system import get_local_ips

DEFAULT_TCP = "21,22,23,25,80,443,445,3389"
DEFAULT_UDP = "53,123,161,500"


def options(
    protocol="tcp",
    tcp_ports=DEFAULT_TCP,
    udp_ports=DEFAULT_UDP,
    *,
    max_ports=7,
    retries=1,
    parallel=4,
    probe_ms=1000,
    recv_ms=1000,
    gateway=None,
):
    if protocol not in ("tcp", "udp", "both"):
        raise ValueError("Firewalk protocol must be tcp, udp or both")
    tcp = sorted(numeric_ports(tcp_ports)) if protocol in ("tcp", "both") else []
    udp = sorted(numeric_ports(udp_ports)) if protocol in ("udp", "both") else []
    max_ports, retries, parallel, probe_ms, recv_ms = map(
        int, (max_ports, retries, parallel, probe_ms, recv_ms)
    )
    if max_ports != -1 and not 1 <= max_ports <= 65535:
        raise ValueError("Firewalk max ports must be 1..65535 or -1 for all eligible ports")
    if (
        not 0 <= retries <= 10
        or not 1 <= parallel <= 128
        or not 100 <= probe_ms <= 60000
        or not 100 <= recv_ms <= 60000
    ):
        raise ValueError(
            "Firewalk tuning out of bounds: retries 0..10, parallel 1..128, timeouts 100..60000 ms"
        )
    if gateway and gateway != "all":
        gateway = str(ipaddress.ip_address(gateway))
    return dict(
        protocol=protocol,
        tcp_ports=tcp,
        udp_ports=udp,
        max_ports=max_ports,
        retries=retries,
        parallel=parallel,
        probe_ms=probe_ms,
        recv_ms=recv_ms,
        gateway=gateway,
    )


def scan_flags(target, settings, firewalk=False):
    flags = ["-Pn", "-n", "-vv"]
    if ":" in target:
        flags.append("-6")
    ports = []
    if settings["tcp_ports"]:
        flags.append("-sS")
        ports.append("T:" + ",".join(map(str, settings["tcp_ports"])))
    if settings["udp_ports"]:
        flags.append("-sU")
        ports.append("U:" + ",".join(map(str, settings["udp_ports"])))
    flags += ["-p", ",".join(ports), "--traceroute"]
    if firewalk:
        arguments = ",".join(
            (
                f"firewalk.max-probed-ports={settings['max_ports']}",
                f"firewalk.max-retries={settings['retries']}",
                f"firewalk.max-active-probes={settings['parallel']}",
                f"firewalk.probe-timeout={settings['probe_ms']}ms",
                f"firewalk.recv-timeout={settings['recv_ms']}ms",
            )
        )
        flags += ["--script", "firewalk", "--script-args", arguments]
    return shlex.join(flags)


def route_gateways(host, target):
    """A route must actually reach the target and identify an intermediate router."""
    hops = []
    for hop in host.get("trace", []):
        try:
            ttl = int(hop.get("ttl", 0))
        except ValueError:
            continue
        if ttl < 1:
            continue
        value = hop.get("ipaddr")
        if value:
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                value = None
        hops.append(dict(ttl=ttl, ip=value, rtt=hop.get("rtt")))
    hops.sort(key=lambda h: h["ttl"])
    destination = next((h for h in hops if h["ip"] == target), None)
    if destination is None:
        return (
            hops,
            [],
            "Traceroute did not establish a path reaching the target; no gateway conclusion can be made.",
        )
    if destination["ttl"] <= 1:
        return (
            hops,
            [],
            "The observed target is directly connected; Firewalk needs a target behind an intermediate gateway.",
        )
    gateways = [h for h in hops if h["ip"] and h["ip"] != target and h["ttl"] < destination["ttl"]]
    if not gateways:
        return (
            hops,
            [],
            "Intermediate hop addresses are unknown; a gateway cannot be selected from this trace.",
        )
    return hops, gateways, None


def parse_report(output):
    """Parse Nmap's Firewalk text table, retaining continuation TCP/UDP rows."""
    rows = []
    hop = None
    host = None
    unparsed = []
    for line in output.splitlines():
        text = line.strip().lstrip("|_ ").strip()
        if not text or text.startswith("HOP ") or text in ("None found", "(none found)"):
            continue
        parts = text.split()
        if parts and parts[0].isdigit() and len(parts) >= 4:
            hop = int(parts[0])
            host = parts[1]
            protocol = parts[2]
            ports = "".join(parts[3:])
        elif parts and parts[0] in ("tcp", "udp") and hop is not None:
            protocol = parts[0]
            ports = "".join(parts[1:])
        else:
            unparsed.append(text)
            continue
        if protocol not in ("tcp", "udp"):
            unparsed.append(text)
            continue
        try:
            parsed = sorted(numeric_ports(ports))
        except ValueError:
            unparsed.append(text)
            continue
        rows.append(dict(hop=hop, host=host, protocol=protocol, ports=parsed))
    return rows, unparsed


def save_report(ctx, report):
    report["finished"] = now()
    path = ctx.dirs["artifacts"] / (report["id"] + ".json")
    report["artifact"] = path.relative_to(ctx.base_path).as_posix()
    path.write_text(json.dumps(report, indent=2) + "\n")
    text = ctx.dirs["artifacts"] / (report["id"] + ".txt")
    text.write_text(
        "Firewalk training report\nStatus: "
        + report["status"]
        + "\nTarget: "
        + report["target"]
        + "\n"
        + report.get("summary", "")
        + "\n\n"
        + report.get("raw_output", "")
        + "\n"
    )
    with connect(ctx.db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO specialized_reports VALUES (?,?,?,?,?,?,?)",
            (
                report["id"],
                "firewalk",
                report["target"],
                report["status"],
                report["started"],
                report["artifact"],
                json.dumps(report),
            ),
        )
    event(
        ctx.db_path,
        f"Firewalk {report['target']}: {report['status']} — {report.get('summary', '')}",
    )
    return report


def run_firewalk(ctx, target_ip, settings=None, gateway_selector=None):
    target = str(ipaddress.ip_address(target_ip))
    if target in get_local_ips():
        raise ValueError(
            "Firewalk target is a local scanner address; self-exclusions remain enabled"
        )
    settings = dict(settings or options())
    if (
        settings.get("gateway") not in (None, "all")
        and ipaddress.ip_address(settings["gateway"]).version
        != ipaddress.ip_address(target).version
    ):
        raise ValueError("Gateway and target must use the same address family")
    report = dict(
        id="firewalk_" + identifier(),
        target=target,
        started=now(),
        status="preflight",
        settings=settings,
        gateways=[],
        trace=[],
        rows=[],
        selected_rows=[],
        artifacts=[],
        raw_output="",
        warnings=[],
    )
    try:
        trace_profile = dict(
            flags=scan_flags(target, settings), scripts=["firewalk"], capture="firewalk"
        )
        ok = deploy_scan(ctx, [target], trace_profile, 1, "61_trace")
        scan = getattr(ctx, "last_scan", None)
        if scan:
            report["artifacts"].append(scan["xml"].relative_to(ctx.base_path).as_posix())
        if (
            not ok
            or not scan
            or (
                ctx.capture
                and (scan.get("capture") or {}).get("status")
                in ("empty", "failed", "startup_failed", "unverified")
            )
        ):
            raise RuntimeError("Route preflight failed; inspect Nmap and capture logs.")
        host = next((h for h in xml_records(scan["xml"]) if h["ip"] == target), None)
        if not host:
            raise RuntimeError("Preflight produced no target host record.")
        trace, gateways, problem = route_gateways(host, target)
        report.update(trace=trace, gateways=gateways)
        if problem:
            report.update(status="inconclusive", summary=problem)
            return save_report(ctx, report)
        selected = settings.get("gateway")
        if selected is None and gateway_selector:
            selected = gateway_selector(gateways)
        if selected is None:
            selected = gateways[-1]["ip"]
        if selected != "all":
            selected = str(ipaddress.ip_address(selected))
            if selected not in {g["ip"] for g in gateways}:
                raise ValueError(
                    "Selected gateway was not observed as an intermediate hop on the target route"
                )
        report["selected_gateway"] = selected
        report["gateway_selection"] = (
            "Report focus only: Nmap Firewalk probes the observed route; the NSE script has no gateway-only parameter."
        )
        eligible = [
            s
            for s in host["services"]
            if s["reason"] in ("no-response", "no-responses")
            and (
                (s["protocol"] == "tcp" and s["state"] == "filtered")
                or (s["protocol"] == "udp" and s["state"] == "open|filtered")
            )
        ]
        report["eligible_ports"] = [
            dict(protocol=s["protocol"], port=s["port"], state=s["state"], reason=s["reason"])
            for s in eligible
        ]
        if not eligible:
            report.update(
                status="no_eligible_ports",
                summary="No unanswered filtered TCP or open|filtered UDP ports were identified; no Firewalk TTL probing was launched.",
            )
            return save_report(ctx, report)
        profile = dict(
            flags=scan_flags(target, settings, True), scripts=["firewalk"], capture="firewalk"
        )
        ok = deploy_scan(ctx, [target], profile, 1, "61")
        scan = getattr(ctx, "last_scan", None)
        if scan:
            report["artifacts"].append(scan["xml"].relative_to(ctx.base_path).as_posix())
        if (
            not ok
            or not scan
            or (
                ctx.capture
                and (scan.get("capture") or {}).get("status")
                in ("empty", "failed", "startup_failed", "unverified")
            )
        ):
            raise RuntimeError(
                "Firewalk execution or required capture failed; existing observations are retained."
            )
        host = next((h for h in xml_records(scan["xml"]) if h["ip"] == target), None)
        if not host:
            raise RuntimeError("Firewalk scan produced no target host record.")
        script = next((s for s in host.get("host_scripts", []) if s["id"] == "firewalk"), None)
        if not script:
            report.update(
                status="inconclusive",
                summary="Nmap returned no Firewalk script report; final route or eligible probe conditions may have changed.",
            )
            return save_report(ctx, report)
        report["raw_output"] = script["output"]
        rows, unparsed = parse_report(script["output"])
        report.update(rows=rows, unparsed_lines=unparsed)
        final_trace, final_gateways, problem = route_gateways(host, target)
        report["final_trace"] = final_trace
        if [(h["ttl"], h["ip"]) for h in trace] != [(h["ttl"], h["ip"]) for h in final_trace]:
            report["warnings"].append(
                "The measured route changed between preflight and Firewalk; blocking attribution may be unstable."
            )
        if problem:
            report["warnings"].append(problem)
        if selected != "all" and selected not in {g["ip"] for g in final_gateways}:
            report["warnings"].append(
                "Selected gateway was not confirmed in the final trace; treat the route comparison as inconclusive."
            )
        report["selected_rows"] = (
            rows if selected == "all" else [r for r in rows if r["host"] == selected]
        )
        if rows:
            report.update(
                status="completed",
                summary="Nmap inferred possible blocking points for the reported probe subset. These are inferences, not verified firewall rules or proof that a service is open.",
            )
        elif script["output"].strip().lower() == "none found":
            report.update(
                status="no_blocking_inferred",
                summary="Nmap did not infer a blocking point for the probed subset; this does not prove unrestricted forwarding.",
            )
        else:
            report.update(
                status="inconclusive",
                summary="Firewalk output was not a recognized blocking table; review the retained raw report.",
            )
        if report["warnings"]:
            report["status"] = "inconclusive"
    except (ValueError, OSError, RuntimeError, ET.ParseError) as exc:
        report.update(status="error", summary=str(exc))
    except BaseException:
        report.update(
            status="cancelled",
            summary="Instructor left or interrupted the Firewalk workflow; completed evidence is retained.",
        )
        save_report(ctx, report)
        raise
    finally:
        set_status(ctx.db_path, "Firewalk " + report["status"])
    return save_report(ctx, report)


"""
INPUT: One routed target, TCP/UDP scope, bounded tuning and optional gateway-report selection.
OUTPUT: Prerequisite checks, ICMP-aware captures, structured report and retained raw evidence.
"""
