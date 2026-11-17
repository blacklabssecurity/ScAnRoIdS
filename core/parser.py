#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/parser.py
Purpose: Normalize Nmap XML/GNMAP, retain observations and export reproducible target lists.
"""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from core.database import connect, init_db, now, update_dc_tags, upsert_service


def number(value):
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def os_guess(name, ttl):
    if name and name != "Unknown":
        return name
    if ttl is None or ttl <= 0 or ttl > 255:
        return "Unknown"
    # TTL is an observation, not a reliable OS fingerprint. The label remains
    # explicitly uncertain and does not determine measured network distance.
    if ttl <= 64:
        return "Linux/Unix/IoT (TTL estimate)"
    if ttl <= 128:
        return "Windows (TTL estimate)"
    return "Network device/Unix (TTL estimate)"


def service_slug(value):
    return re.sub(r"[^A-Za-z0-9_-]", "_", value or "unknown")[:80] or "unknown"


def xml_records(path):
    """Parse complete XML before committing. MAC addresses never become scan targets."""
    root = ET.parse(path).getroot()
    if root.tag != "nmaprun":
        raise ValueError("Not an Nmap XML document")
    records = []
    for host in root.findall("host"):
        address = next(
            (
                a.get("addr")
                for a in host.findall("address")
                if a.get("addrtype") in ("ipv4", "ipv6")
            ),
            None,
        )
        if not address:
            continue
        address = str(ipaddress.ip_address(address))
        status = host.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        ttl = number(status.get("reason_ttl")) if status is not None else None
        if ttl == 0:
            ttl = None
        matches = host.findall("os/osmatch")
        best = max(matches, key=lambda m: number(m.get("accuracy")) or 0) if matches else None
        name = best.get("name") if best is not None else None
        distance = host.find("distance")
        # Measured Nmap distance only; observed TTL is not a measured hop count.
        hops = number(distance.get("value")) if distance is not None else None
        record = dict(
            ip=address,
            state=state,
            os=os_guess(name, ttl),
            ttl=ttl,
            hops=hops,
            hostnames=[n.get("name") for n in host.findall("hostnames/hostname") if n.get("name")],
            services=[],
            zombies=[],
            trace=[dict(h.attrib) for h in host.findall("trace/hop")],
        )
        for port in host.findall("ports/port"):
            pnum, proto = number(port.get("portid")), port.get("protocol")
            if pnum is None or not 1 <= pnum <= 65535 or proto not in ("tcp", "udp", "sctp"):
                continue
            pstate = port.find("state")
            if pstate is None:
                continue
            svc = port.find("service")
            service = svc.get("name", "unknown") if svc is not None else "unknown"
            pttl = number(pstate.get("reason_ttl")) or ttl
            record["services"].append(
                dict(
                    ip=address,
                    os=record["os"],
                    port=pnum,
                    protocol=proto,
                    state=pstate.get("state", "unknown"),
                    service=service,
                    reason=pstate.get("reason", ""),
                    ttl=pttl,
                    hops=hops,
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                    scripts=[
                        dict(id=s.get("id", ""), output=s.get("output", ""))
                        for s in port.findall("script")
                    ],
                    service_link=f"{service_slug(service)}_{pnum}_{proto}/hosts_all.txt",
                )
            )
        sequence = host.find("ipidsequence")
        candidates = [sequence.get("class", "")] if sequence is not None else []
        candidates += [
            s.get("output", "")
            for s in host.findall("hostscript/script")
            if s.get("id") == "ipidseq"
        ]
        record["zombies"] = [s for s in candidates if s.lower().strip() == "incremental"]
        records.append(record)
    return records


def gnmap_records(path):
    """GNMAP has less evidence: missing OS/TTL/scripts remain explicitly unknown."""
    hosts = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        match = re.search(r"^Host: (\S+) \((.*?)\)", line)
        if not match:
            continue
        ip = str(ipaddress.ip_address(match[1]))
        item = hosts.setdefault(
            ip,
            dict(
                ip=ip,
                state="unknown",
                os="Unknown",
                ttl=None,
                hops=None,
                hostnames=[],
                services=[],
                zombies=[],
                trace=[],
            ),
        )
        if match[2] and match[2] not in item["hostnames"]:
            item["hostnames"].append(match[2])
        status = re.search(r"Status: (\S+)", line)
        if status:
            item["state"] = status[1].lower()
        ports = re.search(r"Ports: (.*?)(?:\t|$)", line)
        if not ports:
            continue
        item["state"] = "up"
        for entry in ports[1].split(", "):
            fields = entry.split("/")
            if len(fields) < 7:
                continue
            port, state, proto, _, service, _, product = fields[:7]
            if (
                not port.isdigit()
                or not 1 <= int(port) <= 65535
                or proto not in ("tcp", "udp", "sctp")
            ):
                continue
            item["services"].append(
                dict(
                    ip=ip,
                    os="Unknown",
                    port=int(port),
                    protocol=proto,
                    state=state,
                    service=service or "unknown",
                    reason="",
                    ttl=None,
                    hops=None,
                    product=product,
                    version="",
                    scripts=[],
                    service_link=f"{service_slug(service)}_{port}_{proto}/hosts_all.txt",
                )
            )
    if not hosts:
        raise ValueError("No Nmap host records found in GNMAP")
    return list(hosts.values())


def import_scan(path, ctx):
    """Content-addressed, idempotent import. All DB writes happen in one transaction."""
    path = Path(path)
    if path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("Scan exceeds 256 MB; split the source scan first")
    records = xml_records(path) if path.suffix.lower() == ".xml" else gnmap_records(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    db = init_db(ctx)
    with connect(db) as conn:
        exists = conn.execute("SELECT 1 FROM imports WHERE digest=?", (digest,)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO imports VALUES (?,?,?,?)",
                (digest, path.name, now(), json.dumps(records)),
            )
            for host in records:
                conn.execute(
                    """INSERT INTO hosts VALUES (?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                    state=excluded.state,os=CASE WHEN excluded.os='Unknown' THEN hosts.os ELSE excluded.os END,
                    ttl=COALESCE(excluded.ttl,hosts.ttl),hops=COALESCE(excluded.hops,hosts.hops),
                    hostnames=CASE WHEN excluded.hostnames='[]' THEN hosts.hostnames ELSE excluded.hostnames END,updated=excluded.updated""",
                    (
                        host["ip"],
                        host["state"],
                        host["os"],
                        host["ttl"],
                        host["hops"],
                        json.dumps(host["hostnames"]),
                        now(),
                    ),
                )
                for service in host["services"]:
                    upsert_service(conn, service, digest)
                if host["state"] == "down":
                    conn.execute(
                        "UPDATE scan_results SET state='host-down' WHERE ip=?",
                        (host["ip"],),
                    )
            update_dc_tags(conn)
    export_targets(ctx)
    return len({h["ip"] for h in records if h["state"] == "up"}), sum(
        s["state"] == "open" for h in records if h["state"] == "up" for s in h["services"]
    )


def _write_list(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text("".join(v + "\n" for v in sorted(set(values))))
    temporary.replace(path)


def export_targets(ctx):
    """Rebuild managed exports; stale service lists are emptied, not reused for planning."""
    from config import SCADA_TCP, SCADA_UDP

    db = init_db(ctx)
    with connect(db) as conn:
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE state='up'")]
        services = [
            dict(r)
            for r in conn.execute(
                "SELECT s.* FROM scan_results s JOIN hosts h ON s.ip=h.ip WHERE s.state='open' AND h.state='up'"
            )
        ]
        imports = [json.loads(r[0]) for r in conn.execute("SELECT records FROM imports")]
    root = ctx.dirs["targets"]
    groups = {
        "hosts_all.txt": [h["ip"] for h in hosts],
        "hosts_windows.txt": [],
        "hosts_linux.txt": [],
        "hosts_OS-unknown.txt": [],
        "hosts_network.txt": [],
        "hosts_dnsHostnames.txt": [],
        "hosts_ip-dns_mappings.txt": [],
        "zombie_candidates.txt": [],
    }
    for host in hosts:
        os_name = (host["os"] or "Unknown").lower()
        key = (
            "hosts_windows.txt"
            if "windows" in os_name
            else "hosts_linux.txt"
            if "linux" in os_name
            else "hosts_network.txt"
            if any(s in os_name for s in ("cisco", "network device", "router"))
            else "hosts_OS-unknown.txt"
        )
        groups[key].append(host["ip"])
        for name in json.loads(host["hostnames"]):
            groups["hosts_dnsHostnames.txt"].append(name)
            groups["hosts_ip-dns_mappings.txt"].append(host["ip"] + " | " + name)
    for records in imports:
        for host in records:
            if host.get("zombies"):
                groups["zombie_candidates.txt"].append(
                    host["ip"] + " | incremental (candidate; validate before idle scan)"
                )
    for service in services:
        # Legacy records and imported service names never get to select a path.
        service["service_link"] = (
            f"{service_slug(service['service'])}_{int(service['port'])}_{service['protocol']}/hosts_all.txt"
        )
        groups.setdefault(service["service_link"], []).append(service["ip"])
        ports = SCADA_UDP if service["protocol"] == "udp" else SCADA_TCP
        if service["port"] in ports:
            marker = root / Path(service["service_link"]).parent / "SCADA_LOCK"
            marker.parent.mkdir(exist_ok=True)
            marker.write_text(
                "Industrial service port: explicitly review before version enumeration.\n"
            )
    # Only touch files generated by this exporter (never arbitrary operator files).
    for old in root.glob("*_*_*/hosts_all.txt"):
        groups.setdefault(old.relative_to(root).as_posix(), [])
    for relative, values in groups.items():
        destination = (root / relative).resolve()
        if not destination.is_relative_to(root.resolve()):
            raise ValueError("Target export path escaped session")
        _write_list(destination, values)


def parse_results(xml_path, gnmap_path, ctx):
    errors = []
    for path in (Path(xml_path), Path(gnmap_path)):
        try:
            hosts, services = import_scan(path, ctx)
            return True, hosts, services
        except (OSError, ET.ParseError, ValueError) as exc:
            errors.append(f"{path.name}: {exc}")
    from core.ui import log_error

    log_error("; ".join(errors))
    return False, 0, 0


def pre_flight_check(ctx):
    """Rehydrate every original scan artifact, including legacy names and fallback files."""
    paths = sorted(
        p
        for p in ctx.dirs["artifacts"].glob("*.xml")
        if not p.name.startswith(("gowitness_targets_", "zombie_check_"))
    )
    paths += [
        p
        for p in sorted(ctx.dirs["artifacts"].glob("*.gnmap"))
        if not p.with_suffix(".xml").exists()
    ]
    for path in paths:
        parse_results(path.with_suffix(".xml"), path.with_suffix(".gnmap"), ctx)
    export_targets(ctx)
    with connect(init_db(ctx)) as conn:
        return (
            conn.execute("SELECT COUNT(*) FROM hosts WHERE state='up'").fetchone()[0],
            conn.execute(
                "SELECT COUNT(*) FROM scan_results s JOIN hosts h ON s.ip=h.ip WHERE s.state='open' AND h.state='up'"
            ).fetchone()[0],
        )


def get_host_telemetry(ctx, ip, host_node=None, gnmap_path=None):
    with connect(init_db(ctx)) as conn:
        row = conn.execute("SELECT os,ttl,hops FROM hosts WHERE ip=?", (ip,)).fetchone()
    return dict(row) if row else dict(os="Unknown", ttl=None, hops=None)


"""
INPUT: Nmap XML or GNMAP and a session context.
OUTPUT: Normalized current results, immutable import observations and target-list exports.
"""
