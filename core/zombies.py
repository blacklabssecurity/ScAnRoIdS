#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/zombies.py
Purpose: Persist IPID candidate observations and validation history independently of targets.
"""

import ipaddress
import json
from core.database import connect, now


def record_check(
    conn,
    *,
    ip,
    port,
    classification,
    status,
    reason,
    method,
    source,
    checked=None,
    details=None,
    port_state=None,
):
    ip = str(ipaddress.IPv4Address(ip))
    if port is not None and not 1 <= int(port) <= 65535:
        raise ValueError("Invalid zombie probe port")
    conn.execute(
        """INSERT OR IGNORE INTO zombie_checks
        (ip,probe_port,classification,port_state,status,reason,method,source,checked,details)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            ip,
            port,
            classification,
            port_state,
            status,
            reason,
            method,
            source,
            checked or now(),
            json.dumps(details or {}),
        ),
    )


def record_observations(conn, records, source, checked=None):
    for host in records:
        if ":" in host["ip"]:
            continue
        for evidence in host.get("ipid", []):
            record_check(
                conn,
                ip=host["ip"],
                port=evidence.get("probe_port"),
                classification=evidence["classification"],
                status="candidate" if evidence["incremental"] else "rejected",
                reason="Incremental IPID observed; fresh validation required before use."
                if evidence["incremental"]
                else "IPID classification is not incremental.",
                method=evidence["method"],
                source=source,
                checked=checked,
                port_state=evidence.get("port_state"),
            )


def _attach_evidence(ctx, rows):
    with connect(ctx.db_path) as conn:
        imports = {
            r["digest"]: r["source"] for r in conn.execute("SELECT digest,source FROM imports")
        }
    for row in rows:
        try:
            details = json.loads(row.get("details") or "{}")
        except ValueError:
            details = {}
        candidates = [details.get("artifact"), "artifacts/" + row["source"] + ".xml"]
        imported = imports.get(row["source"])
        if imported:
            candidates += [
                "artifacts/" + imported,
                f"artifacts/imported_{row['source'][:12]}_{imported}",
            ]
        row["artifact"] = next(
            (
                value
                for value in candidates
                if value
                and (ctx.base_path / value).resolve().is_relative_to(ctx.base_path.resolve())
                and (ctx.base_path / value).is_file()
            ),
            None,
        )


def candidate_rows(ctx, only_candidates=False):
    """Latest result per IP/probe port; every underlying observation is retained."""
    with connect(ctx.db_path) as conn:
        rows = [
            dict(r)
            for r in conn.execute("""SELECT * FROM zombie_checks WHERE id IN
            (SELECT MAX(id) FROM zombie_checks GROUP BY ip,probe_port)
            ORDER BY CASE status WHEN 'validated' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END,id DESC""")
        ]
    _attach_evidence(ctx, rows)
    return [r for r in rows if not only_candidates or r["status"] in ("candidate", "validated")]


def validation_history(ctx, limit=200):
    with connect(ctx.db_path) as conn:
        rows = [
            dict(r)
            for r in conn.execute("SELECT * FROM zombie_checks ORDER BY id DESC LIMIT ?", (limit,))
        ]
    _attach_evidence(ctx, rows)
    return rows


def hunt_scope(ctx, mode, manual=None):
    """OS-unknown means absent/measured-OS evidence missing, including TTL estimates."""
    if mode == "manual":
        from core.system import target_tokens

        targets = target_tokens(manual or "")
        for target in targets:
            if ":" in target:
                raise ValueError("Zombie hunting requires IPv4 targets")
        return targets
    if mode not in ("unknown", "all"):
        raise ValueError("Zombie scope must be unknown, all or manual")
    with connect(ctx.db_path) as conn:
        rows = conn.execute("SELECT ip,os FROM hosts WHERE state='up' ORDER BY ip").fetchall()
    targets = [
        r["ip"]
        for r in rows
        if ":" not in r["ip"]
        and (
            mode == "all"
            or not r["os"]
            or r["os"] == "Unknown"
            or "ttl estimate" in r["os"].lower()
            or "ttl guess" in r["os"].lower()
        )
    ]
    if not targets:
        raise ValueError(
            f"No live IPv4 hosts in {mode} scope. Run discovery/import first or choose manual scope."
        )
    return targets


"""
INPUT: IPID observations, fresh-check outcomes and explicit scope selection.
OUTPUT: Candidate records/history and IPv4 hunt scope; never silently expands audit targets.
"""
