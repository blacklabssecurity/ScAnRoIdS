#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/comparison.py
Purpose: Compare confirmed open services across saved training sessions.
"""

import json
from pathlib import Path
from core.database import connect
from core.runner import identifier


def compare_sessions(ctx, other):
    other = Path(other).expanduser().resolve()
    db = other / "artifacts" / "session.db"
    if not db.is_file():
        raise ValueError("Comparison session has no session.db")

    def read(path):
        with connect(path) as conn:
            # Also supports legacy session DBs without state/hosts columns.
            columns = {r[1] for r in conn.execute("PRAGMA table_info(scan_results)")}
            where = " WHERE state='open'" if "state" in columns else ""
            rows = conn.execute(
                "SELECT ip,port,protocol,service FROM scan_results" + where
            ).fetchall()
        return {(r["ip"], r["port"], r["protocol"]): r["service"] for r in rows}

    current, previous = read(ctx.db_path), read(db)
    result = dict(
        previous=other.name,
        current=ctx.session_name,
        added=[
            dict(ip=k[0], port=k[1], protocol=k[2], service=current[k])
            for k in sorted(current.keys() - previous.keys())
        ],
        removed=[
            dict(ip=k[0], port=k[1], protocol=k[2], service=previous[k])
            for k in sorted(previous.keys() - current.keys())
        ],
        changed=[
            dict(ip=k[0], port=k[1], protocol=k[2], before=previous[k], after=current[k])
            for k in sorted(current.keys() & previous.keys())
            if current[k] != previous[k]
        ],
    )
    path = ctx.dirs["artifacts"] / f"comparison_{identifier()}.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    return path


"""
INPUT: Two session databases.
OUTPUT: Downloadable added/removed/changed service observations; absence is not proof of closure.
"""
