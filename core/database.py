#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/database.py
Purpose: Transactional session storage, import history, job state and viewer events.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import sqlite3


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect(db):
    conn = sqlite3.connect(str(db), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(ctx):
    """Additive legacy migration; never truncate an existing session database."""
    db = ctx.dirs["artifacts"] / "session.db"
    if db.exists():
        with connect(db) as original:
            existing = {r[1] for r in original.execute("PRAGMA table_info(scan_results)")}
            backup = db.with_name("session.legacy-backup.sqlite3")
            if existing and "state" not in existing and not backup.exists():
                with sqlite3.connect(backup) as destination:
                    original.backup(destination)
    with connect(db) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS session_info (
            id INTEGER PRIMARY KEY, operator TEXT, customer TEXT, start_time TEXT,
            nmap_syntax TEXT, scan_phase TEXT, status TEXT, artifact_dir TEXT,
            is_active INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT PRIMARY KEY, state TEXT, os TEXT, ttl INTEGER, hops INTEGER,
            hostnames TEXT NOT NULL DEFAULT '[]', updated TEXT);
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, os_guess TEXT, port INTEGER,
            protocol TEXT, service TEXT, reason TEXT, ttl INTEGER, hops INTEGER,
            service_link TEXT, is_interesting INTEGER DEFAULT 0, is_dc INTEGER DEFAULT 0,
            has_tactical INTEGER DEFAULT 0, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS imports (
            digest TEXT PRIMARY KEY, source TEXT, imported TEXT, records TEXT);
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, tool TEXT, phase TEXT, command TEXT, status TEXT,
            started TEXT, finished TEXT, returncode INTEGER, log TEXT, heartbeat TEXT);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, message TEXT);
        """)
        columns = {r[1] for r in conn.execute("PRAGMA table_info(scan_results)")}
        for name, definition in {
            "state": "TEXT DEFAULT 'open'",
            "product": "TEXT DEFAULT ''",
            "version": "TEXT DEFAULT ''",
            "scripts": "TEXT DEFAULT '[]'",
            "source": "TEXT DEFAULT ''",
        }.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE scan_results ADD COLUMN {name} {definition}")
        conn.execute("""DELETE FROM scan_results WHERE id NOT IN
                     (SELECT MAX(id) FROM scan_results GROUP BY ip,port,protocol)""")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS service_identity ON scan_results(ip,port,protocol)"
        )
        conn.execute("""INSERT OR IGNORE INTO hosts(ip,state,os,ttl,hops,hostnames,updated)
                     SELECT ip,'up',os_guess,ttl,hops,'[]',last_seen FROM scan_results""")
        conn.execute(
            """INSERT OR IGNORE INTO session_info VALUES
                     (1,?,?,?,?,?,?,?,0)""",
            (
                ctx.operator,
                ctx.customer,
                now(),
                "Awaiting tasking",
                "N/A",
                "Ready",
                str(ctx.dirs["artifacts"]),
            ),
        )
    return db


def event(db, message):
    with connect(db) as conn:
        conn.execute("INSERT INTO events(timestamp,message) VALUES (?,?)", (now(), message))
        # Bound the live replay buffer. Full tool output remains in job log artifacts.
        conn.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM events)"
        )


def set_status(db, status, active=False, phase=None, command=None):
    with connect(db) as conn:
        conn.execute(
            "UPDATE session_info SET status=?,is_active=? WHERE id=1",
            (status, int(active)),
        )
        if phase is not None:
            conn.execute("UPDATE session_info SET scan_phase=? WHERE id=1", (str(phase),))
        if command is not None:
            conn.execute("UPDATE session_info SET nmap_syntax=? WHERE id=1", (command,))


def recover_jobs(db):
    """A restarted controller cannot own any previously running process."""
    with connect(db) as conn:
        conn.execute(
            "UPDATE jobs SET status='interrupted',finished=? WHERE status='running'",
            (now(),),
        )
    set_status(db, "Ready / session restored")


def upsert_service(conn, data, source=""):
    """Current observation per address/port/transport; history is retained in imports."""
    from config import INTERESTING_PORTS, TACTICAL_SUGGESTIONS

    port = int(data["port"])
    values = dict(
        data,
        port=port,
        os_guess=data.get("os", "Unknown"),
        is_interesting=int(port in INTERESTING_PORTS),
        has_tactical=int(port in TACTICAL_SUGGESTIONS),
        is_dc=0,
        last_seen=now(),
        source=source,
        scripts=json.dumps(data.get("scripts", [])),
    )
    columns = [
        "ip",
        "os_guess",
        "port",
        "protocol",
        "service",
        "reason",
        "ttl",
        "hops",
        "service_link",
        "is_interesting",
        "is_dc",
        "has_tactical",
        "last_seen",
        "state",
        "product",
        "version",
        "scripts",
        "source",
    ]
    values = {key: values.get(key) for key in columns}
    previous = conn.execute(
        "SELECT * FROM scan_results WHERE ip=? AND port=? AND protocol=?",
        (values["ip"], port, values["protocol"]),
    ).fetchone()
    if previous:
        for key in ("product", "version", "reason"):
            if not values[key]:
                values[key] = previous[key]
        for key in ("ttl", "hops"):
            if values[key] is None:
                values[key] = previous[key]
        if values["os_guess"] == "Unknown" or (
            "TTL estimate" in values["os_guess"]
            and "TTL estimate" not in (previous["os_guess"] or "Unknown")
            and previous["os_guess"] != "Unknown"
        ):
            values["os_guess"] = previous["os_guess"]
        if values["service"] == "unknown" and previous["service"] != "unknown":
            values["service"] = previous["service"]
            values["service_link"] = previous["service_link"]
        if values["scripts"] == "[]":
            values["scripts"] = previous["scripts"]
    conn.execute(
        f"""INSERT INTO scan_results({",".join(columns)})
                   VALUES ({",".join(":" + key for key in columns)})
                   ON CONFLICT(ip,port,protocol) DO UPDATE SET
                   {",".join(key + "=excluded." + key for key in columns if key not in ("ip", "port", "protocol"))}""",
        values,
    )


def update_dc_tags(conn):
    from config import DC_PORTS

    conn.execute("UPDATE scan_results SET is_dc=0")
    for row in conn.execute("SELECT DISTINCT ip FROM scan_results WHERE state='open'").fetchall():
        ports = {
            r[0]
            for r in conn.execute(
                "SELECT port FROM scan_results WHERE ip=? AND state='open' AND protocol='tcp'",
                (row[0],),
            )
        }
        if set(DC_PORTS).issubset(ports):
            conn.execute("UPDATE scan_results SET is_dc=1 WHERE ip=?", (row[0],))


def insert_result(db, data):
    """Compatibility API for callers inserting a single open service."""
    values = dict(
        state="open",
        service="unknown",
        reason="",
        ttl=None,
        hops=None,
        service_link="",
        product="",
        version="",
    )
    values.update(data)
    with connect(db) as conn:
        upsert_service(conn, values)
        update_dc_tags(conn)


"""
INPUT: Session context, normalized scan observations and process events.
OUTPUT: SQLite session database retaining current results and import/job history.
"""
