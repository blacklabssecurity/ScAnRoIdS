#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  core/database.py
Purpose: Persistent storage engine for session metadata and scan results. 
         Manages the SQLite schema, OS/TTL fingerprinting logic, and 
         service-level tagging for the Web Dashboard.
"""

import sqlite3
import datetime
from pathlib import Path
from config import INTERESTING_PORTS, DC_PORTS, TACTICAL_SUGGESTIONS


def init_db(ctx):
    """Creates the SQLite database in the session's artifact directory."""
    db_path = ctx.dirs['artifacts'] / "session.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Session Metadata (For the Dashboard Header)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_info (
            id INTEGER PRIMARY KEY,
            operator TEXT,
            customer TEXT,
            start_time TEXT,
            nmap_syntax TEXT,
            scan_phase TEXT,
            status TEXT,
            artifact_dir TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')

    # 2. Populate Initial Metadata (Placeholder)
    # This prevents the 500 error when you log in before the first scan.
    cursor.execute('SELECT COUNT(*) FROM session_info')
    if cursor.fetchone()[0] == 0:
        cursor.execute('''
            INSERT INTO session_info (id, operator, customer, start_time, nmap_syntax, scan_phase, status, artifact_dir)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            1, ctx.operator, ctx.customer,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "Awaiting Tasking...", "N/A", "System Ready / Idle", str(ctx.dirs['artifacts'])
        ))

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, os_guess TEXT, port INTEGER, protocol TEXT,
            service TEXT, reason TEXT, ttl INTEGER, hops INTEGER,
            service_link TEXT, is_interesting INTEGER DEFAULT 0,
            is_dc INTEGER DEFAULT 0, has_tactical INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    return db_path

def insert_result(db_path, data):
    """
    Inserts a parsed Nmap service into the DB with intelligent tagging.
    'data' should be a dictionary from the Parser.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # --- 1. Intelligent OS/TTL Fallback ---
    ttl = data.get('ttl', 0)
    os_guess = data.get('os', 'Unknown')
    if not os_guess or "Unknown" in os_guess:
        if ttl <= 64: os_guess = "Linux/IoT (TTL Guess)"
        elif 65 <= ttl <= 128: os_guess = "Windows (TTL Guess)"
        elif ttl > 128: os_guess = "Network Device (TTL Guess)"

    # --- 2. CSS Styling Logic (Interesting/DC/Tactical) ---
    is_interesting = 1 if str(data['port']) in INTERESTING_PORTS else 0
    has_tactical = 1 if str(data['port']) in TACTICAL_SUGGESTIONS else 0

    # DC Logic: This requires checking other ports on the same IP later, 
    # but we tag individual ports here for immediate highlighting.
    is_dc_port = 1 if str(data['port']) in DC_PORTS else 0

    # --- 3. Database Upsert ---
    # We use 'REPLACE' to update the service if it was found again in Phase 2
    cursor.execute('''
        INSERT OR REPLACE INTO scan_results 
        (ip, os_guess, port, protocol, service, reason, ttl, hops, service_link, is_interesting, is_dc, has_tactical)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['ip'], os_guess, data['port'], data['protocol'], 
        data['service'], data['reason'], ttl, data.get('hops', 0),
        data['service_link'], is_interesting, is_dc_port, has_tactical
    ))

    conn.commit()
    conn.close()
