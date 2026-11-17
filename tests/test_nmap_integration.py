"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_nmap_integration.py
Purpose: Optional real Nmap validation against a temporary HTTP server on loopback only.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import threading
import pytest
from core.database import connect
from core.scanner import deploy_scan, preflight
from config import SCAN_LIBRARY, TACTICAL_SUGGESTIONS, UDP_SUGGESTIONS

pytestmark = pytest.mark.skipif(
    os.environ.get("SCANROIDS_NMAP_INTEGRATION") != "1", reason="Opt-in real Nmap loopback test"
)


def test_real_nmap_connect_scan_imports_open_local_service(ctx, monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Training test")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Production excludes local addresses. This test alone deliberately scans its
    # own temporary loopback service so no external training network is touched.
    monkeypatch.setattr("core.scanner.get_local_ips", lambda: [])
    profile = dict(flags=f"-Pn -n -sT -p {server.server_port}", scripts=[], capture="scope")
    try:
        assert deploy_scan(ctx, ["127.0.0.1"], profile, 1, "99")
        with connect(ctx.db_path) as conn:
            row = conn.execute("SELECT * FROM scan_results WHERE state='open'").fetchone()
            assert row["ip"] == "127.0.0.1" and row["port"] == server.server_port
            assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "completed"
        assert len(list(ctx.dirs["artifacts"].glob("*.xml"))) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_supplied_nse_profiles_exist_in_local_nmap(ctx):
    # --script-help validates installed script names and sends no probe traffic.
    scripts = sorted(
        {script for profile in SCAN_LIBRARY.values() for script in profile.get("scripts", [])}
    )
    import shlex

    for flags in [*TACTICAL_SUGGESTIONS.values(), *UDP_SUGGESTIONS.values()]:
        args = shlex.split(flags)
        scripts.append(args[args.index("--script") + 1])
    scripts.append("vuln,auth,default,discovery")
    preflight(["-sT"], ctx, scripts)


"""
INPUT: Installed Nmap and an explicit integration-test environment switch.
OUTPUT: Verification of actual Nmap artifact parsing and local NSE availability.
"""
