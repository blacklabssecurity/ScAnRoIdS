#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  modules/gowitness.py
Purpose: Monitors scan results for positive findings of web based services.
Once identified, the host and service ports are "witnessed" and artifacts 
colleccted/recorded. Launches dashboard on port 8889
"""

import subprocess
import os
from core.ui import (
    log_note, log_task, log_success, log_error, 
    YELLOW, RESET, BLUE, RED, CYAN, MAGENTA
    )


def run_gowitness_scan(ctx, xml_path):
    """
    Runs Gowitness scan ensuring screenshots are saved as a subdirectory 
    of where the SQLite database is stored (artifacts/).
    """
    # 1. Define paths relative to the 'artifacts' folder
    # This ensures the DB records paths like 'screenshots/image.png'
    db_name = "gowitness.sqlite3"
    screenshot_dir = "screenshots"

    gowitness_cmd = [
        "gowitness", "scan", "nmap",
        "-f", str(xml_path.absolute()), # Absolute path to Nmap XML
        "-s", screenshot_dir,           # Relative to artifacts/
        "--screenshot-format", "png",
        "--write-db",
        "--write-db-uri", f"sqlite://{db_name}",
        "--write-screenshots",
        "--threads", "4"
    ]

    print(f"\n{YELLOW}--- [ WEB SCREENSHOT PHASE ] ---{RESET}")
    log_task(f"Executing Gowitness: {' '.join(gowitness_cmd)}")

    try:
        # CRITICAL: We run the command FROM the artifacts directory.
        # This forces the DB to store paths relative to itself.
        subprocess.run(gowitness_cmd, check=True, cwd=ctx.dirs['artifacts'])
        log_success("Web screenshots captured and linked in artifacts/screenshots/")
    except subprocess.CalledProcessError as e:
        log_error(f"Gowitness scan failed: {e}")
        print(f"{RED}--------------------------------{RESET}\n")


def start_gowitness_server(ctx):
    """
    Starts the server from the artifacts directory to resolve image paths.
    """
    db_name = "gowitness.sqlite3"

    server_cmd = [
        "gowitness", "report", "server",
        "--host", "0.0.0.0",
        "--port", "8889",
        "--db-uri", f"sqlite://{db_name}"
    ]

    log_task(f"Starting Gowitness Server: {' '.join(server_cmd)}")

    try:
        # The server must run from artifacts/ to see the screenshots/ folder
        proc = subprocess.Popen(
            server_cmd, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL,
            cwd=ctx.dirs['artifacts']
        )
        log_success("Gowitness gallery live at http://0.0.0.0:8889")
        print(f"{YELLOW}--------------------------------{RESET}\n")
        return proc
    except Exception as e:
        log_error(f"Failed to start Gowitness server: {e}")
        print(f"{RED}--------------------------------{RESET}\n")
        return None
