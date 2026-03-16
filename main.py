#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  main.py
Purpose: Primary controller for session management, system telemetry, 
         and interactive scan orchestration.
"""

import os
import sys
import datetime
import signal
import time

# --- Forces Python to look in the current folder for 'core' ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --- GLOBAL IMPORTS (Always at the top) ---
from core.ui import *
from core.context import ScanContext
from core.system import OPERATOR, LOCAL_IPS, INTERFACE, INTERFACE_IP, IS_VPN
from config import get_banner, SCAN_LIBRARY
from core.scanner import deploy_scan, deploy_audit_loop
from core.parser import parse_results, pre_flight_check
from modules.gowitness import run_gowitness_scan, start_gowitness_server

# Global list to track background processes (Gowitness server, Dashboard, etc.)
ACTIVE_PROCESSES = []


def check_privileges():
    """Confirms root/sudo privileges required for raw socket Nmap/Tshark operations."""
    if os.geteuid() != 0:
        log_error("Root/Sudo privileges required. Nmap/Tshark cannot function without raw socket access.")
        sys.exit(1)


def get_session_info():
    """Initializes customer context and target scope."""
    # 1. Capture Customer Name
    customer = ""
    while not customer:
        customer = log_question("Enter Customer Name (e.g., Acme Corp):")

    # Instantiate Context (Builds directory structure)
    ctx = ScanContext(customer)

    # 2. Capture Scan Targets
    targets = ""
    while not targets:
        log_note(f"Supported Formats: {YELLOW}Single IP, CIDR (10.0.0.0/24), or -iL <file>{RESET}")
        targets = log_question("Enter Scan Target Scope:")

    return ctx, targets


def get_session_selection():
    """Scans /tools/scans/ and presents a menu for session resumption."""
    from pathlib import Path
    base_path = Path("/tools/scans")

    # Filter for directories only and exclude the global logs dir
    sessions = [d for d in base_path.iterdir() if d.is_dir() and d.name != "logs"]
    sessions.sort(key=lambda x: x.stat().st_mtime, reverse=True)

    if not sessions:
        log_warn("No existing sessions found in /tools/scans/.")
        return None

    print(f"\n{BLUE}{BOLD}========================== - R - e - S - u - M - e - =========================={RESET}")
    print(f"{'#':<3} | {'Session Name':<35} | {'Started':<17} | {'Hosts':<5} | {'Web'}")
    print("-" * 75)

    for i, s in enumerate(sessions, 1):
        try:
            parts = s.name.split('_')
            raw_date, raw_time = parts[-2], parts[-1]
            formatted_time = f"{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:]} {raw_time[:2]}:{raw_time[2:]}"
        except:
            formatted_time = "Unknown          "

        host_count = 0
        host_file = s / "targets" / "hosts_all.txt"
        if host_file.exists():
            with open(host_file, 'r') as f:
                host_count = len([line for line in f if line.strip()])

        has_web = "[W]" if (s / "artifacts" / "gowitness.sqlite3").exists() else "---"
        print(f"{i:<3} | {s.name[:35]:<35} | {formatted_time:<17} | {host_count:<5} | {has_web}")

    print(f"{BLUE}{BOLD}==============================================================================={RESET}\n")

    choice = log_question("Select Session # to Resume (or 'c' to cancel):")
    if choice.lower() == 'c': return None

    try:
        idx = int(choice) - 1
        selected_path = sessions[idx]
        customer_name = selected_path.name.split('_')[0]
        return ScanContext(customer_name, resume_path=str(selected_path))
    except:
        log_error("Invalid selection.")
        return None


def cleanup_and_exit(ctx, start_time, hosts=0, services=0):
    """Kills all background processes and displays the final summary."""
    for proc in ACTIVE_PROCESSES:
        try:
            proc.terminate()
        except:
            pass

    duration = datetime.datetime.now() - start_time

    # last_act is generated NOW to mark the conclusion of the current run
    last_act = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the banner
    summary = f"""
      ________________________________________________________________________

        _________         _____        __________       .___    .____________
       /   _____/ ____   /  _  \   ____\______   \ ____ |   | __| _/   _____/
       \_____  \_/ ___\ /  /_\  \ /    \|       _//  _ \|   |/ __ |\_____  \\
       /        \  \___/    |    \   |  \    |   (  <_> )   / /_/ |/        \\
      /_______  /\___  >____|__  /___|  /____|_  /\____/|___\____ /_______  /
              \/     \/        \/     \/       \/                \/       \/

                   >> -- S - c - A - n - R - o - I - d - S -- <<

      ________________________________________________________________________
      *                                                                      *
      *                  S e S s i O n - C o M p L e T e                     *
      *                                                                      *
      ------------------------------------------------------------------------

             {GREEN}{BULLET} Customer       :{RESET} {ctx.customer:<32}
             {GREEN}{BULLET} Last Activity  :{RESET} {last_act:<32}
             {GREEN}{BULLET} Total Duration :{RESET} {str(duration).split('.')[0]:<32}
             {GREEN}{BULLET} Targets Found  :{RESET} {hosts:<32}
             {GREEN}{BULLET} Services Found :{RESET} {services:<32}
             {GREEN}{BULLET} Artifacts Path :{RESET} {str(ctx.base_path):<32}

      ________________________________________________________________________
      *                                                                      *
      *    [i] Dashboard stopped : All Ports Released! HaPpY HuNtInG [!]     *
      *                                                                      *
      ------------------------------------------------------------------------


    """
    # 1. Print to terminal
    print(summary)

    # 2. Save to text file (Strip ANSI colors for the file)
    # We strip colors and add a trailing newline for the next run
    clean_text = summary.replace(GREEN, "").replace(RESET, "").replace(BLUE, "").replace(BOLD, "").replace(CYAN, "").replace(YELLOW, "")

    try:
        with open(ctx.base_path / "session_summary.txt", "a") as f:
            f.write(clean_text)
            f.write("\n" + "="*17 + " See Below if... R e S u M e D -  s E S s I o N " + "="*17 + "\n") # Divider for the next operator's entry
    except Exception as e:
        log_error(f"Failed to update session_summary.txt: {e}")

    sys.exit(0)


def main():
    # --- 0. System Initialization
    check_privileges()
    SESSION_START_TIME = datetime.datetime.now() # Basis for final runtime stats

    # --- Variables
    targets = ""
    ctx = None
    total_hosts, total_svcs = 0, 0 # Initialize counters

    clear_screen()
    print_banner(get_banner())

    # --- 1. Environmental Situational Awareness
    log_note(f"Operator Identified: {OPERATOR} | Primary Interface: {INTERFACE}")

    if IS_VPN:
        log_warn("VPN ACTIVE: Intrusive egress techniques [N] may be unreliable or blocked by tunnel policy.")

    log_note(f"Scanning Exclusion List (Local IPs): {LOCAL_IPS}")

    # --- 2. SESSION INITIALIZATION ---
    while not ctx:
        mode = log_question("Start [N]ew Session or [R]esume existing? (N/R):").lower()

        if mode == 'r':
            ctx = get_session_selection()
            if ctx:
                # [NEW] Pre-Flight Re-hydration
                from core.parser import pre_flight_check
                total_hosts, total_svcs = pre_flight_check(ctx)

                # Check for targets to allow Phase 2 or Option 99 to run
                host_file = ctx.dirs['targets'] / "hosts_all.txt"
                if host_file.exists():
                    with open(host_file, 'r') as f:
                        targets = ",".join([line.strip() for line in f if line.strip()])
                    log_success(f"Session {ctx.session_name} is now ACTIVE.")
                else:
                    log_warn("Resumed session has no discovered hosts yet.")

        elif mode == 'n':
            customer = log_question("Enter Customer Name:")
            ctx = ScanContext(customer)
            log_note(f"Formats: {YELLOW}10.0.0.0/24, IP, or -iL <file>{RESET}")
            targets = log_question("Enter Initial Scan Target(s):")

        else:
            log_error("Selection required to proceed.")

    # --- AUTO-START SERVICES ON RESUME ---
    if (ctx.dirs['artifacts'] / "gowitness.sqlite3").exists():
        print(f"\n{YELLOW}---- Preparing goWitness Session -----{RESET}\n")
        log_task("Relaunching Gowitness Gallery...")
        gowit_proc = start_gowitness_server(ctx)
        if gowit_proc:
            ACTIVE_PROCESSES.append(gowit_proc)

    # 3. Interactive Scan Orchestration Loop
    while True:
        log_task("System Ready. Awaiting Tasking...\n")
        choice = log_question("Select Scan Menu ID (or 'q' to exit):")

        if choice.lower() == 'q':
            end_time = datetime.datetime.now()
            duration = end_time - SESSION_START_TIME
            log_note(f"Session Terminated. Total Runtime: {duration}")
            break

        if choice in SCAN_LIBRARY:
            # We use .copy() to avoid overwriting the base SCAN_LIBRARY if the script loops
            scan_meta = SCAN_LIBRARY[choice].copy()

            if choice == "99":
                custom_flags = ""
                while not custom_flags:
                    custom_flags = log_question("Enter your custom Nmap flags (e.g. -Pn -n -vv -sS -p 80,443 -T4):")
                scan_meta['flags'] = custom_flags
                log_success(f"Custom Tasking Initialized: {custom_flags}")
            else:
                log_task(f"Tasking Initialized: {scan_meta['name']} (Phase {scan_meta['phase']})")

            # --- PHASE ORCHESTRATION ---
            log_note(f"Handoff to Scanner Engine: {scan_meta['name']}...")

            # TRACK 1: Phase 1 (Discovery)
            if scan_meta['phase'] == 1:
                success = deploy_scan(ctx, targets, scan_meta)

                if success:
                    # Define artifact paths
                    file_base = f"phase1_{ctx.customer}_{ctx.date_str}_{ctx.time_str}"
                    xml_path = ctx.dirs['artifacts'] / f"{file_base}.xml"
                    gnmap_path = ctx.dirs['artifacts'] / f"{file_base}.gnmap"

                    # Trigger Data Hydration
                    parse_ok, total_hosts, total_svcs = parse_results(xml_path, gnmap_path, ctx)

                    if parse_ok:
                        log_success(f"Hydration Complete: {total_hosts} Hosts / {total_svcs} Services discovered.")

                        # Trigger Web Screenshots
                        if xml_path.exists():
                            run_gowitness_scan(ctx, xml_path)
                            gowit_proc = start_gowitness_server(ctx) 
                            if gowit_proc:
                                ACTIVE_PROCESSES.append(gowit_proc)
                            log_success("Gowitness Orchestration Complete.")
                            print(f"{YELLOW}---------------------------------{RESET}\n")
                        else:
                            log_warn("Skipping Gowitness: XML artifact missing.")
                            print(f"{YELLOW}---------------------------------{RESET}\n")

                        log_success(f"Session {ctx.session_name} Phase 1 Tasking Finished.")

                        # Wait State
                        try:
                            print(f"\n{GREEN}{BOLD}$$$$$$$$$$ PHASE 1 COMPLETE $$$$$$$$$${RESET}")
                            log_note(f"Artifacts stored in : {ctx.base_path}")
                            log_note(f"goWitness Gallery   : http://{INTERFACE_IP}:8889")
                            log_note(f"Dashboard (Future)  : http://{INTERFACE_IP}:8888")

                            print(f"\n{YELLOW}{BOLD}[*] Awaiting Exit...{RESET}")
                            log_note(f"Press [ctrl] + [C] to terminate services and generate summary.")

                            while True:
                                time.sleep(1)

                        except KeyboardInterrupt:
                            cleanup_and_exit(ctx, SESSION_START_TIME, hosts=total_hosts, services=total_svcs)
                    else:
                        log_error("Data Hydration failed. Check Nmap artifacts.")

            # TRACK 2: Phase 2 (Audit)
            elif scan_meta['phase'] == 2:
                success = deploy_audit_loop(ctx, scan_meta)

                if success:
                    log_success("All Phase 2 Audits completed.")
                    try:
                        print(f"\n{GREEN}{BOLD}$$$$$$$$$$ PHASE 2 COMPLETE $$$$$$$$$${RESET}")
                        log_note(f"Artifacts stored in : {ctx.base_path}")
                        log_note(f"goWitness Gallery   : http://{INTERFACE_IP}:8889")
                        log_note(f"Dashboard (Future)  : http://{INTERFACE_IP}:8888")
                        log_note(f"Exploit Report      : {ctx.dirs['artifacts']}/searchsploit_{ctx.customer}_{ctx.date_str}.txt")

                        print(f"\n{YELLOW}{BOLD}[*] Awaiting Exit...{RESET}")
                        log_note(f"Press [ctrl]+[c] to terminate services and generate summary.")

                        # Keep the script alive so background servers don't die
                        while True:
                            time.sleep(1)

                    except KeyboardInterrupt:
                        # Pass the cumulative stats to the final summary banner
                        cleanup_and_exit(ctx, SESSION_START_TIME, hosts=total_hosts, services=total_svcs)

                    # In Phase 2, we show the summary immediately after completion
                    cleanup_and_exit(ctx, SESSION_START_TIME, hosts=total_hosts, services=total_svcs)

            # TRACK 3: Failure Catch
            else:
                log_error("Scan execution failed or unknown phase. Check terminal output.")

            break 
        else:
            log_error(f"Invalid Menu Selection: '{choice}'. Reference the banner for valid IDs.")


if __name__ == "__main__":
    # We define these as None so the except block knows if they exist yet
    ctx_obj = None
    start_time = datetime.datetime.now()
    h_count, s_count = 0, 0

    try:
        main()
    except KeyboardInterrupt:
        # If the scan actually ran, we have a context and stats
        # We need to ensure we have access to these variables here.
        # This is a bit of a 'catch-all' to ensure the summary prints.
        print(f"\n{RESET}{BOLD}[!] Operator Abort. Finalizing Session...{RESET}")

        # We need to make sure 'ctx' was initialized in main() 
        # For simplicity, we can just call the cleanup if the session started
        if 'ctx' in locals() or 'ctx' in globals():
            # If you defined ctx in main, we need to pass it here
            pass 

        # A more robust way is to just call sys.exit() or your cleanup
        sys.exit(0)
