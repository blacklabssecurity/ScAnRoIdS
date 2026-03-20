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
import subprocess

# --- Forces Python to look in the current folder for 'core' ---
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --- GLOBAL IMPORTS (Always at the top) ---
from config import get_banner, SCAN_LIBRARY, WEB_PORTS
from core.ui import *
from core.system import OPERATOR, LOCAL_IPS, INTERFACE, INTERFACE_IP, IS_VPN
from core.parser import parse_results, pre_flight_check
from core.context import ScanContext
from core.scanner import deploy_scan, deploy_audit_loop
from core.dashboard import start_dashboard
from modules.gowitness import run_gowitness_scan, start_gowitness_server
from modules.firewalker import run_firewalk

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

    print(f"\n{BLUE}{BOLD}==========================| Resumable sEsSiOnS appear below |==========================={RESET}")
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
    # Print to terminal
    print(summary)

    # Save to text file (Strip ANSI colors for the file)
    # We strip colors and add a trailing newline for the next run
    # Using a raw string r"" prevents 'invalid escape sequence' warnings
    clean_text = summary
    for color in [GREEN, RESET, BLUE, BOLD, CYAN, YELLOW, RED]:
        clean_text = clean_text.replace(color, "")

    try:
        with open(ctx.base_path / "session_summary.txt", "a") as f:
            f.write(clean_text)
            f.write("\n" + "="*17 + " See Below if... R e S u M e D - s E S s I o N " + "="*17 + "\n")
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


    # --- SET OPERATIONAL POSTURE ---
    print(f"\n{YELLOW}{BOLD}--- [ OPERATIONAL POSTURE ] ---{RESET}")
    greedy_choice = log_question("Enable GREEDY_MODE for automated SMB/Looting? (y/n):").lower()

    # We update the actual config module so all imported files see it
    import config
    if greedy_choice == 'y':
        config.GREEDY_MODE = True
        log_success("POSTURE: GREEDY_MODE Enabled (Automated Enum/Looting).")
    else:
        config.GREEDY_MODE = False
        log_note("POSTURE: SURGICAL_MODE Active (Interactive Prompts).")

    print(f"{YELLOW}-------------------------------{RESET}\n")


    # --- 2. SESSION INITIALIZATION ---
    while not ctx:
        mode = log_question("Start [N]ew Session or [R]esume existing? (N/R):").lower()

        if mode == 'r':
            ctx = get_session_selection()
            if ctx:
                # Pre-Flight Re-hydration
                total_hosts, total_svcs = pre_flight_check(ctx)

                # Check for targets to allow Phase 2 or Option 99 to run
                host_file = ctx.dirs['targets'] / "hosts_all.txt"
                if host_file.exists():
                    with open(host_file, 'r') as f:
                        targets = " ".join([line.strip() for line in f if line.strip()])
                    log_success(f"Session {ctx.session_name} is now ACTIVE (Restored Targets).")
                else:
                    log_warn("Resumed session has no discovered hosts yet.")

        elif mode == 'n':
            customer = log_question("Enter Customer Name:")
            ctx = ScanContext(customer)
            log_note(f"Formats: {YELLOW}10.0.0.0/24, IP, or -iL <file>{RESET}")
            targets = log_question("Enter Initial Scan Target(s):")

        else:
            log_error("Selection required to proceed.")

    if ctx:
        start_dashboard(ctx)
        log_success(f"DASHBOARD ACTIVE: http://127.0.0.1:8888")
        log_note(f"Login: operator | Password: {ctx.customer}_{datetime.datetime.now().year}")


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

            # Logic for Specific Scan IDs
            if choice == "04":
                dns_ip = log_question("Enter Custom DNS Server IP (Leave blank for System Default):")
                if dns_ip.strip():
                    scan_meta['flags'] += f" --dns-servers {dns_ip.strip()}"
                    log_success(f"Using Custom DNS: {dns_ip}")
                    log_success("DNS mapping file: targets/hosts_ip-dns_mappings.txt")
                else:
                    scan_meta['flags'] += " --system-dns"
                    log_note("Using System Default DNS.")

            # --- Choice 05/61: Zombie Logic [NEW] ---
            elif choice in ["05", "61"]:
                print(f"\n{YELLOW}--- [ ZOMBIE STEALTH CONFIGURATION ] ---{RESET}")
                z_input = log_question("Enter Zombie Host (IP or IP:PORT) [Default Port 80]:")

                # Parse Input
                z_ip, z_port = z_input.split(":") if ":" in z_input else (z_input, "80")
                t_ports = log_question("Enter Target Port(s) to probe (e.g., 445, 80-100, or -p-):")

                # --- SUITABILITY CHECK ---
                print(f"\n{YELLOW}--- [ ZOMBIE SUITABILITY CHECK ] ---{RESET}")
                log_task(f"Preparing Zombie Validation on {z_ip}:{z_port}...")
                check_cmd = ["nmap", "-O", "-v", "-p", z_port, "--max-retries", "1", "--host-timeout", "30s", z_ip]
                log_task(f"Executing: {' '.join(check_cmd)}")


                try:
                    proc = subprocess.run(check_cmd, capture_output=True, text=True)
                    is_ready = "Incremental" in proc.stdout and f"{z_port}/tcp open" in proc.stdout

                    if is_ready:
                        log_success(f"Zombie {z_ip}:{z_port} is UP and PREDICTABLE (Incremental IPID).")
                    else:
                        log_warn(f"Zombie {z_ip} suitability check failed (Non-incremental or Port Closed).")
                        if log_question("Attempt stealth scan anyway? (y/n):").lower() != 'y':
                            continue # Jump back to main menu

                    # Overwrite flags with the surgical Zombie strings
                    z_flags = f"-Pn -vv -sI {z_ip}:{z_port} -p {t_ports}"
                    scan_meta['flags'] = z_flags
                    # Ensure hybrid scans (61) use it for both phases
                    scan_meta['flags_p1'] = z_flags
                    scan_meta['flags_p2'] = z_flags

                except Exception as e:
                    log_error(f"Zombie check failed: {e}")
                    continue

            elif choice == "10":
                # Override the global targets for this specific multicast task
                targets = "ff02::1"
                scan_meta['flags'] += f" -e {INTERFACE}"
                log_task(f"IPv6 Multicast Discovery Initialized on {INTERFACE}...")

            elif choice == "20":
                # Ensure we have a target to check for IPv6 colons
                current_target = targets if targets else "0.0.0.0" 

                if ":" in current_target:
                    # Only add -6 if it's not already in the config.py flags
                    if "-6" not in scan_meta['flags']:
                        scan_meta['flags'] += " -6"
                    log_task("SCTP Probe: IPv6 Multihoming Mode...")
                else:
                    log_task("SCTP Probe: IPv4 Legacy Mode...")

            elif choice == "36":
                print(f"\n{RED}{BOLD}!!! SCADA/ICS FRAGILITY WARNING !!!{RESET}")
                log_warn("Industrial controllers (PLCs/HMIs) can be crashed by active scanning.")
                log_warn("Scan 36 is locked to -T2 (Polite) to minimize packet per second impact.")

                if log_question("Are you CERTAIN you want to proceed with SCADA discovery? (y/n):").lower() != 'y':
                    log_note("Aborting SCADA Tasking.")
                    continue

            elif choice == "51":
                # Firewalking requires a single IP for accuracy in TTL calculation
                if "/" in targets or "," in targets:
                    log_error("Firewalk (51) requires a single Target IP, not a range.")
                    continue

                status = run_firewalk(ctx, targets)
                # This status can be pushed to your future dashboard
                log_note(f"Final Status: {status}")
                continue

            elif choice == "99":
                custom_flags = ""
                while not custom_flags:
                    custom_flags = log_question("Enter your custom Nmap flags (e.g. -Pn -n -vv -sS -p 80,443 -T4):")
                scan_meta['flags'] = custom_flags
                log_success(f"Custom Tasking Initialized: {custom_flags}")
            else:
                log_task(f"Tasking Initialized: {scan_meta['name']} (Phase {scan_meta['phases'][0]})")

            # --- PHASE ORCHESTRATION ---
            log_note(f"Handoff to Scanner Engine: {scan_meta['name']}...")

            # --- HIGH PERFORMANCE & SCOPE CHECK ---
            # Define "No-Boost" zones for fragile or stealthy scans
            no_boost_ids = ["02", "03", "04", "05", "20", "36", "37", "60", "61", "99"]

            # Logic: Is it the 'Kitchen Sink' OR a large CIDR range?
            is_kitchen_sink = (choice == "38")
            is_large_cidr = False

            if "/" in targets:
                try:
                    # Capture common large CIDR suffixes
                    suffix = int(targets.split("/")[-1])
                    if suffix <= 24: # /24, /23 /22 ... etc.
                        is_large_cidr = True
                except ValueError:
                    pass

            # Execution Gate
            if (is_kitchen_sink or is_large_cidr) and choice not in no_boost_ids:
                print(f"\n{YELLOW}{BOLD}--- [ HIGH PERFORMANCE CHECK ] ---{RESET}")
                log_warn(f"Large target scope or intensive scan detected: {targets}")

                confirm = log_question("Inject performance switches? (--min-rate 1000, --min-parallelism 100) (y/n):").lower()

                if confirm == 'y':
                    perf_flags = " --min-hostgroup 64 --min-parallelism 100 --min-rate 1000"

                    # Apply to all active phases of this scan
                    if 'flags' in scan_meta and scan_meta['flags']:
                        scan_meta['flags'] += perf_flags
                    if 'flags_p1' in scan_meta:
                        scan_meta['flags_p1'] += perf_flags
                    if 'flags_p2' in scan_meta:
                        scan_meta['flags_p2'] += perf_flags

                    log_success(f"Performance Boosters Active: {perf_flags}")
                else:
                    log_note("Proceeding with default Nmap timing.")

                print(f"{YELLOW}---------------------------------{RESET}\n")

            # TRACK 1: Phase 1 (Discovery)
            for current_phase in scan_meta['phases']:

                if current_phase == 1:
                    success = deploy_scan(ctx, targets, scan_meta, current_phase, choice)

                    if success:
                        file_base = f"phase{current_phase}_discovery_{ctx.customer}_{ctx.date_str}_{ctx.time_str}"
                        xml_path = ctx.dirs['artifacts'] / f"{file_base}.xml"
                        gnmap_path = ctx.dirs['artifacts'] / f"{file_base}.gnmap"

                        # Trigger Data Hydration
                        time.sleep(2) #Let nmap buffer flush to XML
                        parse_ok, total_hosts, total_svcs = parse_results(xml_path, gnmap_path, ctx)

                        if parse_ok:
                            log_success(f"Hydration Complete: {total_hosts} Hosts / {total_svcs} Services discovered.")

                            # --- [ GOWITNESS GATEKEEPER START ] ---
                            stealth_ids = ["02", "03", "04", "05", "10", "11", "20", "60", "61"]
                            web_found = False
                            web_keywords = ["http", "https", "web", "ssl", "nginx", "apache", "iis", "ws", "title"]

                            # Crawl discovered target directories for Web indicators
                            for d in ctx.dirs['targets'].iterdir():
                                if d.is_dir() and "_" in d.name:
                                    parts = d.name.lower().split("_")
                                    svc_name = parts[0]
                                    try:
                                        port_num = int(parts[-1])
                                    except: continue

                                    # Check Port Registry OR Keyword Match
                                    if port_num in WEB_PORTS or any(kw in svc_name for kw in web_keywords):
                                        web_found = True
                                        log_note(f"Web/HTTP Indicator: {d.name} identified.")
                                        break

                            # Trigger Web Screenshots ONLY if safe and necessary
                            if choice not in stealth_ids and web_found:
                                if xml_path.exists():
                                    log_task("Initializing goWitness Orchestration...")
                                    run_gowitness_scan(ctx, xml_path)
                                    gowit_proc = start_gowitness_server(ctx) 
                                    if gowit_proc:
                                        ACTIVE_PROCESSES.append(gowit_proc)
                                    log_success(f"goWitness Gallery is now LIVE: http://{INTERFACE_IP}:8889")
                                else:
                                    print(f"\n{YELLOW}-------- goWitness ----------{RESET}")
                                    log_warn("Skipping Gowitness: XML artifact missing.")
                            else:
                                if choice in stealth_ids:
                                    print(f"\n{YELLOW}-------- goWitness ----------{RESET}")
                                    log_note(f"OPSEC LOCK: Gowitness suppressed for Stealth ID {choice}.")
                                elif not web_found:
                                    log_note("Gowitness Skipped: No web-related services detected.")

                            print(f"{YELLOW}---------------------------------{RESET}\n")

                            # ONLY HOLD IF THIS IS THE ONLY/LAST PHASE
                            if len(scan_meta['phases']) == 1 or current_phase == scan_meta['phases'][-1]:
                                log_success(f"Session {ctx.session_name} Phase 1 Tasking Finished.")
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
                elif current_phase == 2:
                    success = deploy_audit_loop(ctx, scan_meta, current_phase, choice)

                    if success:
                        log_success("All Phase 2 Audits completed successfully.")

                        try:
                            print(f"\n{GREEN}{BOLD}$$$$$$$$$$ PHASE 2 COMPLETE $$$$$$$$$${RESET}")
                            log_note(f"Artifacts stored in : {ctx.base_path}")
                            log_note(f"goWitness Gallery   : http://{INTERFACE_IP}:8889")
                            log_note(f"Dashboard (Future)  : http://{INTERFACE_IP}:8888")
                            log_note(f"Exploit Report      : {ctx.dirs['artifacts']}/searchsploit_{ctx.customer}_{ctx.date_str}.txt")

                            print(f"\n{YELLOW}{BOLD}[*] Awaiting Exit...{RESET}")
                            log_note(f"Press [ctrl]+[c] to terminate services and generate summary.")
                            while True:
                                time.sleep(1)

                        except KeyboardInterrupt:
                        # This is the ONLY way out of the loop
                            cleanup_and_exit(ctx, SESSION_START_TIME, hosts=total_hosts, services=total_svcs)

                    else:
                        log_error("Audit Loop failed or was aborted.")

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
