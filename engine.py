# ==============================================================================
# SCRIPT: engine.py
# PURPOSE: Execution Engine for Subprocesses and Nmap Orchestration
# FUNCTIONALITY: 
#   - Executes shell commands via thread-safe subprocess management.
#   - Implements 'Ghost-Buster' logic to reap hung/zombie processes via timeouts.
#   - Streams live command output to the dashboard_data log list.
#   - Manages the Multi-Phase transition (Phase 1 Discovery -> Phase 2 Surgical).
#   - Signals the Web UI for scan completion via 'scan_active' flag toggling.
# ==============================================================================

import os, time, re, sys, subprocess, ipaddress
from datetime import datetime
from registry import scans
from surgeon import parse_and_sync_results, parse_gnmap_version_update, surgical_searchsploit_update, trigger_external_tools

# --- 1. ADD ANSI COLORS TO THE TOP ---
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


# --- Primary scan functionn ---
def run_scan(choice, target_cmd, exclude_flag, perf_switches, file_prefix, 
             BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock):

    # 1. passed in as arguments
    # --- PHASE CALCULATION ---
    current_scan = scans.get(choice, {})

    # 2. Check for scripts safely
    has_phase2 = "scripts" in current_scan
    total_phases = 2 if has_phase2 else 1

    # 3. Handle '99' or missing entries gracefully
    discovery_flags = current_scan.get("discovery", "")

    nmap_base_path = os.path.abspath(os.path.join(BASE_DIR, f"{file_prefix}_discovery"))
    xml_file = nmap_base_path + ".xml"

    # NOW we build the command string
    phase1_cmd = f'nmap {discovery_flags} {exclude_flag} {perf_switches} {target_cmd} -oA "{nmap_base_path}" --reason --open'


    # Update Dashboard Metrics (These now update the shared dictionary)
    dashboard_data['meta_user'] = CURRENT_USER
    dashboard_data['meta_time'] = datetime.now().strftime('%H:%M:%S')
    dashboard_data['meta_cmd'] = phase1_cmd
    dashboard_data['phase_info'] = f"Phase 1 of {total_phases}"
    dashboard_data['status'] = "Scanning (Reconnaissance Phase)..."

    # 2. Update the subprocess call to include the logs and lock
    print(f"\n{BLUE}[*]{RESET} Phase 1 Started: {phase1_cmd}")
    execute_subprocess_with_logging(phase1_cmd, live_logs, completion_lock)

    # --- IDLE SCAN CONFIRMATION ---
    if "-sI" in phase1_cmd:
        try:
            zombie_used = phase1_cmd.split("-sI")[1].split()[0]
            print(f"\n{GREEN}[+]{RESET} IDLE SCAN SUCCESSFUL against {target_cmd}")
            print(f"{BLUE}[*]{RESET} Zombie Host: {zombie_used}")
        except:
            print("\n[!] Idle Scan triggered, but Zombie IP could not be parsed.")
        sys.stdout.flush() 

    # 2. --- POST-PHASE 1: TOOLS & DASHBOARD ---
    print(f"\n{BLUE}[*]{RESET} Phase 1 finished. Syncing files and triggering tools...")

    # Wait for I/O to settle before parsing
    count = 0
    while not os.path.exists(xml_file) and count < 5:
        time.sleep(1)
        count += 1

    parse_and_sync_results(xml_file, dashboard_data, BASE_DIR, choice)

    print(f"{YELLOW}[*]{RESET} Debug: Parser found {dashboard_data.get('service_count', 0)} open services.")

    if dashboard_data.get('service_count', 0) == 0:
        print(f"{YELLOW}[!]{RESET} No open ports found in Phase 1. Concluding.")
        dashboard_data['status'] = "FINISHED (No targets for Phase 2)"
        return 

    try:
        trigger_external_tools(xml_file, choice, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs)
    except Exception as e:
        msg = f"{RED}[!] WARNING:{RESET} Background tools encountered an error: {e}"
        print(msg)
        with completion_lock:
            live_logs.append(msg)

    # 3. --- PHASE 2: SURGICAL DEEP DIVE (GNMAP LOOP) ---
    if has_phase2:
        gnmap_file = nmap_base_path + ".gnmap"

        # Stability: Ensure GNMAP is ready
        count = 0
        while not os.path.exists(gnmap_file) and count < 5:
            time.sleep(1)
            count += 1

        # Extract IP:PORT relationships (Grepable Parsing)
        surgical_targets = []
        if os.path.exists(gnmap_file):
            with open(gnmap_file, 'r') as f:
                for line in f:
                    if "Ports:" in line and "Status: Up" not in line:
                        parts = line.split()
                        target_ip = parts[1]
                        # Extract only 'open' ports
                        open_ports = re.findall(r'(\d+)/open', line)
                        if open_ports:
                            surgical_targets.append((target_ip, ",".join(open_ports)))

        if not surgical_targets:
            print(f"{YELLOW}[!]{RESET} No open ports found in GNMAP. Skipping Phase 2.")
            dashboard_data['status'] = "FINISHED (No targets for Phase 2)"
            return

        # Execute Surgical Loop
        script_flags = scans[choice].get("scripts", "").strip()
        total_hosts = len(surgical_targets)

        for idx, (ip, ports) in enumerate(surgical_targets, 1):
            try:
                # Define output base - we add -oA to get GNMAP for the version parser
                phase2_out_base = os.path.abspath(os.path.join(BASE_DIR, f"audit_{ip}"))

                # MODIFIED: Added -oA to ensure we get .gnmap for the surgical version parser
                p2_cmd = f'nmap -Pn {script_flags} -p {ports} {ip} -oA "{phase2_out_base}" --reason'

                # Update Dashboard Status
                dashboard_data['phase_info'] = f"Phase 2: Host {idx} of {total_hosts}"
                dashboard_data['status'] = f"Auditing {ip} (Port {ports})"
                dashboard_data['meta_cmd'] = p2_cmd

                print(f"\n{BLUE}[*]{RESET} Surgical Audit {idx}/{total_hosts}: {p2_cmd}")
                execute_subprocess_with_logging(p2_cmd, live_logs, completion_lock) ##############################################

                # --- UPDATE THE DASHBOARD IN REAL-TIME VIA GNMAP ---
                from surgeon import parse_gnmap_version_update, surgical_searchsploit_update

                # We pass the .gnmap file to get the cleanest version strings
                parse_gnmap_version_update(f"{phase2_out_base}.gnmap", dashboard_data)

                # Trigger SearchSploit using the surgical .nmap text file
                surgical_searchsploit_update(f"{phase2_out_base}.nmap", xml_file, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data)

            except Exception as e:
                print(f"{RED}[!] WARNING:{RESET} Error auditing {ip}: {e}")
                continue

    # --- FINAL CONCLUSION BLOCK ---
    # Ensure BLUE, BOLD, and RESET are imported or defined in engine.py
    print(f"\n{BLUE}{BOLD}" + "!"*70)
    print(f"[*] SESSION COMPLETE:{RESET} {file_prefix}")
    print(f"{BLUE}{BOLD}[*] Artifacts stored in:{RESET} {BASE_DIR}")
    print(f"{BLUE}{BOLD}[!] Dashboard is LIVE. Press {RESET}Ctrl+C{BLUE}{BOLD} to exit.")
    print(f"!"*70 + f"{RESET}\n")

    # Update the SHARED dictionary so the Dashboard stops the heartbeat
    dashboard_data['status'] = "FINISHED (Full Audit Complete)"

    # Wait 2 seconds to ensure the Flask heartbeat catches up
    # before we flip the 'active' switch and kill the thread.
    time.sleep(2) 

    # Trigger the JavaScript 'clearInterval' in index.html
    dashboard_data['scan_active'] = False 

    # Final Terminal Signal
    print(f"{GREEN}[+]{RESET} Scan Engine Thread successfully de-registered.")


def execute_subprocess_with_logging(cmd, live_logs, completion_lock):
    """Streams command output to console and dashboard with thread-safety."""
    use_shell = isinstance(cmd, str)

    # Use bufsize=1 for line-buffered streaming
    proc = subprocess.Popen(cmd, shell=use_shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    for line in iter(proc.stdout.readline, ''):
        clean_line = line.strip()
        if clean_line:
            sys.stdout.write(line)
            sys.stdout.flush()

            # --- MODULAR LOCKING ---
            with completion_lock: 
                live_logs.append(clean_line)
                #print(f"{YELLOW} [!] DEBUG:{RESET} Engine appended to live_logs. Current size: {len(live_logs)}")
                if len(live_logs) > 20:
                    live_logs.pop(0)

    try:
        return_code = proc.wait(timeout=10)
        print(f"{YELLOW}[*] DEBUG:{RESET} Process exited with {return_code}")
    except subprocess.TimeoutExpired:
        print("{RED}[!] DEBUG: GHOST DETECTED!{RESET} Process timed out. Killing...")
        proc.kill()
        return_code = proc.poll()

    with completion_lock:
        live_logs.append("--- COMMAND PHASE COMPLETE ---")


def is_local_target(target, local_ips):
    """Checks if the target is in the same /24 as the attacker."""
    if not local_ips: return False
    try:
        # 1. Strip any CIDR notation from the target if present
        target_clean = target.split('/')[0]

        # 2. Compare first three octets
        attacker_net = ".".join(local_ips.split('.')[:-1])
        target_net = ".".join(target_clean.split('.')[:-1])

        return attacker_net == target_net
    except:
        return False
