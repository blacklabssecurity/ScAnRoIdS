# ==============================================================================
# SCRIPT: engine.py (REFACTORED BASELINE)
# PURPOSE: High-Performance Execution Engine & Concurrent Orchestration
# ==============================================================================

import os, time, re, sys, subprocess, threading, signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from registry import scans
from surgeon import parse_and_sync_results, parse_gnmap_version_update, surgical_searchsploit_update, trigger_external_tools

# --- 1. GLOBALS & COLORS ---
BLUE, YELLOW, GREEN, RED, BOLD, RESET = "\033[94m", "\033[93m", "\033[92m", "\033[91m", "\033[1m", "\033[0m"
active_processes = []

def cleanup_processes(sig=None, frame=None):
    """Ensures all nmap and tshark processes die on exit."""
    print(f"\n{RED}[!] REAPING PROCESSES...{RESET}")
    for p in active_processes:
        try: p.terminate()
        except: pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_processes)

# --- 2. LOGGING ENGINE ---
def execute_subprocess_with_logging(cmd, live_logs, completion_lock, timeout=None):
    """Streams output to console and dashboard buffer."""
    use_shell = isinstance(cmd, str)
    proc = subprocess.Popen(cmd, shell=use_shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    active_processes.append(proc)

    try:
        for line in iter(proc.stdout.readline, ''):
            if line:
                sys.stdout.write(line)
                sys.stdout.flush()
                with completion_lock:
                    live_logs.append(line.strip())
                    if len(live_logs) > 50: live_logs.pop(0) # Increased buffer
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
    finally:
        if proc in active_processes: active_processes.remove(proc)

# --- 3. SURGICAL WORKER (FOR CONCURRENCY) ---
def audit_host_task(ip, ports, script_flags, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs, completion_lock, xml_phase1):
    """Worker function for parallel Phase 2 auditing."""
    phase2_out = os.path.abspath(os.path.join(BASE_DIR, f"audit_{ip}"))
    p2_cmd = f'nmap -Pn {script_flags} -p {ports} {ip} -oA "{phase2_out}" --reason'
    
    execute_subprocess_with_logging(p2_cmd, live_logs, completion_lock)
    
    # Update dashboard with new version info immediately
    parse_gnmap_version_update(f"{phase2_out}.gnmap", dashboard_data)
    surgical_searchsploit_update(f"{phase2_out}.nmap", BASE_DIR, CUSTOMER, DATE_STR, dashboard_data)

# --- 4. PRIMARY SCAN ENGINE ---
def run_scan(choice, target_cmd, exclude_flag, perf_switches, file_prefix, 
             BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock):

    current_scan = scans.get(choice, {})
    total_phases = 2 if "scripts" in current_scan else 1
    
    # --- STEP 0: START TSHARK CAPTURE ---
    cap_dir = os.path.join(BASE_DIR, "captures")
    os.makedirs(cap_dir, exist_ok=True)
    pcap_file = os.path.join(cap_dir, f"{CUSTOMER}_{DATE_STR}.pcapng")
    
    print(f"{BLUE}[*]{RESET} Starting Tshark background capture: {pcap_file}")
    tshark_proc = subprocess.Popen(["tshark", "-i", "any", "-f", f"host {target_cmd}", "-w", pcap_file], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    active_processes.append(tshark_proc)

    # --- PHASE 1: DISCOVERY ---
    nmap_base = os.path.abspath(os.path.join(BASE_DIR, f"{file_prefix}_discovery"))
    phase1_cmd = f'nmap {current_scan.get("discovery", "")} {exclude_flag} {perf_switches} {target_cmd} -oA "{nmap_base}" --reason --open'
    
    dashboard_data.update({'status': "Phase 1: Discovery...", 'phase_info': f"Phase 1 of {total_phases}", 'meta_cmd': phase1_cmd})
    execute_subprocess_with_logging(phase1_cmd, live_logs, completion_lock)
    
    parse_and_sync_results(f"{nmap_base}.xml", dashboard_data, BASE_DIR)
    trigger_external_tools(f"{nmap_base}.xml", choice, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs)

    # --- PHASE 2: CONCURRENT AUDIT ---
    if total_phases == 2:
        surgical_targets = [] # Parse GNMAP for IP:PORT pairs
        with open(f"{nmap_base}.gnmap", 'r') as f:
            for line in f:
                if "Ports:" in line:
                    ip = line.split()[1]
                    open_ports = re.findall(r'(\d+)/open', line)
                    if open_ports: surgical_targets.append((ip, ",".join(open_ports)))

        if surgical_targets:
            script_flags = current_scan.get("scripts", "").strip()
            print(f"{BLUE}[*]{RESET} Starting Concurrent Phase 2 (Workers: 5)")
            with ThreadPoolExecutor(max_workers=5) as executor:
                for ip, ports in surgical_targets:
                    executor.submit(audit_host_task, ip, ports, script_flags, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs, completion_lock, f"{nmap_base}.xml")

    # --- CLEANUP ---
    tshark_proc.terminate()
    dashboard_data['status'] = "FINISHED (Full Audit Complete)"
    dashboard_data['scan_active'] = False
    print(f"\n{GREEN}[+]{RESET} SESSION COMPLETE. Artifacts in {BASE_DIR}")
