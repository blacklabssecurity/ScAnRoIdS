#!/usr/bin/env pyt from modules.searchsploit import run_searchhon3
"""
Project: Scanroids Red Team Orchestrator
Module:  core/scanner.py
Purpose: Orchestrates the simultaneous execution of Tshark packet capture 
         and Nmap scanning with real-time command echoing and terminal feedback.
"""

import subprocess
import time
import os
import signal
import xml.etree.ElementTree as ET
from core.ui import log_note, log_task, log_success, log_error, log_warn, RESET, BOLD, BLUE, YELLOW, RED, MAGENTA, GREEN, CYAN
from core.system import INTERFACE, LOCAL_IPS
from core.parser import get_host_telemetry
from modules.searchsploit import run_search


def deploy_scan(ctx, targets, scan_meta):
    """
    Main execution wrapper for a scan task.
    :param ctx: ScanContext object (for paths/naming)
    :param targets: String of targets (IP/CIDR/File)
    :param scan_meta: Dictionary containing flags/phase/name
    """

    # 1. Setup Naming & Paths
    file_base = f"phase{scan_meta['phase']}_{ctx.customer}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
    nmap_out_base = ctx.dirs['artifacts'] / file_base

    # 2. Construct Commands
    # Tshark: Capture on primary interface, quiet mode (-q)
    tshark_cmd = [
        "tshark", "-i", INTERFACE, 
        "-w", str(pcap_path),
        "-q"
    ]
    tshark_echo = " ".join(tshark_cmd)

    # Nmap: Comprehensive build including exclusions and artifacts
    nmap_cmd = [
        "nmap", 
        *scan_meta['flags'].split(),
        "--exclude", LOCAL_IPS,
        "-oA", str(nmap_out_base),
        "--reason",
        targets
    ]
    nmap_echo = " ".join(nmap_cmd)

    # 3. Execution Phase
    print(f"\n{YELLOW}--- [ PACKET CAPTURE PHASE ] ---{RESET}")
    log_task(f"Initializing Packet Capture: {tshark_echo}")
    print(f"{YELLOW}--------------------------------{RESET}\n")

    try:
        # Start Tshark (Background)
        t_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2) # Interface warmup

        print(f"\n{YELLOW}------ [ SCANNING PHASE ] ------{RESET}")
        log_task(f"Executing Nmap Task: {nmap_echo}")
        print(f"{BOLD}{BLUE}{'='*33} Live Logs {'='*33}{RESET}")

        # Start Nmap (Foreground with live streaming)
        with subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as n_proc:
            for line in n_proc.stdout:
                print(line, end="") # Direct terminal output

            n_proc.wait()

        print(f"{BOLD}{BLUE}{'='*80}{RESET}")
        log_success(f"Nmap Task Completed Successfully.")

    except KeyboardInterrupt:
        log_warn("Scan Aborted by Operator. Terminating background processes...")
        if 't_proc' in locals(): t_proc.terminate()
        return False
    except Exception as e:
        log_error(f"Scanner Engine Failure: {e}")
        return False
    finally:
        # Ensure Tshark is always closed to finalize the PCAP file
        if 't_proc' in locals():
            t_proc.terminate()
            log_success(f"Capture Closed: {pcap_path.name}")

    return True


def deploy_audit_loop(ctx, scan_meta):
    """
    Reads discovered hosts and executes a host-by-host deep audit.
    :param ctx: ScanContext object
    :param scan_meta: Dictionary containing audit flags/name
    """
    target_file = ctx.dirs['targets'] / "hosts_all.txt"

    if not target_file.exists():
        log_error("Audit Loop Failed: No discovered hosts found in targets/hosts_all.txt")
        log_note("Please run a Discovery Scan (Phase 1) first to populate targets.")
        return False

    # 1. Load targets into a list
    with open(target_file, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]

    if not hosts:
        log_warn("Audit Loop: hosts_all.txt is empty. No targets to audit.")
        return False

    log_task(f"Initializing Phase 2 Audit for {len(hosts)} targets...")

    # 2. Iterate through each host
    for index, ip in enumerate(hosts, 1):
        print(f"\n{BLUE}{BOLD}[Audit {index}/{len(hosts)}]{RESET} {CYAN}Targeting Host: {ip}{RESET}")

        # --- PORT RECONSTRUCTION ---
        # Logic: Look at all folders in ./targets/ and if ip is in their hosts_all.txt, add that port
        target_ports = set() # Use a set to prevent duplicate port IDs

        # Iterate through the targets subdirectories
        for svc_dir in ctx.dirs['targets'].iterdir():
            # Check for folders like 'http_80', 'ssh_22', etc.
            if svc_dir.is_dir() and "_" in svc_dir.name:
                try:
                    port_id = svc_dir.name.split("_")[-1]
                    host_file = svc_dir / "hosts_all.txt"

                    if host_file.exists():
                        # Using 'with' is safer for file handles
                        with open(host_file, 'r') as hf:
                            if ip in hf.read():
                                target_ports.add(port_id)
                except Exception:
                    continue # Skip malformed directory names

        # Convert set back to a sorted list for the Nmap -p flag
        sorted_ports = sorted(list(target_ports), key=int)

        if not target_ports:
            log_note(f"Skipping {ip}: No open ports mapped in Phase 1.")
            continue

        # --- THE TACTICAL NOTE ---
        port_string = ",".join(target_ports)
        print(f"\n{BLUE}{BOLD}[Audit {index}/{len(hosts)}]{RESET} {CYAN}Target: {ip}{RESET}")
        log_note(f"Resuming Audit: Found {len(target_ports)} services from previous Phase 1 artifact. ({port_string})")

        # 3. Setup Naming for this specific host
        file_base = f"audit_{ctx.customer}_{ip.replace('.','-')}_{ctx.date_str}"
        pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
        nmap_base = ctx.dirs['artifacts'] / file_base

        # 4. Construct Commands (Filtered PCAP)
        tshark_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", f"host {ip}", "-q"]
        nmap_cmd = [
            "nmap", *scan_meta['flags'].split(),
            "-p", port_string,
            "--exclude", LOCAL_IPS,
            "-oA", str(nmap_base),
            "--reason", ip
        ]

        # 5. Execution Block
        try:
            print(f"\n{YELLOW}--- [ PACKET CAPTURE PHASE ] ---{RESET}")
            log_task(f"Capture Start: {pcap_path.name}")
            print(f"{YELLOW}--------------------------------{RESET}\n")
            t_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2) # Warmup

            print(f"\n{YELLOW}------ [ SCANNING PHASE ] ------{RESET}")
            log_task(f"Audit Start  : {' '.join(nmap_cmd)}")
            print(f"{BOLD}{BLUE}{'='*33} Live Logs {'='*33}{RESET}")

            with subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as n_proc:
                for line in n_proc.stdout:
                    print(line, end="")
                n_proc.wait()

            print(f"{BOLD}{BLUE}{'='*80}{RESET}")
            log_success(f"Audit Complete for {ip}")

            # 2. Post-Scan Analysis (Triggered after Nmap finishes for THIS host)
            xml_file = nmap_base.with_suffix('.xml')   
            gnmap_file = nmap_base.with_suffix('.gnmap')

            if xml_file.exists():
                tree = ET.parse(xml_file)
                root = tree.getroot()

                for host in root.findall('host'):
                    # Get OS/TTL Telemetry (The tiered logic we just built)
                    data = get_host_telemetry(ctx, ip, host_node=host, gnmap_path=gnmap_file)
                    log_success(f"Host Details: {data['os']} (TTL: {data['ttl']})")

                    # A. Search by Services
                    for port in host.findall('.//port'):
                        svc = port.find('service')
                        if svc is not None:
                            product = svc.get('product', '')
                            version = svc.get('version', '')
                            query = f"{product} {version}".strip()
                            if query: # Safety check for empty queries
                                run_search(ctx, query, ip=ip)

                    # B. Search by Kernel
                    if data['kernel'] != "Unknown":
                        log_note(f"Kernel identified: {data['kernel']}. Searching exploits...")
                        run_search(ctx, data['kernel'], ip=ip)

        except KeyboardInterrupt:
            log_warn(f"Audit Loop Aborted by Operator during {ip}.")
            if 't_proc' in locals(): t_proc.terminate()
            return False
        finally:
            if 't_proc' in locals():
                t_proc.terminate()
                log_note(f"Capture Closed for {ip}")

    log_success("Full Audit Loop Finished.")
    return True


# --- FUTURE HOOKS (Gowitness, SearchSploit) ---
# We will follow this same 'log_task' + 'echo command' pattern for 
# the auxiliary tools in the next module.
