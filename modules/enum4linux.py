#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module:  modules/enum4linux.py
Purpose: Gathers system and environemntal details of Windows hosts
        through either surgical OR greedy/aggressive tool usage. 
"""

import time
import subprocess
from config import GREEDY_MODE
from core.ui import (
    log_task, log_success, log_error, log_note, 
    YELLOW, BLUE, RED, CYAN, BOLD, RESET, BULLET
    )
from core.system import INTERFACE

"""
Project: Scanroids Red Team Orchestrator
Module:  modules/enum4liux.py
Executes enum4linux with a dedicated Tshark packet capture.
Attempts logic tree based on discovered ports and protocols.
"""


def run_enum4linux(ctx, ip, choice, INTERFACE):
    # 1. Identify which SMB/NetBIOS folders exist for this specific IP
    found_tcp = []
    found_udp = []

    for d in ctx.dirs['targets'].iterdir():
        if d.is_dir() and "_" in d.name:
            parts = d.name.split("_") # [service, port, proto]
            if len(parts) < 3: continue

            svc, port, proto = parts[0], int(parts[1]), parts[2]

            # Verify this IP is actually in this service's host list
            host_file = d / "hosts_all.txt"
            if host_file.exists() and ip in host_file.read_text():
                if proto == 'tcp': found_tcp.append(port)
                if proto == 'udp': found_udp.append(port)

    # 2. Apply your Logic Tree
    cmd_flags = ""

    # GREEDY MODE Spray and Pray
    if GREEDY_MODE:
        cmd_flags = "-A -v"
        log_task(f"GREEDY MODE ACTIVE: Firing Full SMB Audit (-A) for {ip}")
    else:
        # Scenario 1: UDP 137 only -> NetBIOS Discovery
        if 137 in found_udp and not any(p in found_tcp for p in [135, 139, 445]):
            cmd_flags = "-n -v"
            log_task(f"Logic Match: NetBIOS Discovery for {ip}")

        # Scenario 2: TCP 135/139 only -> MSRPC/Session Enum
        elif all(p in found_tcp for p in [135, 139]) and 445 not in found_tcp and 137 not in found_udp:
            cmd_flags = "-U -G -P -o -v"
            log_task(f"Logic Match: MSRPC/Session Enum for {ip}")

        # Scenario 3: TCP 445 only -> SMB Share Enum
        elif 445 in found_tcp and not any(p in found_tcp for p in [135, 139]) and 137 not in found_udp:
            cmd_flags = "-S -M -v"
            log_task(f"Logic Match: SMB Share Enum for {ip}")

        # Fallback: If it's a mix or something else, use the safe 'All' or skip
        else:
            if not found_tcp and not found_udp: return # No SMB found
            cmd_flags = "-A -v" # Broadest coverage if logic doesn't perfectly match
            log_task(f"Logic Match: Full SMB/NetBIOS Audit for {ip}")

    # --- Setup Naming for the PCAP ---
    file_base = f"enum4_audit_{ctx.customer}_{ip.replace('.','-')}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
    log_file = ctx.base_path / "logs" / f"enum4linux_{ip.replace('.','-')}.log"

    # --- Start Tshark (Targeted Filter) ---
    # We filter specifically for the Target IP to keep the PCAP clean
    cap_filter = f"host {ip}"
    t_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", cap_filter, "-q"]

    print(f"\n{YELLOW}--- [ SMB PACKET CAPTURE ] ---{RESET}")
    log_task(f"Capture Start: {pcap_path.name}")
    log_note(f"Wireshark filter: {RESET}'smb || ntlmssp || dcerpc'")
    t_proc = subprocess.Popen(t_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) # Warmup


    # --- SMB ENUMERATION Execution
    cmd = ["enum4linux"] + cmd_flags.split() + [ip]
    print(f"\n{YELLOW}--- [ SMB SURGICAL ENUMERATION ] ---{RESET}")
    log_task(f"Command: {' '.join(cmd)}")

    try:
        with open(log_file, "w") as f:
            # We use bufsize=1 for real-time line buffering to the terminal
            e_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in e_proc.stdout:
                print(line, end="")
                f.write(line)
            e_proc.wait()

        log_success(f"SMB Enum Finished. Log: {log_file.name}")
        log_success(f"PCAP Generated: {pcap_path.name}")
    except Exception as e:
        log_error(f"Enum4linux error: {e}")
    finally:
        if 't_proc' in locals():
            t_proc.terminate()
            log_note(f"Capture Closed for {ip}")
        print(f"{YELLOW}------------------------------{RESET}\n")
