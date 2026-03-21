#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  nfs_enum.py
Purpose: Surgical RPC (111) and NFS (2049) enumeration module.
         Performs Portmapper queries, Export discovery, and conditional looting.
"""

import time
import subprocess
from config import GREEDY_MODE
from core.ui import (
    log_task, log_success, log_error, log_note, log_warn, 
    log_question, YELLOW, RESET, BLUE, BOLD, RED, GREEN, BULLET
    )
from core.system import INTERFACE


def run_nfs_enum(ctx, ip, choice):
    # 1. Setup Naming and Paths
    file_base = f"nfs_audit_{ctx.customer}_{ip.replace('.','-')}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
    log_file = ctx.base_path / "logs" / f"nfs_enum_{ip.replace('.','-')}.log"

    # 2. Tshark Filter (RPC + NFS + Mountd)
    # BPF: Port 111 (Portmapper), 2049 (NFS), 20048 (Common Mountd)
    cap_filter = f"host {ip} and (port 111 or port 2049 or port 20048)"
    t_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", cap_filter, "-q"]

    print(f"\n{YELLOW}--- [ NFS/RPC PACKET CAPTURE ] ---{RESET}")
    log_task(f"Capture Start: {pcap_path.name}")
    log_note(f"Wireshark filter: {RESET}'rpc || nfs || mountd'")

    t_proc = subprocess.Popen(t_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) # Warmup

    try:
        with open(log_file, "w") as f:
            # --- STEP A: RPCINFO (Portmapper Query) ---
            print(f"\n{YELLOW}--- [ RPC PORTMAPPER QUERY ] ---{RESET}")
            log_task(f"Executing: rpcinfo -p {ip}")
            rpc_res = subprocess.run(["rpcinfo", "-p", ip], capture_output=True, text=True, timeout=30)

            if rpc_res.returncode == 0:
                f.write("--- [ RPCINFO OUTPUT ] ---\n" + rpc_res.stdout + "\n")
                print(rpc_res.stdout)
                log_success("RPC Program list retrieved.")
            else:
                log_error("RPC Portmapper query failed.")

            # --- STEP B: SHOWMOUNT (Export Discovery) ---
            print(f"\n{YELLOW}--- [ NFS EXPORT DISCOVERY ] ---{RESET}")
            log_task(f"Executing: showmount -e {ip}")
            sm_res = subprocess.run(["showmount", "-e", ip], capture_output=True, text=True, timeout=30)

            exports_found = []
            if sm_res.returncode == 0:
                f.write("--- [ SHOWMOUNT EXPORTS ] ---\n" + sm_res.stdout + "\n")
                print(sm_res.stdout)
                log_success("NFS Export list retrieved.")

                # Identify exports for potential anonymous access
                exports_found = [line.strip() for line in sm_res.stdout.splitlines() if "/" in line]

            # --- STEP C: CONDITIONAL LOOTING ---
            is_wide_open = any("*" in e or "everyone" in e.lower() for e in exports_found)

            if is_wide_open or GREEDY_MODE:
                if is_wide_open:
                    log_warn(f"WIDE-OPEN NFS EXPORT DETECTED on {ip}!")

                do_loot = GREEDY_MODE or (log_question(f"Map open NFS shares for {ip}? (y/n):").lower() == 'y')

                if do_loot:
                    for export in exports_found:
                        share_path = export.split()[0]
                        f.write(f"[LOOT CANDIDATE] Export: {export}\n")
                        log_success(f"Export mapped for reporting: {share_path}")

        log_success(f"NFS Enum Finished. Log: {log_file.name}")
        log_success(f"PCAP Generated: {pcap_path.name}")

    except Exception as e:
        log_error(f"NFS Enum error: {e}")
    finally:
        if 't_proc' in locals():
            t_proc.terminate()
            log_note(f"NFS Capture Closed for {ip}")
        print(f"{YELLOW}------------------------------{RESET}\n")
