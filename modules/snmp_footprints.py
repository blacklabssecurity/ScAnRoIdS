#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/snmp_footprints.py
Purpose: Two-Stage SNMP Interrogation:
         1. Brute/Verify Community String (onesixtyone)
         2. Deep Interrogation (snmp-check)
"""

import subprocess
import time
from config import GREEDY_MODE
from core.ui import (
    log_task, log_success, log_error, log_note, log_warn,
    log_question, YELLOW, RESET, BLUE, BOLD, RED, CYAN
    )
from core.system import INTERFACE


def run_snmp_enum(ctx, ip):
    # 1. Setup Naming and Paths
    file_base = f"snmp_audit_{ctx.customer}_{ip.replace('.','-')}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
    log_file = ctx.base_path / "logs" / f"snmp_audit_{ip.replace('.','-')}.log"
    discovery_out = ctx.dirs['artifacts'] / "snmp_discovery.txt"

    # 2. Tshark Filter (UDP 161)
    cap_filter = f"host {ip} and udp port 161"
    t_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", cap_filter, "-q"]

    print(f"\n{YELLOW}--- [ SNMP PACKET CAPTURE ] ---{RESET}")
    log_task(f"Capture Start: {pcap_path.name}")
    t_proc = subprocess.Popen(t_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) # Warmup

    try:
        found_string = ""

        # --- STAGE 1: COMMUNITY STRING DISCOVERY ---
        if GREEDY_MODE:
            log_task("GREEDY MODE: Running Aggressive SNMP Brute...")
            wordlist = "/usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt"
            found_string = _execute_onesixtyone(ip, wordlist)
        else:
            print(f"\n{YELLOW}--- [ SNMP SURGICAL SELECTION ] ---{RESET}")
            print(f"1. Short List ................: /usr/share/doc/onesixtyone/dict.txt")
            print(f"2. Aggressive List ...........: /usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt")
            print(f"3. Manual Entry (Full Path) ..: [Enter Location]")
            print(f"4. Direct Entry (Single String): [Enter String]")

            choice = log_question("Select SNMP Discovery Method (Default 'public'):")

            if choice == "1":
                found_string = _execute_onesixtyone(ip, "/usr/share/doc/onesixtyone/dict.txt")
            elif choice == "2":
                found_string = _execute_onesixtyone(ip, "/usr/share/wordlists/seclists/Discovery/SNMP/snmp-onesixtyone.txt")
            elif choice == "3":
                path = log_question("Enter full path to wordlist:")
                found_string = _execute_onesixtyone(ip, path)
            elif choice == "4":
                found_string = log_question("Enter community string:")
            else:
                # Default attempt
                found_string = _execute_onesixtyone(ip, "public", is_single=True)

        # --- STAGE 2: DETAILED INTERROGATION ---
        if found_string:
            log_success(f"Proceeding with discovered string: '{found_string}'")
            print(f"\n{YELLOW}--- [ SNMP DETAILED INVENTORY ] ---{RESET}")

            s_cmd = ["snmp-check", ip, "-c", found_string]
            log_task(f"Executing: {' '.join(s_cmd)}")

            with open(log_file, "a") as f, open(discovery_out, "a") as out:
                header = f"\n{'='*20} SNMP: {ip} ({found_string}) {'='*20}\n"
                out.write(header)

                s_proc = subprocess.Popen(s_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in s_proc.stdout:
                    print(line, end="") # Live terminal feedback
                    f.write(line)
                    out.write(line)
                s_proc.wait()

            log_success(f"SNMP Inventory saved to artifacts/snmp_discovery.txt")
        else:
            log_error(f"Failed to identify a valid SNMP community string for {ip}")

    except Exception as e:
        log_error(f"SNMP Module Error: {e}")
    finally:
        if 't_proc' in locals():
            t_proc.terminate()
            log_note(f"SNMP Capture Closed for {ip}")
        print(f"{YELLOW}------------------------------{RESET}\n")


def _execute_onesixtyone(ip, target, is_single=False):
    """Internal helper to run onesixtyone and return the first valid string found."""
    if is_single:
        # Create a temp file for a single string if onesixtyone requires it
        cmd = ["onesixtyone", "-c", target, ip]
    else:
        cmd = ["onesixtyone", "-c", target, ip]

    log_task(f"Interrogating: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)

    # onesixtyone output format: IP [community_string] System_Description
    if "[" in res.stdout:
        # Extracts 'public' from '192.168.1.1 [public] Hardware: ...'
        return res.stdout.split("[")[1].split("]")[0]
    return ""
