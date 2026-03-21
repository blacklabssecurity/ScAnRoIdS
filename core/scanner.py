#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  core/scanner.py
Purpose: Orchestrates the simultaneous execution of Tshark packet capture 
         and Nmap scanning with real-time command echoing and terminal feedback.
"""

import os
import time
import signal
import subprocess
import xml.etree.ElementTree as ET
from core.ui import (
    log_note, log_task, log_success, log_error,
    log_warn, RESET, BOLD, BLUE, YELLOW, RED,
    MAGENTA, GREEN, CYAN
    )
from core.system import INTERFACE, LOCAL_IPS, nmap_to_bpf
from core.parser import get_host_telemetry
from config import (
    SMB_TCP_PORTS, SMB_UDP_PORTS, GREEDY_MODE,
    AUTO_LOOT_SHARES, SCTP_PORTS, WEB_PORTS, MGMT_TCP,
    MGMT_UDP, SCADA_TCP,SCADA_UDP, LINUX_PORTS, 
    WINDOWS_PORTS, NFS_TCP_PORTS
    )
# External Tool Modules
from modules.smbget import run_smbget
from modules.nfs_enum import run_nfs_enum
from modules.enum4linux import run_enum4linux
from modules.searchsploit import run_search


def deploy_scan(ctx, targets, scan_meta, phase_num, choice):
    """
    Main execution wrapper for a scan task.
    :param ctx: ScanContext object (for paths/naming)
    :param targets: String of targets (IP/CIDR/File)
    :param scan_meta: Dictionary containing flags/phase/name
    """

    # --- Setup Naming & Paths ---
    file_base = f"phase{phase_num}_discovery_{ctx.customer}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
    nmap_out_base = ctx.dirs['artifacts'] / file_base

    # --- Construct Commands ---
    # Initialize the capture filter
    # Note: Ensure 'choice' or 'scan_id' is passed into deploy_scan from main.py
    # For scans with larger target lists and/or ports lists, we will attempt BPF filters.
    # This may include lists provided by the operator and/or lists contained above (port registry).
    cap_filter = ""


    # Scan 01: Aggressive Discovery Scan (-PU, -PS, -PA, -PE)
    if choice == "01":
        ip_bpf = nmap_to_bpf(targets)
        # Restrict broad protocol capture to the defined target scope
        cap_filter = f"({ip_bpf}) and (tcp or udp or icmp)"
        log_note("Tshark Filter: Capturing all TCP/UDP/ICMP Discovery traffic.")

    # Scan 02: ACK 'Ping' Discovery (Stateless Firewall Check)
    elif choice == "02":
        # Extract the ports from the flags to keep the filter in sync
        # Flags: -sn -n -vv -PA21,22,23,80...
        ip_bpf = nmap_to_bpf(targets)
        ack_ports = "21,22,23,80,88,111,135,443,445,2049,3389"
        port_bpf = ack_ports.replace(',', ' or port ')

        # Logic: (Target IPs) AND (Target Ports OR any TCP Reset)
        # Note: We keep 'tcp-rst' outside the port list to catch resets on any port
        cap_filter = f"({ip_bpf}) and (tcp port {port_bpf} or tcp[tcpflags] & tcp-rst != 0)"
        log_note(f"Tshark Filter: Isolating TCP ACK/RST responses for {targets}.")
        log_note(f"Wireshark filter: {RESET}'(tcp.flags.ack == 1 or tcp.flags.reset == 1) and ip.addr == {targets}'")

    # Scan 03: Local ARP Discovery (Layer 2 MAC Discovery)
    elif choice == "03":
        # Capture Filter: ARP protocol only
        cap_filter = "arp"
        log_note("Tshark Filter: Isolating ARP requests and replies (Layer 2).")
        # Wireshark Display Filter: ARP Opcode 1 (Request) and Opcode 2 (Reply)
        log_note(f"Wireshark filter: {RESET}'arp.opcode in {{1, 2}}'")

    # Scan 04: Reverse DNS
    elif choice == "04":
        cap_filter = "port 53"
        log_note("Tshark Filter: Isolating DNS traffic (port 53).")
        log_note(f"Wireshark filter: {RESET}'dns.flags.response == 0' or 'dns.flags.response == 1'")
        log_note(f"Wireshark (RD - You Asked): {RESET}'dns.flags.recdesired == 1'")
        log_note(f"Wireshark (RA - Server Can): {RESET}'dns.flags.recursion_available == 1'")

    # Scan 05: ZOMBIE PCAP LOGIC
    elif choice in ["05", "61"]:
        # Extract the IP from the flags string "-sI <zombie_ip>:<port>"
        flags = scan_meta.get('flags', '')
        try:
            z_ip = flags.split("-sI ")[1].split(" ")[0].split(":")[0]
            cap_filter = f"host {z_ip}"
            log_note(f"Stealth PCAP Active: Filtering for Zombie ({z_ip})")
            log_note(f"Wireshark filter: {RESET}'ip.addr == {z_ip}'")
        except:
            log_warn("Could not parse Zombie IP for Tshark filter. Capturing all traffic.")
            cap_filter = ""

    # Scan 10: IPv6 Multicast (Standard icmp6)
    elif choice == "10":
        cap_filter = "icmp6"
        log_note("Tshark Filter: Isolating ICMPv6 Discovery (Ping & Neighbor).")
        log_note(f"Wireshark filter: {RESET}'icmpv6.type in {128, 129, 135, 136}'")

    # Scan 11: Neighbor Discovery Only (NS/NA)
    elif choice == "11":
        # icmp6[0] is the Type field in the ICMPv6 header
        cap_filter = "icmp6 and (icmp6[0] == 135 or icmp6[0] == 136)"
        log_note("Tshark Filter: Isolating Neighbor Solicitation/Advertisement (135/136).")
        log_note(f"Wireshark filter: {RESET}'icmpv6.type == 135 || icmp6.type == 136'")

    # Scan 12: SLAAC Discovery Only (RS/RA)
    elif choice == "12":
        cap_filter = "icmp6 and (icmp6[0] == 133 or icmp6[0] == 134)"
        log_note("Tshark Filter: Isolating Router Solicitation/Advertisement (133/134).")
        log_note(f"Wireshark filter: {RESET}'icmpv6.type == 133 || icmp6.type == 134'")

    # Scan 20: SCTP INIT Ping (IPv4/IPv6 + ICMP Fallback)
    elif choice in ["20", "21", "22"]:
        # 1. Capture SCTP (Protocol 132) OR ICMP (Protocol 1/58)
        # 2. Filter by the specific Target IP to stay surgical
        # Note: If 'targets' is a range (192.168.1.0/24), 'net' is used instead of 'host'
        ip_bpf = nmap_to_bpf(targets)

        # 2. Combine IP scope with Protocol requirements (SCTP/ICMP)
        cap_filter = f"({ip_bpf}) and (sctp or icmp or icmp6)"

        log_note(f"Tshark Filter: Isolating SCTP and ICMP feedback for {targets}.")
        # Wireshark Display Filter: Type 1 (INIT) and Type 2 (INIT-ACK)
        log_note(f"Wireshark filter: {RESET}'sctp.chunk_type in {{1, 2}}'")
        log_note(f"Wireshark filter: {RESET}'(sctp or icmp or icmpv6) and ip.addr == {targets}'")
        log_note("Best use is against External Face of FW or hunting Critical Infrastructure.")

    # Scan 30: Top 1K Discovery (Broad Scope)
    elif choice == "30":
        cap_filter = nmap_to_bpf(targets)
        log_note(f"Tshark Filter: Isolating broad discovery traffic for {targets}.")
        log_note(f"Wireshark filter: {RESET}'ip.addr == {targets}'")

    # Scan 31: Windows Discovery (TCP) Scan
    elif choice == "31":
        ip_bpf = nmap_to_bpf(targets)
        port_bpf = " or tcp port ".join(LINUX_PORTS)
        cap_filter = f"({ip_bpf}) and (tcp port {port_bpf})"
        log_note("Tshark Filter: Isolating Windows RPC/SMB/RDP traffic.")

    # Scan 32: Linux Discovery (TCP) Scan
    elif choice == "32": 
        ip_bpf = nmap_to_bpf(targets)
        port_bpf = " or tcp port ".join(LINUX_PORTS)
        cap_filter = f"({ip_bpf}) and (tcp port {port_bpf})"
        log_note("Tshark Filter: Isolating Core Linux traffic.")
        log_note(f"Wireshark filter: {RESET}'tcp.port in {{{','.join(MGMT_TCP)}}} || udp.port in {{{','.join(MGMT_UDP)}}}'")


    # Scan 33: Web Discovery Scan
    elif choice == "33": # Web
        ip_bpf = nmap_to_bpf(targets)
        port_bpf = " or tcp port ".join(WEB_PORTS)
        cap_filter = f"({ip_bpf}) and (tcp port {port_bpf})"
        log_note("Tshark Filter: Isolating HTTP/S traffic.")
        log_note(f"Wireshark filter: {RESET}'tcp.port in {{{','.join(WEB_PORTS)}}}'")

    # Scan 34: Mgmt Discovery (TCP & UDP) Scan
    elif choice == "34":
        # 1. Combine both registries into one list of strings and remove duplicates (set)
        ip_bpf = nmap_to_bpf(targets)
        tcp_str = " or ".join(MGMT_TCP)
        udp_str = " or ".join(MGMT_UDP)
        # Combine them into a single filter string
        cap_filter = f"({ip_bpf}) and ((tcp port {tcp_str}) or (udp port {udp_str}))"
        log_note(f"Tshark Filter: Isolating MGMT traffic ports.")
        log_note(f"Wireshark filter: {RESET}'tcp.port in {{{','.join(MGMT_TCP)}}} || udp.port in {{{','.join(MGMT_UDP)}}}'")

    # Scan 35: DB Discovery (TCP) Scan
    elif choice == "35":
        ip_bpf = nmap_to_bpf(targets)
        port_bpf = " or tcp port ".join(DB_TCP)
        cap_filter = f"({ip_bpf}) and (tcp port {port_bpf})"
        log_note("Tshark Filter: Isolating Database traffic.")

    # Scan 36: SCADA/ICS Discovery (TCP & UDP) Scan
    elif choice == "36":
        # Capture both TCP and UDP for SCADA safety
        ip_bpf = nmap_to_bpf(targets)
        # Join the lists with ' or '
        tcp_str = " or ".join(SCADA_TCP)
        udp_str = " or ".join(SCADA_UDP)
        # Combine them into a single filter string
        cap_filter = f"({ip_bpf}) and ((tcp port {tcp_str}) or (udp port {udp_str}))"
        log_note("Tshark Filter: Isolating SCADA/ICS traffic.")

    # Scan 50: Auto-Zombie Hunter (IPID Sequence Analysis)
    elif choice == "50":
        ip_bpf = nmap_to_bpf(targets)
        # Capture all IP traffic for these targets to analyze ID increments
        cap_filter = f"({ip_bpf}) and ip"

        log_note(f"Tshark Filter: Full IP Analysis for {targets} (Zombie Hunting)")
        # Wireshark filter to see the Identification field in the IP header
        log_note(f"Wireshark filter: {RESET}'tcp.flags.syn == 1 && (tcp.flags.ack ==1 || tcp.flags.reset == 1)'")

    # Build the command ONCE
    tshark_cmd = [
        "tshark", "-i", INTERFACE, 
        "-w", str(pcap_path),
        "-q"
    ]

    # Append the filter ONLY if it's not empty
    if cap_filter:
        tshark_cmd.extend(["-f", cap_filter])

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


def deploy_audit_loop(ctx, scan_meta, phase_num, choice):
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
                if (svc_dir / "SCADA_LOCK").exists():
                    log_warn(f"OPSEC ALERT: {svc_dir.name} is a FRAGILE SCADA service.")
                    override = log_question(f"Bypass lock and perform version audit on {ip}? (y/n):").lower()
                    if override != 'y':
                        log_note(f"Skipping audit for {svc_dir.name} on {ip} for safety.")
                        continue
                try:
                    parts = svc_dir.name.split("_")
                    port_id = parts if len(parts) >= 2 else "0"
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
        port_string = ",".join(sorted_ports)
        print(f"\n{BLUE}{BOLD}[Audit {index}/{len(hosts)}]{RESET} {CYAN}Target: {ip}{RESET}")
        log_note(f"Resuming Audit: Found {len(target_ports)} services from previous Phase 1 artifact. ({port_string})")

        # Setup Naming for this specific host
        file_base = f"phase{phase_num}_audit_{ctx.customer}_{ip.replace('.','-')}_{ctx.date_str}_{ctx.time_str}"
        pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"
        nmap_base = ctx.dirs['artifacts'] / file_base

        # --- SURGICAL BYPASS FOR SCAN 99 ---
        skip_nmap = False
        if choice == "99":
            print(f"\n{YELLOW}--- [ CUSTOM SCAN BYPASS ] ---{RESET}")
            log_note(f"Scan ID 99 (Custom) detected for {ip}.")
            ans = log_question("Skip deep Nmap audit (-sV) and move straight to Service Modules (SMB/NFS/SNMP)? (y/n):").lower()
            if ans == 'y':
                skip_nmap = True
                log_success("Nmap bypassed. Proceeding to Service Interrogation...")

        # Construct Commands (Filtered PCAP)
        tshark_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", f"host {ip}", "-q"]
        nmap_cmd = [
            "nmap", *scan_meta['flags'].split(),
            "-p", port_string,
            "--exclude", LOCAL_IPS,
            "-oA", str(nmap_base),
            "--reason", ip
        ]

        # Initialize to None to prevent NameError in finally block
        t_proc = None 

        # --- Execution Block ---
        try:
            # --- SURGICAL BYPASS FOR SCAN 99 ---
            skip_nmap = False
            if choice == "99":
                print(f"\n{YELLOW}--- [ CUSTOM SCAN BYPASS ] ---{RESET}")
                log_note(f"Scan ID 99 (Custom) detected for {ip}.")
                ans = log_question("Skip deep Nmap audit (-sV) and move straight to Service Modules? (y/n):").lower()
                if ans == 'y':
                    skip_nmap = True
                    log_success("Nmap bypassed. Proceeding to Service Interrogation...")

            print(f"{YELLOW}--------------------------------{RESET}\n")

            if not skip_nmap:
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

            # Post-Scan Analysis (Now handles both Nmap and Bypass scenarios)
            xml_file = nmap_base.with_suffix('.xml')   
            gnmap_file = nmap_base.with_suffix('.gnmap')

            # We enter the interrogation block if XML exists OR we are skipping Nmap
            if xml_file.exists() or skip_nmap:

                # These sub-blocks only run if an XML was actually generated
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

                # --- SMB/NETBIOS SURGICAL ENUMERATION ---
                has_smb = any(str(p) in target_ports for p in SMB_TCP_PORTS)
                has_netbios = any(str(p) in target_ports for p in SMB_UDP_PORTS)

                if has_smb or has_netbios:
                    log_success(f"SMB/NetBIOS fingerprint detected on {ip}")

                    # 1. Determine if we run Enum4Linux
                    do_enum = False
                    if GREEDY_MODE:
                        log_task(f"GREEDY MODE: Automating SMB Enumeration for {ip}")
                        do_enum = True
                    else:
                        ans = log_question(f"Launch Surgical SMB Enumeration (enum4linux) for {ip}? (y/n):").lower()
                        do_enum = (ans == 'y')

                    if do_enum:
                        # Run the Enumeration Module
                        run_enum4linux(ctx, ip, choice, INTERFACE)

                        # 2. Determine if we run SMBGET (Looting)
                        if GREEDY_MODE:
                            log_task(f"GREEDY MODE: Attempting Auto-Loot for {ip}...")
                            for share in AUTO_LOOT_SHARES:
                                run_smbget(ctx, ip, share)

                        else:
                            # Clean Manual Flow
                            ans_loot = log_question(f"Attempt recursive loot (smbget) for {ip}? (y/n):").lower()
                            if ans_loot == 'y':
                                share_to_loot = log_question("Enter Share Name (Default: IPC$):") or "IPC$"
                                run_smbget(ctx, ip, share_to_loot)
                            else:
                                log_warn("No share name provided. Skipping loot phase.")

                # --- NFS/RPC SURGICAL ENUMERATION ---
                has_nfs = any(str(p) in target_ports for p in NFS_TCP_PORTS)

                if has_nfs:
                    log_success(f"NFS/RPC fingerprint detected on {ip}")

                    do_nfs = False
                    if GREEDY_MODE:
                        log_task(f"GREEDY MODE: Automating NFS Enumeration for {ip}")
                        do_nfs = True
                    else:
                        ans_nfs = log_question(f"Launch Surgical NFS Enumeration (rpcinfo/showmount) for {ip}? (y/n):").lower()
                        do_nfs = (ans_nfs == 'y')

                    if do_nfs:
                        from modules.nfs_enum import run_nfs_enum
                        run_nfs_enum(ctx, ip, choice)

                # --- SNMP SURGICAL INTERROGATION ---
                has_snmp = any(str(p) in target_ports for p in MGMT_UDP if str(p) == "161")

                if has_snmp:
                    log_success(f"SNMP listener detected on {ip}")

                    do_snmp = False
                    if GREEDY_MODE:
                        log_task(f"GREEDY MODE: Automating SNMP Footprinting for {ip}")
                        do_snmp = True
                    else:
                        ans_snmp = log_question(f"Launch SNMP Footprinting (onesixtyone/snmp-check) for {ip}? (y/n):").lower()
                        do_snmp = (ans_snmp == 'y')

                    if do_snmp:
                        from modules.snmp_footprints import run_snmp_enum
                        run_snmp_enum(ctx, ip)

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
