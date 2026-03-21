#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module:  core/parser.py
Purpose: Tiered parsing for Nmap results. Attempts XML first for detail, 
         pivots to Grepable (.gnmap) if XML is corrupted or truncated.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from core.ui import (
    log_task, log_success, log_error, log_warn, 
    log_note, RESET, YELLOW, BLUE, GREEN, RED, BOLD
    )
from config import SCADA_TCP, SCADA_UDP 


def parse_results(xml_path, gnmap_path, ctx):
    print(f"\n{YELLOW}--- [ DATA PARSING PHASE ] ---{RESET}")

    # Initialize counters at this level
    final_success = False
    hosts = 0
    services = 0

    # Attempt Primary XML Parsing
    # Update: _parse_xml needs to return (success, host_count, svc_count)
    success, hosts, services = _parse_xml(xml_path, ctx)
    final_success = success

    if not success:
        log_warn("XML artifact corrupted. Pivoting to GNMAP fallback...")
        # Note: GNMAP has limited service data, so services will likely be 0
        success, hosts, services = _parse_gnmap(gnmap_path, ctx) 
        final_success = success

    if final_success:
        _deduplicate_all(ctx.dirs['targets'])
        print(f"{YELLOW}------------------------------{RESET}\n")

    return final_success, hosts, services


def _parse_xml(xml_file, ctx):
    """Detailed XML Parsing Logic with DNS Mapping support."""
    host_count = 0
    svc_count = 0
    try:
        log_task(f"Attempting XML Parse: {xml_file.name}")
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall('host'):
            # 1. Capture IP and Status
            status = host.find('status').get('state')
            ip = host.find('address').get('addr')

            # --- DNS HOSTNAME EXTRACTION ---
            # We do this BEFORE the 'up' check so we capture names from List Scans (-sL)
            hostnames_node = host.find('hostnames')
            if hostnames_node is not None:
                for hn in hostnames_node.findall('hostname'):
                    name = hn.get('name')
                    if name:
                        map_file = ctx.dirs['targets'] / "hosts_ip-dns_mappings.txt"
                        _append_dns_map(map_file, ip, name)

            if status == 'up' or "-6" in str(xml_file):
                host_count += 1
                addr_node = host.find('address')
                if addr_node is not None:
                    ip = addr_node.get('addr')
                    _append_target(ctx.dirs['targets'] / "hosts_all.txt", ip)

                # SINGLE PORT LOOP (Efficiency for Kitchen Sink)
                for p in host.findall('.//port'):
                    svc_count += 1
                    port_id_str = p.get('portid')
                    port_id_int = int(port_id_str)
                    proto = p.get('protocol', 'tcp')

                    svc = p.find('service')
                    svc_name = svc.get('name') if svc is not None else "unknown"

                    # Define the service directory
                    svc_dir = ctx.dirs['targets'] / f"{svc_name}_{port_id_str}_{proto}"
                    svc_dir.mkdir(exist_ok=True)
                    _append_target(svc_dir / "hosts_all.txt", ip)

                    # --- FRAGILE DEVICE ALERT ---
                    if port_id_int in SCADA_TCP or port_id_int in SCADA_UDP:
                        fragile_marker = svc_dir / f"!!!_FRAGILE_{ip.replace('.','-')}_!!!"
                        if not fragile_marker.exists():
                            with open(fragile_marker, "w") as f:
                                f.write(f"ALERT: {ip} port {port_id_int} is SCADA/ICS.")
                            # Terminal warning for the operator
                            log_warn(f"FRAGILE DEVICE: {ip} is running SCADA on {port_id_int}/{proto}!")

                # --- ZOMBIE CANDIDATE DETECTION ---
                seq_class = ""

                # Try Nmap Scripts (ipidseq)
                for script in host.findall('.//script'):
                    if script.get('id') == 'ipidseq':
                        seq_class = script.get('output', '').lower()

                # Try Native OS Engine Tag (ipidsequence)
                if not seq_class:
                    ipid_node = host.find('ipidsequence')
                    if ipid_node is not None:
                        seq_class = ipid_node.get('class', '').lower()

                # Final Deep Search: Grep the raw .nmap text if XML is "unsure"
                if not seq_class:
                    nmap_file = xml_file.with_suffix('.nmap')
                    if nmap_file.exists():
                        with open(nmap_file, 'r') as f:
                            # We look for the IPID line specifically in this host's block
                            content = f.read()
                            if ip in content:
                                match = re.search(r"IP ID Sequence Generation: ([\w\s-]+)", content)
                                if match:
                                    seq_class = match.group(1).lower()

                # --- Execute Alert & Looting ---
                if "incremental" in seq_class:
                    zombie_file = ctx.dirs['targets'] / "zombie_candidates.txt"
                    _append_target(zombie_file, f"{ip:<15} | {seq_class.strip()}")
                    log_success(f"ZOMBIE FOUND: {ip} is UP and PREDICTABLE ({seq_class.strip()}).")

        return True, host_count, svc_count
    except Exception as e:
        log_error(f"Parser Error: {e}")
        return False, 0, 0


def _parse_gnmap(gnmap_file, ctx):
    """Robust Grepable Fallback with host telemetry."""
    host_count = 0
    services = 0
    try:
        log_task(f"Executing GNMAP Fallback: {gnmap_file.name}")
        unique_ips = set()
        with open(gnmap_file, 'r') as f:
            for line in f:
                if "Status: Up" in line or "Ports:" in line:
                    ip_match = re.search(r'Host: ([\d\.]+) ', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in unique_ips:
                            _append_target(ctx.dirs['targets'] / "hosts_all.txt", ip)
                            unique_ips.add(ip)
                            host_count += 1
        # GNMAP doesn't make service counting easy, so we return 0 for svcs
        return True, host_count, 0
    except Exception as e:
        log_error(f"GNMAP Fallback also failed: {e}")
        return False, 0, 0


def _append_target(file_path, ip):
    """
    Safely adds an IP to a target file only if it doesn't already exist.
    """
    existing_ips = []
    if file_path.exists():
        with open(file_path, 'r') as f:
            existing_ips = [line.strip() for line in f]

    if ip not in existing_ips:
        with open(file_path, "a") as f:
            f.write(f"{ip}\n")


def _append_dns_map(file_path, ip, hostname):
    """Safely adds unique IP | Hostname pairs to the mapping file."""
    # Skip generic reverse-DNS noise
    if "in-addr.arpa" in hostname.lower():
        return

    entry = f"{ip:<20} | {hostname}"
    existing = []
    if file_path.exists():
        with open(file_path, 'r') as f:
            existing = [line.strip() for line in f]

    if entry not in existing:
        with open(file_path, "a") as f:
            f.write(f"{entry}\n")


def _deduplicate_all(target_root):
    """Ensures unique IPs in all generated host files."""
    for path in target_root.rglob("hosts_*.txt"):
        if path.is_file():
            with open(path, 'r') as f:
                unique = sorted(set(line.strip() for line in f if line.strip()))
            with open(path, 'w') as f:
                f.write("\n".join(unique) + "\n")


def get_host_telemetry(ctx, ip, host_node=None, gnmap_path=None):
    """
    Tiered Telemetry:
    1. Try XML (Detailed)
       > 2. Try GNMAP (Robust Fallback for TTL/Status)
          > 3. Final Fallback (TTL Guessing)
    """
    data = {"os": "Unknown", "kernel": "Unknown", "ttl": 0}

    # --- TRACK 1: XML Parsing (Preferred) ---
    if host_node is not None:
        try:
            status_node = host_node.find('status')
            if status_node is not None:
                data['ttl'] = int(status_node.get('reason_ttl', 0))

            os_match = host_node.find(".//osmatch")
            data['os'] = os_match.get('name') if os_match is not None else "Unknown"

            # Kernel discovery from service ostype
            for svc in host_node.findall(".//service"):
                ostype = svc.get('ostype', '')
                if ostype and "kernel" in ostype.lower():
                    data['kernel'] = ostype
                    break
        except Exception:
            pass # Move to Track 2

    # --- TRACK 2: GNMAP Regex Fallback (If XML failed or data is missing) ---
    if (data['os'] == "Unknown" or data['ttl'] == 0) and gnmap_path and gnmap_path.exists():
        try:
            with open(gnmap_path, 'r') as f:
                for line in f:
                    if f"Host: {ip}" in line:
                        ttl_match = re.search(r'reason_ttl: (\d+)', line)
                        if ttl_match:
                            data['ttl'] = int(ttl_match.group(1))
                        break
        except Exception as e:
            log_warn(f"GNMAP Telemetry extraction failed for {ip}: {e}")

    # --- TRACK 3: Logic-Based OS Guessing (Fallback) ---
    if "Unknown" in data['os'] and data['ttl'] > 0:
        ttl = data['ttl']
        if ttl <= 64:
            data['os'] = "Linux/IoT (TTL Guess)"
        elif 65 <= ttl <= 128:
            data['os'] = "Windows (TTL Guess)"
        else:
            data['os'] = "Network Device/Solaris (TTL Guess)"

    return data


def pre_flight_check(ctx):
    """
    Scans artifacts for a Phase 1 XML to rebuild the service map.
    Returns: (host_count, service_count)
    """
    print(f"\n{YELLOW}--- [ DATA PARSING PHASE ] ---{RESET}")
    log_task("Performing Pre-Flight artifact analysis...")

    # Find any XML file starting with 'phase1'
    xml_files = list(ctx.dirs['artifacts'].glob("phase1_*.xml"))

    if not xml_files:
        log_warn("No Phase 1 artifacts found for re-hydration.")
        print(f"{YELLOW}------------------------------{RESET}\n")
        return 0, 0

    # We use our existing _parse_xml logic to rebuild the targets/ folders
    # This ensures the 'targets/service_port/' directories exist for Phase 2
    success, hosts, svcs = _parse_xml(xml_files[0], ctx)

    if success:
        log_success(f"Pre-Flight Complete: Restored {hosts} hosts and {svcs} services to session.")
        print(f"{YELLOW}------------------------------{RESET}\n")
        return hosts, svcs
    return 0, 0


# --- IMPACT CHECK ---
# This ensures that even if the operator hits Ctrl+C mid-scan, 
# Phase 2 will still have a 'hosts_all.txt' to work with.
