#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  core/parser.py
Purpose: Tiered parsing for Nmap results. Attempts XML first for detail, 
         pivots to Grepable (.gnmap) if XML is corrupted or truncated.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from core.ui import log_task, log_success, log_error, log_warn, log_note, RESET, YELLOW, BLUE, GREEN, RED, BOLD


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
        success, hosts = _parse_gnmap(gnmap_path, ctx)
        services = 0 
        final_success = success

    if final_success:
        _deduplicate_all(ctx.dirs['targets'])
        print(f"{YELLOW}------------------------------{RESET}\n")

    return final_success, hosts, services


def _parse_xml(xml_file, ctx):
    """Detailed XML Parsing Logic with telemetry counts."""
    host_count = 0
    svc_count = 0
    try:
        log_task(f"Attempting XML Parse: {xml_file.name}")
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall('host'):
            status = host.find('status').get('state')
            if status == 'up':
                host_count += 1
                ip = host.find('address').get('addr')
                _append_target(ctx.dirs['targets'] / "hosts_all.txt", ip)

                # Port/Service Categorization
                for p in host.findall('.//port'):
                    svc_count += 1 # Increment for every open port found
                    port_id = p.get('portid')
                    svc = p.find('service')
                    svc_name = svc.get('name') if svc is not None else "unknown"

                    svc_dir = ctx.dirs['targets'] / f"{svc_name}_{port_id}"
                    svc_dir.mkdir(exist_ok=True)
                    _append_target(svc_dir / "hosts_all.txt", ip)

        return True, host_count, svc_count
    except Exception:
        return False, 0, 0

def _parse_gnmap(gnmap_file, ctx):
    """Robust Grepable Fallback with host telemetry."""
    host_count = 0
    try:
        log_task(f"Executing GNMAP Fallback: {gnmap_file.name}")
        with open(gnmap_file, 'r') as f:
            for line in f:
                if "Status: Up" in line:
                    host_count += 1
                    ip_match = re.search(r'Host: ([\d\.]+) ', line)
                    if ip_match:
                        _append_target(ctx.dirs['targets'] / "hosts_all.txt", ip_match.group(1))
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
