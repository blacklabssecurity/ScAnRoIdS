# ==============================================================================
# SCRIPT: surgeon.py (REFACTORED BASELINE)
# PURPOSE: High-Performance Data Extraction and Dashboard Synchronization
# ==============================================================================

import os, re, subprocess, logging, time, threading
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import Counter
from registry import TACTICAL_SUGGESTIONS, JUICY_PORTS, DC_PORTS, WEB_PORTS

# --- 1. UTILITIES & HELPERS ---
BLUE, YELLOW, GREEN, RED, BOLD, RESET = "\033[94m", "\033[93m", "\033[92m", "\033[91m", "\033[1m", "\033[0m"

def safe_unpack(string, delimiter=' ', limit=2, default="Unknown"):
    """Prevents 'not enough values to unpack' by ensuring list length."""
    parts = string.split(delimiter, limit - 1)
    while len(parts) < limit:
        parts.append(default)
    return [p.strip() for p in parts]

def calculate_network_depth(ttl_str):
    """Unified TTL-based OS fingerprinting and hop calculation."""
    try:
        ttl = int(ttl_str)
        if ttl <= 0: return 0, "N/A"
        
        # Determine base OS and Max TTL
        if 129 <= ttl <= 255: hops, base = 255 - ttl, "Solaris/Cisco"
        elif 65 <= ttl <= 128: hops, base = 128 - ttl, "Windows"
        else: hops, base = 64 - ttl, "Linux/IoT"
        
        # Sanitize negative hops (protects against non-standard stacks)
        hops = max(0, hops)
        display = f"Local (TTL: {ttl})" if hops == 0 else f"{ttl} ({hops} Hops - {base})"
        return ttl, display
    except:
        return 0, "N/A"

# --- 2. SURGICAL SEARCHSPLOIT ---
def surgical_searchsploit_update(nmap_file, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data):
    """Cleans service strings and triggers prioritized exploit searches."""
    sploit_out = os.path.join(BASE_DIR, f"{CUSTOMER}_{DATE_STR}_exploits.txt")
    sploit_log = os.path.join(BASE_DIR, "logs", "searchsploit.log")
    os.makedirs(os.path.dirname(sploit_log), exist_ok=True)

    if not os.path.exists(nmap_file): return

    with open(nmap_file, 'r') as f:
        for line in f:
            if "open" in line and "/tcp" in line:
                # Safe Extraction using our helper
                parts = line.split()
                if len(parts) < 3: continue
                
                svc_name = parts[2]
                raw_version = " ".join(parts[3:])
                
                # Cleanup: Strip TTL/Reason noise for searchsploit
                clean_v = re.sub(r'\b(syn-ack|ttl|64|128|255)\b', '', raw_version).strip()
                query = f"{svc_name} {clean_v.split(' (')[0]}".strip()

                if len(query) > 4:
                    with open(sploit_out, "a") as out_f:
                        out_f.write(f"\n{'='*60}\n[ TARGET: {os.path.basename(nmap_file)} | QUERY: {query} ]\n{'='*60}\n")
                    
                    print(f"{BLUE}[*]{RESET} Searching Exploits: {query}")
                    subprocess.run(f"searchsploit '{query}' --disable-colour >> '{sploit_out}'", shell=True)
    
    dashboard_data['exploits_found'] = os.path.exists(sploit_out) and os.path.getsize(sploit_out) > 500

# --- 3. THE MASTER XML PARSER (HIGH-SPEED) ---
def parse_and_sync_results(xml_file, dashboard_data, BASE_DIR):
    """High-speed O(1) sync logic. Replaces O(n) list searches."""
    if not os.path.exists(xml_file) or os.path.getsize(xml_file) == 0: return

    try:
        # Step 1: Sanitization (In-Memory to prevent corruption)
        with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        if "</nmaprun>" not in content: content += "\n</nmaprun>"
        
        root = ET.fromstring(content)
        
        # Use a dictionary for instant lookups: key = "IP:PORT"
        results_map = {f"{e['host']}:{e['port']}": e for e in dashboard_data.get('results', [])}
        
        # Buffered logging to avoid disk bottleneck
        host_logs = {"all": set(), "windows": set(), "linux": set(), "OS-unknown": set()}

        for host in root.findall('host'):
            ip = host.find("address[@addrtype='ipv4']").get('addr')
            vendor = host.find("address[@addrtype='mac']").get('vendor', '') if host.find("address[@addrtype='mac']") is not None else ""
            
            # OS & TTL Logic
            os_match = host.find("os/osmatch")
            os_name = os_match.get('name', 'Unknown') if os_match is not None else 'Unknown'
            raw_ttl = host.find("status").get('reason_ttl', '0')
            ttl_num, ttl_text = calculate_network_depth(raw_ttl)

            # Buffered File Logging (O(1) logic)
            host_logs["all"].add(ip)
            sfx = "windows" if "windows" in os_name.lower() else ("linux" if "linux" in os_name.lower() else "OS-unknown")
            host_logs[sfx].add(ip)

            ports = host.findall(".//port")
            for p in ports:
                if p.find('state').get('state') == 'open':
                    pid = p.get('portid')
                    svc_node = p.find('service')
                    svc_name = svc_node.get('name', 'unknown') if svc_node is not None else 'unknown'
                    
                    key = f"{ip}:{pid}"
                    suggestion = TACTICAL_SUGGESTIONS.get(int(pid), "Standard audit.")
                    
                    # Update or Create Entry
                    results_map[key] = {
                        "host": ip, "os": os_name, "port": pid, "service": svc_name,
                        "reason": p.find('state').get('reason', 'syn-ack'),
                        "raw_ttl": ttl_num, "ttl_display": ttl_text,
                        "suggestion": f"nmap {suggestion} {ip}" if "nmap" not in suggestion else suggestion,
                        "css_class": "interesting" if int(pid) in JUICY_PORTS else ("dc-pulse" if int(pid) in DC_PORTS else "")
                    }

        # Step 4: Write Buffers to Disk (Instant completion)
        for sfx, ips in host_logs.items():
            h_path = os.path.join(BASE_DIR, f"hosts_{sfx}.txt")
            with open(h_path, "a") as f:
                for ip in ips: f.write(f"{ip}\n")

        # Convert dictionary back to list for the Dashboard
        dashboard_data['results'] = list(results_map.values())
        dashboard_data['host_count'] = len(set(e['host'] for e in results_map.values()))

    except Exception as e:
        print(f"{RED}[!] XML Sync Error:{RESET} {e}")
