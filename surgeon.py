# ==============================================================================
# SCRIPT: surgeon.py
# PURPOSE: Data Extraction, Normalization, and Artifact Management
# FUNCTIONALITY: 
#   - Parses Nmap XML/GNMAP data into the dashboard_data results dictionary.
#   - Performs 'Surgical' version cleaning and TTL-based OS finger-printing.
#   - Triggers background external tools (SearchSploit, Gowitness, SMB Enum).
#   - Dynamically creates service-specific artifacts (e.g., ./ssh_22/hosts_all.txt).
#   - Sanitizes corrupted XML files to prevent parser crashes on partial scans.
# ==============================================================================


import os, re, subprocess, logging, time, threading
import xml.etree.ElementTree as ET
#from surgeon import calculate_network_depth
from datetime import datetime
from registry import TACTICAL_SUGGESTIONS, JUICY_PORTS, DC_PORTS, WEB_PORTS
from collections import Counter


# --- 1. ADD ANSI COLORS TO THE TOP ---
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def calculate_network_depth(ttl_str):
    """Returns (raw_ttl, analyzed_string) for dashboard display."""
    try:
        ttl = int(ttl_str)
        if ttl <= 0: return 0, "N/A"

        if 129 <= ttl <= 255:
            hops = 255 - ttl
            base = "Solaris/Cisco"
        elif 65 <= ttl <= 128:
            hops = 128 - ttl
            base = "Windows"
        else:
            hops = 64 - ttl
            base = "Linux/IoT"

        display = f"Local: ttl Value of {ttl}" if hops == 0 else f"{ttl} ({hops} Hops - {base})"
        return ttl, display
    except:
        return 0, "N/A"


def get_top_cves(sploit_file):
    if not os.path.exists(sploit_file) or os.path.getsize(sploit_file) < 10:
        return [] 
    try:
        with open(sploit_file, 'r', errors='ignore') as f:
            content = f.read()

        # 1. Regex to catch both CVEs AND Exploit-DB IDs
        # This turns [1.1] EDB-ID 45233 into a clickable finding
        findings = re.findall(r'(CVE-\d{4}-\d{4,7}|EDB-ID \d{5})', content)

        if not findings: 
            return []

        # 2. Return the top 3 (Could be a mix of CVEs and EDB-IDs)
        return Counter(findings).most_common(3)
    except:
        return []


def surgical_searchsploit_update(nmap_file, xml_file, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data):
    """Combines version-based searches with the critical Kernel check."""

    # 1. Setup Paths (Reused from your logic)
    sploit_out = os.path.join(BASE_DIR, f"{CUSTOMER}_{DATE_STR}_exploits.txt")
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    sploit_log = os.path.join(BASE_DIR, "logs", "searchsploit.log")

    # Prepare the dashboard reference
    if not dashboard_data.get('exploits_found'):
        dashboard_data['exploits_found'] = False

    # Kernel/OS Check
    # We check the discovery XML for Kernel exploits while we're here
    discovery_xml = xml_file # Use the actual path passed from the main script
    if os.path.exists(discovery_xml):
        try:
            tree = ET.parse(discovery_xml)
            for host in tree.getroot().findall('host'):
                os_match = host.find("os/osmatch")
                os_name = os_match.get('name', 'Unknown') if os_match is not None else 'Unknown'
                if "linux" in os_name.lower() and "unknown" not in os_name.lower():
                    # Your specific Kernel logic (Line 354)
                    kernel_query = os_name.split(' (')[0].replace("Linux ", "Linux Kernel ")
                    subprocess.run(f"searchsploit '{kernel_query}' --disable-colour >> '{sploit_out}'", shell=True)
        except: pass

    # Surgical Service Search
    if os.path.exists(nmap_file):
        with open(nmap_file, 'r') as f:
            for line in f:
                # 1. Surgical Extraction: Locate the 'open' state and service name
                if "open" in line and "/tcp" in line:
                    parts = line.split()
                    # parts[2] is service name, parts[3:] is the version info
                    svc_name = parts[2]

                    # 2. Clean 'syn-ack' and 'ttl' noise to reveal the version number
                    # This turns "syn-ack ttl 64 Apache httpd 2.4.29" into "Apache httpd 2.4.29"
                    raw_version = " ".join(parts[3:]).replace("syn-ack", "").replace("ttl", "").strip()
                    # Remove common TTL numbers (64, 128, 255) to prevent "blind" searches
                    raw_version = re.sub(r'\b(64|128|255)\b', '', raw_version).strip()

                    # 3. BUILD SURGICAL QUERY
                    # Remove the service name if it's already at the start of raw_version
                    # This turns "ssh OpenSSH 7.6p1" into "OpenSSH 7.6p1"
                    query_clean = raw_version.replace(svc_name, "").strip()

                    # Split and remove OS/Distro noise (e.g., Ubuntu, Debian, etc.)
                    # We only want the first 2-3 parts (Software + Version)
                    v_parts = query_clean.split(' (')[0].split()

                    if len(v_parts) >= 2:
                        # If it's a web service, keep 3 words, otherwise keep 2
                        limit = 3 if "http" in svc_name else 2
                        # FIX: Join the list into a single space-separated string
                        version_str = " ".join(v_parts[:limit]).strip()
                    else:
                        # Fallback to Software + Version if parsing is thin
                        version_str = f"{svc_name} {query_clean.split(' (')[0]}".strip()

                    # 4. Final Quality Check & Search
                    if len(version_str) > 4 and "syn-ack" not in version_str:
                        # Add a Header so you know which host owns these exploits
                        with open(sploit_out, "a") as out_f:
                            out_f.write(f"\n\n{'='*60}\n[ TARGET: {os.path.basename(nmap_file)} | SERVICE: {version_str} ]\n{'='*60}\n")

                        print(f"{BLUE}[*]{RESET} Surgical Sploit Search: {version_str}")
                        with open(sploit_log, "a") as log_f:
                            subprocess.run(f"searchsploit '{version_str}' --disable-colour >> '{sploit_out}'", shell=True, stderr=log_f)

    # 5. Update Dashboard Toggle
    if os.path.exists(sploit_out) and os.path.getsize(sploit_out) > 500:
        # Trigger the UI to show the 'View Exploits' button
        dashboard_data['exploits_found'] = True
        # Store the relative filename so the /artifacts/ route can serve it
        dashboard_data['sploit_file'] = os.path.basename(sploit_out)
        print(f"{GREEN}[+]{RESET} Exploits logged: {dashboard_data['sploit_file']}")


def parse_gnmap_version_update(gnmap_file, dashboard_data):
    """Surgically extracts versions and TTLs from GNMAP and updates the UI."""
    if not os.path.exists(gnmap_file): return

    # 1. Identify the host from the filename (e.g., audit_192.168.1.1.gnmap)
    ip_from_file = os.path.basename(gnmap_file).replace("audit_", "").replace(".gnmap", "")

    with open(gnmap_file, 'r') as f:
        for line in f:
            if "Ports:" not in line: continue

            # 2. Extract global TTL for this host (Regex for 'Ignored' or 'Status' lines)
            ttl_match = re.search(r"(?i)ttl\s*[:=]?\s*(\d+)", line)
            raw_ttl = int(ttl_match.group(1)) if ttl_match else 0

            # 3. Split the 'Ports: ' section
            parts = line.split("Ports: ")
            port_sections = parts[1].split(", ")

            for section in port_sections:
                data = section.split("/")
                if len(data) >= 7 and "open" in data[1]:
                    port = data[0].strip()
                    svc = data[4].strip()
                    ver = data[6].strip()

                    # --- ARTIFACT FOLDER GENERATION (All Hosts / Particular Service: ssh_22/hosts_all.txt) ---
                    try:
                        # We take ONLY the first word (e.g., 'ssh') and remove illegal characters
                        # This prevents "ssh OpenSSH 9.6p1..." from breaking the URL
                        clean_svc = re.sub(r'[^a-zA-Z0-9]', '_', svc.split()[0])
                        folder_name = f"{clean_svc}_{port}"
                        # BASE_DIR is accessible here if passed to the function
                        artifact_folder = os.path.join(dashboard_data.get('base_dir_ref'), folder_name)
                        os.makedirs(artifact_folder, exist_ok=True)

                        # Append the current IP to the hosts_all.txt in that specific service folder
                        with open(os.path.join(artifact_folder, "hosts_all.txt"), "a") as af:
                            af.write(f"{ip_from_file}\n")
                    except Exception as e:
                        print(f"{RED}[!] Artifact Error:{RESET} {e}")

                    # Combine Service + Version (e.g., "http Apache httpd 2.4.29")
                    display_val = f"{svc} {ver}".strip()

                    # 4. Update the Dashboard Global Reference
                    for entry in dashboard_data['results']:
                        if entry['host'] == ip_from_file and str(entry['port']) == port:
                            # UPDATE SERVICE WITHOUT WIPING OS
                            entry['service'] = display_val
                            # 2. Re-apply the Artifact Link so it doesn't disappear
                            entry['clean_svc_port'] = folder_name
                            # 3. Ensure the CSS class persists
                            if not entry.get('css_class'):
                                # Priority 1: Domain Controller Detection
                                if int(port) in [88, 389, 636, 3268]:
                                    entry['css_class'] = "dc-pulse"
                                    entry['os'] = f"{entry.get('os', 'Unknown')} (DC)"
                                    dashboard_data['dc_found'] = True
                                # Priority 2: Juicy/Interesting Ports
                                elif int(port) in JUICY_PORTS:
                                    entry['css_class'] = "interesting"
                                else:
                                    entry['css_class'] = ""

                            # 1. Update the record with the TTL found in this GNMAP line
                            if raw_ttl > 0:
                                entry['raw_ttl'] = raw_ttl
                                # Use your helper to get the "Hop" display (e.g. 64 (0 Hops))
                                # Assuming calculate_network_depth returns (int, str)
                                r_num, d_text = calculate_network_depth(raw_ttl)
                                entry['ttl_display'] = d_text

                            # 2. Re-apply the OS Guess if it's currently Unknown
                            if "Unknown" in entry.get('os', 'Unknown') and entry['raw_ttl'] > 0:
                                r_num = entry['raw_ttl']
                                if r_num <= 64: 
                                    entry['os'] = "Linux/IoT (TTL Guess)"
                                elif 65 <= r_num <= 128: 
                                    entry['os'] = "Windows (TTL Guess)"
                                elif r_num > 128:
                                    entry['os'] = "Network Device/Solaris (TTL Guess)"

                            # If the OS is currently Unknown, try to re-apply the guestimate
                            if entry.get('os') == "Unknown" and entry.get('raw_ttl', 0) > 0:
                             # This re-triggers the TTL -> OS logic from Phase 1
                                r_num, d_text = calculate_network_depth(entry['raw_ttl'])
                                if r_num <= 64: entry['os'] = "Linux/IoT (TTL Guess)"
                                elif 65 <= r_num <= 128: entry['os'] = "Windows (TTL Guess)"


                            # --- PERSISTENT TTL ---
                            # Only update TTL if Phase 2 found a NEW one; otherwise, keep Phase 1's value
                            if raw_ttl:
                                raw_num, display_text = calculate_network_depth(raw_ttl)
                                entry['raw_ttl'] = raw_num
                                entry['ttl_display'] = display_text


def parse_and_sync_results(xml_file, dashboard_data, BASE_DIR, choice):
    """Surgically cleans and synchronizes Nmap XML with the live dashboard."""
    if not os.path.exists(xml_file) or os.path.getsize(xml_file) == 0:
        return

    try:
        # --- STEP 1: XML SANITIZATION ---
        with open(xml_file, 'r', encoding='utf-8-sig', errors='ignore') as f:
            content = f.read()

        if "</nmaprun>" in content:
            content = content.split("</nmaprun>")[0].strip() + "\n</nmaprun>"

        # Clean task noise and extraports to prevent parser bloat
        content = re.sub(r'<task(begin|progress|status|end)[^>]*/>', '', content)
        content = re.sub(r'<extraports[^>]*>.*?</extraports>', '', content, flags=re.DOTALL)

        with open(xml_file, 'w', encoding='utf-8') as f:
            f.write(content)

        # --- STEP 2: DATA EXTRACTION ---
        tree = ET.parse(xml_file)
        root = tree.getroot()
        temp_entries = []

        for host in root.findall('host'):
            addr_node = host.find("address[@addrtype='ipv4']")
            if addr_node is None: continue
            ip = addr_node.get('addr')

            # --- MAC VENDOR HIGHLIGHTER ---
            mac_node = host.find("address[@addrtype='mac']")
            vendor = mac_node.get('vendor', '') if mac_node is not None else ''
            # Flag Raspberry Pi or VMware in Green for quick ID
            mac_css = "interesting" if any(x in vendor.lower() for x in ["raspberry", "vmware"]) else ""

            # --- OS FINGERPRINTING ---
            os_match = host.find("os/osmatch")
            os_name = os_match.get('name', 'Unknown') if os_match is not None else 'Unknown'

            # --- TTL ANALYSIS ---
            status_node = host.find("status")
            raw_val = status_node.get('reason_ttl', '0') if status_node is not None else '0'
            raw_num, analyzed_text = calculate_network_depth(raw_val)

            # --- TTL GUESTIMATE (If Nmap is unsure) ---
            if os_name == "Unknown" and raw_num > 0:
                if 65 <= raw_num <= 128: os_name = "Windows (TTL Guess)"
                elif raw_num <= 64: os_name = f"Linux/IoT ({vendor})" if vendor else "Linux/IoT (TTL Guess)"
                elif raw_num > 128: os_name = "Cisco/Network (TTL Guess)"

            # --- GATE 1: FILE LOGGING ---
            suffix = "windows" if "windows" in os_name.lower() else ("linux" if any(x in os_name.lower() for x in ["linux", "iot"]) else "OS-unknown")
            for sfx in ["all", suffix]:
                h_file = os.path.join(BASE_DIR, f"hosts_{sfx}.txt")
                if not os.path.exists(h_file): open(h_file, 'w').close()
                with open(h_file, "a+") as f:
                    f.seek(0)
                    if ip not in f.read(): f.write(f"{ip}\n")

#           # -- TTL Organization ---
#           entry['os'] = os_name
#           entry['raw_ttl'] = raw_num
#           # Ensure calculate_network_depth is called correctly
#           entry['ttl_display'] = calculate_network_depth(raw_num)[1]

            # --- GATE 2: DASHBOARD DEDUPLICATION ---
            ports = host.findall(".//port")

            if not ports:
                # Add Discovery row only if this IP isn't already listed
                if not any(e['host'] == ip for e in temp_entries):
                    temp_entries.append({
                        "host": ip, "os": os_name, "port": "N/A", "service": f"Discovery ({vendor})" if vendor else "Discovery",
                        "reason": status_node.get('reason', 'N/A') if status_node is not None else 'N/A',
                        "raw_ttl": raw_num, "ttl_display": analyzed_text, "css_class": mac_css
                    })
            else:
                # Remove "Discovery Only" placeholders if real ports are now found
                temp_entries = [e for e in temp_entries if not (e['host'] == ip and e['port'] == "N/A")]

                for p in ports:
                    state_node = p.find('state')
                    if state_node is not None and state_node.get('state') == 'open':
                        pid = int(p.get('portid'))
                        svc = p.find('service').get('name', 'unknown') if p.find('service') is not None else 'unknown'

                        # Apply Tactical Suggestions
                        suggestion = TACTICAL_SUGGESTIONS.get(pid, "Standard service audit recommended.")
                        full_suggest = f"nmap {suggestion} {ip}" if pid in TACTICAL_SUGGESTIONS else suggestion

                        temp_entries.append({
                            "host": ip, "os": os_name, "port": pid, "service": svc,
                            "reason": state_node.get('reason', 'syn-ack'),
                            "raw_ttl": raw_num, "ttl_display": analyzed_text,
                            "suggestion": full_suggest,
                            "css_class": "interesting" if pid in JUICY_PORTS else ("dc" if pid in DC_PORTS else mac_css)
                        })

        # --- STEP 3: GLOBAL STATE UPDATES ---
        unique_ips = set(e['host'] for e in temp_entries)
        service_rows = [e for e in temp_entries if e['port'] != "N/A"]

        dashboard_data['results'] = temp_entries
        dashboard_data['host_count'] = len(unique_ips)
        dashboard_data['service_count'] = len(service_rows)

        # Calculate Juicy Target (Most open ports)
        if service_rows:
            counts = Counter([e['host'] for e in service_rows])
            top = counts.most_common(1)[0]
            dashboard_data['juicy_target'] = f"{top[0]} ({top[1]} Ports)"

        # --- IDS/IPS DETECTION LOGIC ---
        ips_blocked = any(e['reason'] == 'admin-prohibited' for e in temp_entries)
        dashboard_data['ips_blocked'] = ips_blocked

        # --- DC IDENTIFICATION LOGIC (MULTIPLE SUPPORT) ---
        dc_list = []

        for target_ip in unique_ips:
            host_ports = [e['port'] for e in temp_entries if e['host'] == target_ip]
            # Check for Kerberos, LDAP, and SMB
            if all(p in host_ports for p in [88, 389, 445]):
                dc_list.append(target_ip)

        # Update global state
        dashboard_data['dc_found'] = len(dc_list) > 0
        if len(dc_list) > 1:
            dashboard_data['dc_display'] = f"{len(dc_list)} DCs IDENTIFIED"
        elif len(dc_list) == 1:
            dashboard_data['dc_display'] = f"DC IDENTIFIED: {dc_list[0]}"
        else:
            dashboard_data['dc_display'] = ""

        # Push final counts to dashboard
        dashboard_data['results'] = temp_entries
        dashboard_data['host_count'] = len(unique_ips)
        dashboard_data['service_count'] = len(service_rows)

    except Exception as e:
        logging.error(f"Sync Failure: {e}")


# --- GOWITNESS SERVER ENGINE ---
def start_gowitness_report(db_uri):
    """Starts the Gowitness v3 UI on port 8889."""
    # Extract the directory from the URI to find where to put the logs
    target_dir = os.path.dirname(db_uri.replace("sqlite:///", ""))

    # Ensure the logs directory exists inside the customer folder
    log_dir = os.path.join(target_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    server_log = os.path.join(log_dir, "gowitness_server.log")

    report_cmd = f"gowitness report server --host 0.0.0.0 --port 8889 --db-uri '{db_uri}'"

    with open(server_log, "a") as log_file:
        subprocess.Popen(report_cmd, shell=True, stdout=log_file, stderr=log_file, cwd=target_dir)


# --- EXTERNAL TOOLS ---
def trigger_external_tools(xml_file, choice, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs):
    import xml.etree.ElementTree as ET

    # Exit early if this was a discovery-only scan
    if dashboard_data.get('service_count', 0) == 0:
        print(f"{YELLOW}[*]{RESET} No open ports discovered. Skipping Gowitness and SMB Enumeration.")
        return

    """Helper to run SearchSploit and Gowitness on the clean XML file."""
    # --- GOWITNESS LOGIC ---
    web_targets_found = False
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for port in root.findall(".//port"):
            if port.find('state').get('state') == 'open' and port.get('portid') in WEB_PORTS:
                web_targets_found = True
                break
    except Exception as e:
        print(f"{RED}[!] WARNING:{REST} XML check for web ports failed: {e}")

    if web_targets_found:
        # 1. Define and Create Absolute Paths
        # Note: Use 'screenshots' instead of 'web_snapshots' for v3 compatibility
        snap_dir = os.path.abspath(os.path.join(BASE_DIR, "screenshots"))
        db_file = os.path.abspath(os.path.join(BASE_DIR, "gowitness.sqlite3"))
        db_uri = f"sqlite:///{db_file}"

        os.makedirs(snap_dir, exist_ok=True)

        # 2. Build the Command (MATCHING THE VARIABLE NAMES)
        abs_xml = os.path.abspath(xml_file)

        # Ensure we use 'snap_dir' here since that is what we defined above
        gowitness_cmd = (f"gowitness scan nmap -f '{abs_xml}' "f"-s '{snap_dir}' --write-db --write-db-uri '{db_uri}' --threads 4")

        print(f"{BLUE}[*]{RESET} Launching Gowitness: {gowitness_cmd}")

        # 3. Execution and Logging
        os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
        scan_log = os.path.join(BASE_DIR, "logs", "gowitness_scan.log")

        def run_gowitness(cmd, log_path, db_uri):
            # 1. Run the actual scan (Blocks until screenshots are done)
            with open(log_path, "w") as f:
                subprocess.run(cmd, shell=True, stdout=f, stderr=f)

            # 2. TRIGGER THE SERVER (The missing link!)
            print(f"{GREEN}[+]{RESET} Gowitness Scan Complete. Starting Report Server...")
            start_gowitness_report(db_uri)

        # 4. Start the background thread
        threading.Thread(target=run_gowitness, args=(gowitness_cmd, scan_log, db_uri), daemon=True).start()

        dashboard_data['visual_recon_live'] = True
        print(f"{GREEN}[+]{RESET} Dashboard updated: Gowitness Gallery link is now LIVE.")
    else:
        dashboard_data['visual_recon_live'] = False
        print(f"{YELLOW}[*]{RESET} No web services found. Gowitness skipped.")

    # --- SMB ENUMERATION LOGIC ---
    if choice in ["08", "09", "11", "12", "13", "15", "17", "99"]:
        print(f"{BLUE}[*]{RESET} Service found on potentially vulnerable scan type. Triggering SMB Enum...")
        # We wrap this in a thread so it doesn't block SearchSploit or Phase 2
        threading.Thread(target=trigger_smb_enumeration, daemon=True).start()
