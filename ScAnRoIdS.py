#!/usr/bin/env python3

# ==============================================================================
# SCRIPT: ScAnRoIdS.py
# PURPOSE: Main Entry Point & User Interface Orchestrator
# FUNCTIONALITY: 
#   - Enforces root privileges and captures environment (SUDO_USER, Local IPs).
#   - Initializes the Global State (dashboard_data) and Threading Locks.
#   - Manages the Interactive Terminal Menu for 20+ scan types.
#   - Initializes the Flask Web Server (Blueprints) and background scan threads.
#   - Handles clean signal exits (Ctrl+C) and provides Session Summaries.
# ==============================================================================

# --- IMPORTS ---
import os, time, sys, logging, subprocess, threading, getpass, re, xml.etree.ElementTree as ET, signal
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from engine import run_scan
from surgeon import parse_and_sync_results, trigger_external_tools, surgical_searchsploit_update, parse_gnmap_version_update, get_top_cves
from datetime import datetime
from registry import scans, TACTICAL_SUGGESTIONS
from flask_login import LoginManager, UserMixin, login_user, login_required
from collections import Counter
from werkzeug.utils import secure_filename
from logging.handlers import RotatingFileHandler


# --- ANSI COLORS ---
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --- SESSION TIMING ---
START_SESSION_TIME = datetime.now()

# --- ROOT ENFORCEMENT ---
if os.geteuid() != 0:
    print(f"\n{RED}[!] ERROR:{RESET} ScAnRoIdS must be run with root privileges.\n")
    print(f"{YELLOW}[*] Usage:{RESET} sudo (.venv_Location)/python3 ScAnRoIdS.py\n")
    sys.exit(1)


# --- Clear the terminal ---
os.system('clear')


#Supports the building of the local IPs to add the exclude flag in the scan
def get_local_ips():
    try:
        # Pulls all active interface IPs (eth0, wlan0, tun0, etc.)
        output = subprocess.check_output("hostname -I", shell=True, text=True)
        return ",".join(output.strip().split())
    except:
        return ""

LOCAL_IPS = get_local_ips()


# --- Pulls primary interface ---
def get_default_interface():
    try:
        cmd = "ip route get 8.8.8.8 | grep -Po '(?<=dev )\\S+'"
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except:
        return "eth0"

DEFAULT_IFACE = get_default_interface()

# Allows display of proper user running script, not root from the sudo cmd
CURRENT_USER = os.environ.get('SUDO_USER', getpass.getuser())


# --- BANNER CREATION ---
BANNER = r"""

                 _____________________________________________

        _________         _____        __________       .___    .____________
       /   _____/ ____   /  _  \   ____\______   \ ____ |   | __| _/   _____/
       \_____  \_/ ___\ /  /_\  \ /    \|       _//  _ \|   |/ __ |\_____  \
       /        \  \___/    |    \   |  \    |   (  <_> )   / /_/ |/        \
      /_______  /\___  >____|__  /___|  /____|_  /\____/|___\____ /_______  /
              \/     \/        \/     \/       \/                \/       \/

                 >> -- S - c - A - n - R - o - I - d - S -- <<

                 _____________________________________________

"""

# Print the Banner in Cyan/Green hacker style
print(f"{BLUE}" + BANNER + "\n")

# --- INITIAL SETUP ---
CUSTOMER = input(f"{YELLOW}[?]{RESET} Enter Customer Name (no spaces): ")
DATE_STR = datetime.now().strftime("%d%b%Y").upper()
YEAR_STR = datetime.now().strftime("%Y")

print(f"{BLUE}[*] Operator:{RESET} {CURRENT_USER}")
print(f"{BLUE}[*] Target Exclusion:{RESET} {LOCAL_IPS if LOCAL_IPS else 'None'}")
print(f"{BLUE}={RESET}"*90)

BASE_DIR = f"{CUSTOMER}_{DATE_STR}"
os.makedirs(BASE_DIR, exist_ok=True)

# --- MENU AND USER INPUT ---
MENU = f"""
========================== - S - c - A - n - R - o - I - d - S - ==========================

[ DISCOVERY - NETWORK LAYER - HOSTS List Building Only ]
01. Aggressive Discovery ...[N]: SYN/ACK/UDP/ICMP Egress Techniques
02. ACK Discovery ..........[S]: TCP ACK Ping (Stateless Firewall Check)
03. Local ARP Discovery ....[S]: Layer 2 MAC Discovery (Local Subnet)
04. Reverse DNS Lookup .....[S]: Query Hostnames via Specific DNS Server
05. Zombie Idle Scan .......[S]: Blind Stealth Scan (Requires Zombie IP)

[ IPv6 Discovery - HOSTS List Building Only ]
06. IPv6 Link-Local ........[N]: Multicast Ping ff02::1 (Iface: {DEFAULT_IFACE})
07. Neighbor Solicitation ..[S]: IP Neighbor Cache Dump

[ PORT SCANNING & AUDITS - HOSTS Building -or- Supply HOSTS from earlier scans ]
08. Anti-Throttling ........[S]: Slow & Steady (T2) with Randomized Targets
09. Windows ................[P]: RPC, SMB, RDP
10. Linux ..................[P]: SSH, RPC, Web Mgmt
11. Aggressive 1k ..........[N]: Top 1000 w/ Versioning & Vuln Scripts
12. Kitchen Sink ...........[N]: All Ports -p- (Phase 2: Surgical Scripts)
13. General Discovery ......[P]: Standard Top Services
14. Web Discovery ..........[P]: HTTP/S Title, Headers, Methods, Enum
15. MGMT Ports .............[N]: SSH, Telnet, Web, VNC, SNMP, IPMI
16. Database Discovery .....[P]: MSSQL, Oracle, MySQL, Postgres, NoSQL
17. SCADA/ICS ..............[N]: Modbus, S7, BACnet, MQTT, Ethernet/IP

[ SPECIALIZED ]
18. Auto-Zombie Hunter .....[S]: Scan OS-Unknowns for Incremental IPID (Idle Scan Prep)
19. Firewalk Scan..............: TTL Analysis to Gateway

--- EVASION & SPOOFING ---
20. Ghost Scan .............[E]: Decoy Army (RAND:10), MAC Spoof, & DNS Source Port

99. User Defined Option........: Enter your own flags...
====================================================================================================

*** NOTE: Scans noted with a [P] can be executed through Proxychains: Full TCP Connection (-sT). ***
***       Scans noted with a [N] can be extremely noisey! Want stealth? This ain't it...         ***
***       Scans noted with a [S] are less intrusive! Discovery through passive segemnt traffic.  ***
***       Scans noted with a [E] make attemps to disguise the layer 2 and 3 source.              *** 

     Running a version scan (-sV) as sudo/root will defalut to a -sS scan before version checking! 
     This script requires sudo/root, so DO NOT leverage Proxychains with -sV ONLY! 

====================================================================================================
"""


# --- GLOBAL STATE ---
scan_active = True

# --- VALID_CHOICES ---
VALID_CHOICES = list(scans.keys()) + ["99"]
#VALID_CHOICES = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "99"]

choice = ""
while choice not in VALID_CHOICES:
    print(MENU)
    choice = input("Select Scan Option: ").strip()
    if choice not in VALID_CHOICES:
        print(f"{YELLOW}\n[!] INVALID OPTION: '{choice}'.{RESET} Please select a valid number from the menu.")


dashboard_data = {
    "scan_active": True,
    "base_dir_ref": BASE_DIR,
    "status": "Scanning...",
    "phase_info": "Phase 0 of 0",
    "results": [],
    "host_count": 0,
    "service_count": 0,
    "visual_recon_live": False,
    "exploits_found": False,
    "smb_enum_complete": False,
    "sploit_file": f"{CUSTOMER}_{DATE_STR}_exploits.txt",
    "meta_user": CURRENT_USER,
    "meta_time": "Waiting...",
    "meta_cmd": "Initializing..."
}

# --- smb Enum Preparation ---
smb_semaphore = threading.Semaphore(5)

# --- Safe Threading  Logic ---
completion_lock = threading.Lock()

# --- FLASK CONFIG ---
app = Flask(__name__)
#import logging

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Disable the default Flask console logger
log = logging.getLogger('werkzeug')
log.setLevel(logging.INFO)

# Initialize the Rotating Handler (Capped at 5MB)
file_handler = RotatingFileHandler(
    os.path.join('logs', 'flask.log'), 
    maxBytes=5*1024*1024, 
    backupCount=3
)

# Configure Formatting
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

# Attach to Flask and Stop Propagation
log.addHandler(file_handler)
log.propagate = False

app.secret_key = os.urandom(24)
login_manager = LoginManager(app)
login_manager.login_view = 'web.login'

# DEFINE THE CONFIG
ui_config = {
    "CUSTOMER": CUSTOMER,
    "DATE_STR": DATE_STR,
    "BASE_DIR": os.path.abspath(BASE_DIR),
    "YEAR_STR": YEAR_STR,
    "meta_user": CURRENT_USER
}

# --- Initialize live_log feed  (nmap to dashboard) ---
live_logs = []

# Link the shared memory (dashboard_data) to the blueprint
from web_interface import web_bp, init_web_data, User
init_web_data(dashboard_data, ui_config, live_logs)

# REGISTER THE BLUEPRINT
app.register_blueprint(web_bp)

# --- User Loader for Flask ---
@login_manager.user_loader
def load_user(user_id): 
    return User(user_id)

def print_session_summary():
    """Calculates and prints the final red-team report to the terminal."""
    END_SESSION_TIME = datetime.now()
    duration = END_SESSION_TIME - START_SESSION_TIME
    
    hours, remainder = divmod(duration.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    duration_str = f"{hours:02}:{minutes:02}:{seconds:02}"

    print(f"{GREEN}\n\n" + "="*70)
    print(f" - S - c - A - n - R - o - I - d - S -  SESSION SUMMARY")
    print("="*70)
    print(f"{GREEN}Customer       :{RESET} {CUSTOMER}")
    print(f"{GREEN}Total Duration :{RESET} {duration_str}")
    print(f"{GREEN}Targets Found  :{RESET} {dashboard_data.get('host_count', 0)}")
    print(f"{GREEN}Services Found :{RESET} {dashboard_data.get('service_count', 0)}")
    
    # SID Logic
    sid_report = "N/A"
    sid_path = os.path.join(BASE_DIR, "domain_sid.txt")
    if os.path.exists(sid_path):
        with open(sid_path, 'r') as f:
            line = f.readline()
            if "]" in line: sid_report = line.split("] ")[1].strip()

    print(f"{GREEN}Domain SID     :{RESET} {sid_report}")
    print(f"{GREEN}Artifacts Path :{RESET} {os.path.abspath(BASE_DIR)}")
    print(f"{GREEN}="*70)
    print(f"{YELLOW}[+] Dashboard stopped:{RESET} Port 8888 released. Happy Hunting.\n")


def get_ports(port_list):
    """Joins a list of ports into a comma-separated string."""
    return ",".join(port_list)


def signal_handler(sig, frame):
    """The 'Secret Sauce' that catches Ctrl+C."""
    print_session_summary()
    os._exit(0)


def trigger_smb_enumeration():
    """Runs enum4linux with a 5-thread limit and updates the dashboard upon completion."""
    smb_hosts_file = os.path.join(BASE_DIR, "microsoft-ds_445", "hosts_all.txt")
    
    if os.path.exists(smb_hosts_file):
        with open(smb_hosts_file, 'r') as f:
            ips = list(set(f.read().splitlines()))
        
        if ips:
            enum_dir = os.path.abspath(os.path.join(BASE_DIR, "smb_enumeration"))
            os.makedirs(enum_dir, exist_ok=True)
            print(f"[*] Found {len(ips)} SMB targets. Queuing enumeration (Max 5 concurrent)...")
            
            def worker(ip, log_path, total_ips, completed_list):
                with smb_semaphore: # Limits concurrency to 5
                    cmd = (
                        f"enum4linux -a -u '' -p '' {ip} | "
                        f"sed -r 's/\\x1B\\[([0-9]{{1,2}}(;[0-9]{{1,2}})?)?[mGK]//g' "
                        f"> '{log_path}' 2>&1"
                    )
                    subprocess.run(cmd, shell=True)
                     
                    # --- NEW: DOMAIN SID EXTRACTION ---
                    try:
                        # Grep the newly created log for the SID pattern
                        sid_cmd = f"grep -Po 'S-1-5-21-[\\d-]+' '{log_path}' | head -n 1"
                        sid_result = subprocess.check_output(sid_cmd, shell=True, text=True).strip()
                         
                        if sid_result:
                            sid_file = os.path.join(BASE_DIR, "domain_sid.txt")
                            with open(sid_file, "a") as f:
                                f.write(f"[{ip}] {sid_result}\n")
                            print(f"{GREE}[+] Domain SID Captured:{RESET} {sid_result}")
                    except Exception as e:
                        pass # Silently skip if SID isn't found on this specific host

                    print(f"[+] enum4linux completed for {ip}.")

                    # Use the lock for shared list update
                    with completion_lock: 
                        completed_list.append(ip)
                        if len(completed_list) == len(total_ips):
                            dashboard_data['smb_enum_complete'] = True
                            print(f"{BLUE}[*]{RESET} ALL SMB Enumeration finished. Logs: {enum_dir}")

            completed_ips = []
            for ip in ips:
                log_file = os.path.join(enum_dir, f"{ip}_enum4linux.txt")
                threading.Thread(target=worker, args=(ip, log_file, ips, completed_ips), daemon=True).start()


def execute_firewalk(target_ip):
    """Multi-stage logic to determine TTL and execute firewalking."""
    print(f"{BLUE}[*] Stage 1:{RESET} Determining Hop Count to {target_ip}...")
    dashboard_data['status'] = "Scanning (Stage 1: Traceroute)..."
    dashboard_data['meta_cmd'] = f"Firewalk Stage 1: Traceroute {target_ip}"

    # Stage 1: Get Traceroute Data
    trace_cmd = f"nmap -sn --traceroute {target_ip}"
    proc = subprocess.run(trace_cmd, shell=True, capture_output=True, text=True)

    # Find the highest hop number using regex
    hops = re.findall(r"^\s+(\d+)\s+[\d\.]+\s+.*$", proc.stdout, re.MULTILINE)

    if not hops:
        # OPTIMIZATION: Check if target is on the same subnet
        print("{YELLOW}[!]{RESET} No intermediate hops detected. Checking local connectivity...")
        # If we can ping it but there are no hops, it's likely on the same segment
        if "Host is up" in proc.stdout:
            msg = f"{YELLOW}[*]{RESET} Target {target_ip} appears to be on the SAME SUBNET (0 hops). Firewalking is not applicable."
            print(msg)
            live_logs.append(msg)
            dashboard_data['status'] = "SKIPPED (Local Target)"
            return
        else:
            msg = "{RED}[!] Error:{RESET} Target unreachable or traceroute failed."
            print(msg)
            live_logs.append(msg)
            dashboard_data['status'] = "FAILED (Traceroute Error)"
            return

    # Calculate TTL (Hop + 1)
    target_ttl = int(hops[-1]) + 1
    fire_msg = f"Firewall detected at hop {hops[-1]}. Testing TTL {target_ttl}."
    print(f"{GREEN}[+]{RESET} {fire_msg}")
    live_logs.append(f"[*] {fire_msg}")

    # Stage 2: Execute the actual Firewalk scan
    dashboard_data['status'] = f"Scanning (Stage 2: Firewalk TTL {target_ttl})..."
    fire_cmd = f"nmap -Pn --ttl {target_ttl} --script firewalk --script-args=firewalk.max-retries=1 {target_ip} --reason"

    # Update dashboard to show current command
    dashboard_data['meta_cmd'] = fire_cmd

    # Call your standard engine to handle the live logs and final parsing
    run_scan("12", fire_cmd, "", "", f"{CUSTOMER}_{DATE_STR}_firewalk")

    # Post-Scan Analysis for Success vs. Filtered vs. Closed
    # Ensure we are looking for the file run_scan actually created:
    xml_file_to_check = os.path.join(BASE_DIR, f"{CUSTOMER}_{DATE_STR}_firewalk_discovery.xml")
    if os.path.exists(xml_file_to_check):
        found_open = False
        try:
            # 1. Surgical check for OPEN ports (Success)
            tree = ET.parse(xml_file_to_check)
            root = tree.getroot()
            for port in root.findall(".//port"):
                state_node = port.find('state')
                if state_node is not None and state_node.get('state') == 'open':
                    found_open = True
                    break
            
            # 2. Update Dashboard with the findings
            if found_open:
                msg = "SUCCESS: [OPEN] Firewall is LEAKING traffic at this TTL!"
                dashboard_data['status'] = f"FINISHED ({msg})"
                live_logs.append(f"{GREEN}[+]{RESET} {msg}")
            else:
                # Fallback to check for Filtered/Blocked if nothing was open
                with open(xml_file_to_check, 'r') as f:
                    xml_content = f.read()
                    if "filtered" in xml_content or "no-response" in xml_content:
                        dashboard_data['status'] = "FINISHED (WARNING: [FILTERED] Firewall Dropping Packets)"
                    else:
                        dashboard_data['status'] = "FINISHED (No Open Paths Found)"
            dashboard_data['scan_active'] = False
        except Exception as e:
            print(f"{RED}[!] WARNING:{RESET} Error analyzing Firewalk XML: {e}")
            dashboard_data['status'] = "FINISHED (Analysis Error)"


# --- PREPARE ENVIRONMENT ---
exclude_flag = f"--exclude {LOCAL_IPS}" if LOCAL_IPS else ""
perf_switches = ""

# --- DEFINE LABELS AND PATHS (Crucial: Define these FIRST) ---
scan_label = choice.replace("0", "") if choice.startswith("0") else choice
file_prefix = f"{CUSTOMER}_{DATE_STR}_scan_{scan_label}"
nmap_out_base = os.path.join(BASE_DIR, f"{file_prefix}_discovery")
xml_out = nmap_out_base + ".xml"

# --- THE TARGET LOGIC (Consolidated) ---
if choice in ["03", "06", "07"]:
    # Start with a default placeholder
    target_cmd = "LOCAL_INTERFACE"
     
    # Specific "Smart Subnet" logic for the ARP Scan (03)
    if choice == "03":
        try:
            # Grabs actual CIDR (e.g., 10.10.50.0/22) for your active interface
            cmd = f"ip -4 addr show {DEFAULT_IFACE} | grep -oP '(?<=inet\\s)\\S+'"
            target_cmd = subprocess.check_output(cmd, shell=True, text=True).strip()
            print(f"{YELLOW}[*]{RESET} Detected Local Subnet for ARP: {target_cmd}")
        except:
            # Fallback to /24 if the ip command fails
            target_cmd = ".".join(LOCAL_IPS.split('.')[:-1]) + ".0/24"
     
    # Sync the dashboard name to the command value
    target_in = target_cmd

else:
    # ONLY ask for a target if it's NOT a local-only scan (01, 02, 04, 05, 08-99)
    target_in = input(f"\n{YELLOW}[?]{RESET} Enter Target (IP, Subnet, or File Path): ").strip()
    target_cmd = f"-iL {target_in}" if os.path.exists(target_in) else target_in

# --- PROCESS CHOICE ---
final_cmd = "Initializing..."

# ARP Discovery [S] (Choice 03)
if choice == "03":
# --- NEW: VPN / INTERFACE CHECK ---
    if "tun" in DEFAULT_IFACE.lower() or "ppp" in DEFAULT_IFACE.lower():
        print(f"\n{RED}[!] WARNING:{RESET}: ARP Scanning on VPN interface '{DEFAULT_IFACE}' will likely fail.")
        print(f"{YELLOW}[!]{RESET} ARP requires a Layer 2 connection (Ethernet/Wi-Fi).")
        confirm = input(f"{YELLOW}[?]{RESET} Proceed anyway? (y/n): ").lower()
        if confirm != 'y':
            print(f"{YELLOW}[*]{RESET} Scan aborted by operator. Choose a different scan type or interface.")
            os._exit(0)
    try:
        # Grabs actual CIDR for your active interface
        cmd = f"ip -4 addr show {DEFAULT_IFACE} | grep -oP '(?<=inet\\s)\\S+'"
        target_cmd = subprocess.check_output(cmd, shell=True, text=True).strip()
        print(f"{YELLOW}[*]{RESET} Detected Local Subnet for ARP: {target_cmd}")
    except:
        target_cmd = ".".join(LOCAL_IPS.split('.')[:-1]) + ".0/24"

    final_cmd = f"nmap -sn -PR {target_cmd} -oA '{nmap_out_base}' --reason"

# Reverse DNS Lookup [S] (Choice 04)
elif choice == "04":
    dns_server = input(f"{YELLOW}[?]{RESET} Enter DNS Server IP to query: ").strip()     
    # 1. Update the target_cmd to include the DNS server flag
    # This is what gets passed to the run_scan function in the main thread
    target_cmd = f"{target_cmd} --dns-servers {dns_server}"
     
    # 2. Define final_cmd for the Dashboard Header only
    final_cmd = f"nmap -sL {target_cmd} -oA '{nmap_out_base}'"

# Zombie Idle Scan [S] (Choice 05)
elif choice == "05":
    zombie_input = input(f"{YELLOW}[?]{RESET} Enter Zombie Host (IP or IP:PORT) [Zombie SRC Port for traffic (Default 80)]: ").strip()
    target_ports = input(f"{YELLOW}[?]{RESET} Enter Target Port(s) to scan (e.g., 445, 80-100 or -p-): ").strip()
     
    # Parse Zombie Input
    zombie_ip = zombie_input.split(':')[0]
    zombie_port = zombie_input.split(':')[1] if ':' in zombie_input else "80"
      
    # --- 1. IPIDSEQ SUITABILITY CHECK (On Zombie) ---
    print(f"{YELLOW}[*]{RESET} Checking {zombie_ip}:{zombie_port} suitability...")
    check_cmd = f"nmap -O -v -p {zombie_port} --max-retries 1 --host-timeout 30s {zombie_ip}"
    proc = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
      
    if "Incremental" in proc.stdout and "open" in proc.stdout:
        print(f"{GREEN}[+]{RESET} SUCCESS: {zombie_ip}:{zombie_port} is open and predictable.")
    else:
        print(f"{RED}[!] WARNING:{RESET}: {zombie_ip}:{zombie_port} suitability check failed.")
        confirm = input("[?] Attempt scan anyway? (y/n): ").lower()
        if confirm != 'y': os._exit(0)

    # --- 2. EXECUTE SCAN ---
    # We add the -p {target_ports} flag to the command
    scans["05"]["discovery"] = f"-Pn -vv -sI {zombie_ip}:{zombie_port} -p {target_ports}"
    final_cmd = f"nmap {scans['05']['discovery']} {target_cmd} -oA '{nmap_out_base}' --reason --open"
    print(f"{BLUE}[*]{RESET} Initializing Stealth Engine: {zombie_ip}:{zombie_port} -> {target_cmd}:{target_ports}")
#   time.sleep(1.5)

# --- [ NON-NMAP DISCOVERY BLOCKS ] ---
# IPv6 Link-Local [N]
elif choice == "06": # IPv6 Link-Local [N]
    final_cmd = scans["06"]["cmd"].format(IFACE=DEFAULT_IFACE)

    def ipv6_auto_sequence(cmd):
        # 1. Wake them up with the multicast ping
        print(f"{YELLOW}[*]{RESET} Waking up IPv6 neighbors on {DEFAULT_IFACE}...")
        execute_subprocess_with_logging(cmd, live_logs, completion_lock)
         
        # 2. Wait 2 seconds for the cache to settle
        time.sleep(2)
         
        # 3. Automatically trigger the Neighbor Scan logic
        print("{BLUE}[*]{RESET} Ping complete. Auto-syncing neighbor cache to dashboard...")
         
        proc = subprocess.run("ip neighbor", shell=True, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            match = re.match(r"^([a-fA-F0-9\.:]+)\s+dev", line)
            if match:
                ip = match.group(1)
                # Dashboard Deduplication
                with completion_lock: # Protect the list from "Double-Writes"
                    if not any(d['host'] == ip for d in dashboard_data['results']):
                        dashboard_data['results'].append({
                            "host": ip, "os": "Unknown (IPv6 Discover)", "port": "N/A", 
                            "service": "Host Discovery", "ttl": "N/A", "css_class": ""
                        })
                # File Deduplication (a+ mode)
                h_file = os.path.join(BASE_DIR, "hosts_all.txt")
                if not os.path.exists(h_file): open(h_file, 'w').close()
                with open(h_file, "a+") as f:
                    f.seek(0)
                    if ip not in f.read():
                        f.write(f"{ip}\n")
         
        # 4. Final Metrics and CONCLUSION BOX
        dashboard_data['host_count'] = len(set(d['host'] for d in dashboard_data['results']))
        dashboard_data['status'] = "FINISHED (IPv6 Discovery & Sync Complete)"
        dashboard_data['scan_active'] = False
         
        # --- THE CLEANUP MESSAGE (Added for Scan 06) ---
        print("{BLUE}\n" + "="*60)
        print("[+] IPv6 MULTICAST DISCOVERY COMPLETE")
        print(f"[*] Total Unique Targets in Cache:{RESET} {dashboard_data['host_count']}")
        print("{RESET}[!] Dashboard is now LIVE. Use {RESET}Ctrl+C{BLUE} to exit when finished.{RESET}")
        print("="*60 + "\n")
       
        live_logs.append("{BLUE}[+]{RESET} IPv6 Discovery Complete. Dashboard Updated.")

    threading.Thread(target=ipv6_auto_sequence, args=(final_cmd,), daemon=True).start()

# Neighbor Solicitation [S] (Choice 07)
elif choice == "07":
    final_cmd = "ip neighbor"
    def neighbor_wrapper():
        print("{BLUE}[*]{RESET} Accessing Local Neighbor Cache...")
        # 1. Capture the output
        proc = subprocess.run("ip neighbor", shell=True, capture_output=True, text=True)
        output = proc.stdout
          
        # 2. Process each line
        for line in output.splitlines():
            # Print to terminal and live_logs
            print(line)
            live_logs.append(line)
             
            # 3. REGEX PARSE: Grab the IP at the start of the line
            match = re.match(r"^([a-fA-F0-9\.:]+)\s+dev", line)
            if match:
                ip = match.group(1)
                 
                # Deduplication check for Dashboard
                with completion_lock: 
                    if not any(d['host'] == ip for d in dashboard_data['results']):
                        dashboard_data['results'].append({
                            "host": ip, "os": "Unknown (Neighbor Cache)", "port": "N/A", 
                            "service": "Host Discovery", "ttl": "N/A", "css_class": ""
                        })
                 
                # Deduplication check for Physical File
                h_file = os.path.join(BASE_DIR, "hosts_all.txt")
                if not os.path.exists(h_file): open(h_file, 'w').close()
                 
                with open(h_file, "a+") as f:
                    f.seek(0) # Go to the very start of the file
                    existing_hosts = f.read().splitlines()
                    if ip not in existing_hosts:
                        f.write(f"{ip}\n")

        # 4. Global Metrics Update
        dashboard_data['host_count'] = len(set(d['host'] for d in dashboard_data['results']))
        dashboard_data['status'] = "FINISHED (Neighbor Cache Dump)"
        dashboard_data['scan_active'] = False

        # 5. THE CLEANUP MESSAGE (Now inside the function so it waits for completion)
        print("{BLUE}\n" + "="*60)
        print("[+] NEIGHBOR DISCOVERY COMPLETE")
        print(f"[*] Total Unique Targets:{RESET} {dashboard_data['host_count']}")
        print("{BLUE}[!] Dashboard is now LIVE. Use {RESET}Ctrl+C{BLUE} to exit when finished.{RESET}")
        print("="*60 + "\n")
     
    threading.Thread(target=neighbor_wrapper, daemon=True).start()

elif choice == "18": # Auto-Zombie Hunter [S]
    unknown_file = os.path.join(BASE_DIR, "hosts_OS-unknown.txt")
    if not os.path.exists(unknown_file) or os.path.getsize(unknown_file) == 0:
        print("\n" + "!"*70)
        print(f"{RED}[!] ERROR:{RESET} Target file '{unknown_file}' is missing or empty.")
        print("{YELLOW}[!] ACTION:{RESET} Run a Discovery Scan (01-07) first to populate OS-unknowns.")
        print("!"*70 + "\n")
        # Hard exit to terminal
        os._exit(0)
    else:
        def zombie_hunter_thread():
            with open(unknown_file, 'r') as f:
                targets = f.read().splitlines()
            
            print(f"{YELLOW}[*]{RESET} Hunting for suitable zombies in {len(targets)} candidates...")
            dashboard_data['status'] = f"Hunting Zombies (0/{len(targets)})..."
            
            found_count = 0
            for i, ip in enumerate(targets):
                dashboard_data['status'] = f"Hunting Zombies ({i+1}/{len(targets)})..."
                cmd = f"nmap -O -v --max-retries 0 --host-timeout 30s {ip}"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if "IP ID Sequence Generation: Incremental" in proc.stdout:
                    found_count += 1
                    with open(os.path.join(BASE_DIR, "zombie_candidates.txt"), "a") as zf:
                        zf.write(f"{ip} (Incremental IPID)\n")
                    print(f"{GREEN}[+] ZOMBIE FOUND:{RESET} {ip} is suitable for Idle Scanning!")
                    live_logs.append(f"[+] ZOMBIE FOUND: {ip} is suitable!")

            dashboard_data['status'] = f"FINISHED ({found_count} Zombies Found)"
            dashboard_data['scan_active'] = False
            print(f"{BLUE}[*]{RESET} Zombie Hunt Complete. {found_count} suitable hosts logged to zombie_candidates.txt")

        # Start the thread inside the else block
        threading.Thread(target=zombie_hunter_thread, daemon=True).start()

# Firewalk [ MULTI-PHASED ]
elif choice == "19":
    # 1. Firewalk Sequence (Stays independent)
    if "/" in target_in or " " in target_in:
        print(f"\n[!] {RED}WARNING:{RESET} Firewalking is most accurate against a single IP (Gateway).")
    
    # Note: We keep this for the 'final_cmd' display, 
    # but execute_firewalk now builds its own XML path internally.
    final_cmd = f"nmap -sn --traceroute {target_in}"
    
    # CORRECTED: Pass only (target_in,) as a tuple
    threading.Thread(target=execute_firewalk, args=(target_in,), daemon=True).start()

# DECOY SCANNING
elif choice == "20": # Ghost Scan [E] (Decoys & Spoofing)
    target_in = input(f"\n{YELLOW}[?]{RESET} Enter Target (IP or Subnet): ").strip()
    target_cmd = target_in
     
    # 1. Determine Subnet for Decoys (Use target's subnet for RAND)
    # nmap -D RAND:10 will use random IPs, but we can't force them to a specific subnet 
    # easily in one flag. However, using 'ME' ensures your IP is hidden in the mix.
    decoy_flag = "-D RAND:10,ME"
     
    # 2. Check for Same-Subnet to enable MAC Spoofing
    spoof_flag = ""
    if is_local_target(target_in):
        print("{BLUE}[+]{RESET} Target is LOCAL. Enabling --spoof-mac 0 (Random Manufacturer).")
        spoof_flag = "--spoof-mac 0"
    else:
        print("{RED}[!] WARNING:{RESET} Target is REMOTE. Skipping MAC spoofing (Layer 3 restriction).")

    # 3. Source Port Manipulation (DNS/53 or HTTPS/443)
    source_port = "-g 53" 

    # 4. Build Final Command
    scans["20"]["discovery"] = f"-sS -Pn -T2 {decoy_flag} {spoof_flag} {source_port} --data-length 24"
     
    # Define final_cmd for the Dashboard Header only
    final_cmd = f"nmap {scans['20']['discovery']} {target_cmd} -oA '{nmap_out_base}' --reason --open"
      
    print(f"{YELLOW}[*]{RESET} Ghost Scan [E] Engaged. Spoofing as random device via {source_port}...")

# User Defined (Choice 99)
elif choice == "99":
    # 1. Define Paths FIRST
    nmap_out_base = os.path.join(BASE_DIR, file_prefix)
    xml_out = nmap_out_base + ".xml"

    # 2. Gather User Input
    user_flags = input("Enter full nmap flags: ")
    
    # 3. IPv6 Auto-detection
    ipv6_flag = "-6" if ":" in target_in and "-6" not in user_flags else ""
    if ipv6_flag:
        print(f"{YELLOW}[*]{RESET} IPv6 detected in target. Automatically appending '{ipv6_flag}' flag.")
    
    # 4. Build Final Command
    final_cmd = f"nmap {ipv6_flag} {user_flags} {exclude_flag} {target_cmd} -oA '{nmap_out_base}' --reason --open"
     
    # 5. Define the Wrapper (Ensure it has access to global data)
    def manual_scan_wrapper(cmd, xml_file, choice_val):
        # Pass the global logs and lock so the UI sees the output
        global live_logs, completion_lock, dashboard_data
        execute_subprocess_with_logging(cmd, live_logs, completion_lock)

        # Use your modular surgeon calls
        parse_and_sync_results(xml_file, dashboard_data, BASE_DIR, choice_val)
        trigger_external_tools(xml_file, choice_val, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs)
        dashboard_data['scan_active'] = False
         
    # 6. Start the SINGLE Thread for this choice
    threading.Thread(target=manual_scan_wrapper, args=(final_cmd, xml_out, choice), daemon=True).start()


# All Other Standard Scans
else:
    # Aggressive 1k [N] and Kitchen Sink [N]
    if choice in ["08", "11", "12"]: 
        print(f"\n{YELLOW}[!] HIGH PERFORMANCE CHECK")
        confirm = input("Add performance switches? (y/n):{RESET} ").lower()
        if confirm == 'y':
            perf_switches = "--min-hostgroup 64 --min-parallelism 100 --min-rate 1000"
            
    # Define the command HERE so we can pass it to the dashboard
    discovery_flags = scans[choice]["discovery"]
    
    # Define the base path for -oA (MATCHING what run_scan uses)
    nmap_out_base = os.path.join(BASE_DIR, f"{file_prefix}_discovery")
    
    # Built the Syntax for the Dashboard
    actual_nmap_syntax = f"nmap {discovery_flags} {exclude_flag} {perf_switches} {target_cmd} -oA '{nmap_out_base}' --reason --open"

# Update Dashboard Header immediately
final_cmd = actual_nmap_syntax 
dashboard_data["meta_cmd"] = final_cmd
dashboard_data["meta_time"] = datetime.now().strftime('%H:%M:%S')

# --- STARTUP LOGIC ---
if __name__ == "__main__":
    try:
        # 1. Launch the CORRECT Scan Engine in the Background
        import threading

        # Register the Ctrl+C signal BEFORE starting Flask
        signal.signal(signal.SIGINT, signal_handler)

        # Only launch the standard Nmap engine if it's NOT the specialized IPv6 scan
        if choice not in ["06", "07", "18", "19", "99"]:
            from engine import run_scan
            scan_thread = threading.Thread(
                target=run_scan, 
                args=(
                    choice,
                    target_cmd,
                    exclude_flag,
                    perf_switches,
                    file_prefix,
                    BASE_DIR,
                    CUSTOMER,
                    DATE_STR,
                    CURRENT_USER,
                    dashboard_data,
                    live_logs,
                    completion_lock
                )
            )
            scan_thread.daemon = True
            scan_thread.start()

        elif choice in ["99"]:
            print(f"{BLUE}[*]{RESET} User Customized Scan is active...")

        elif choice in ["18", "19"]:
            print(f"{BLUE}[*]{RESET} Specialized nmap Scan is selected...")

        else:
            print(f"{BLUE}[*]{RESET} Specialized IPv6 Multicast Engine is active...")

        # 2. Print Terminal Banner
        print(f"\n{BLUE}[*] ScAnRoIdS Active:{RESET} {file_prefix}")
        print(f"{BLUE}[*] Dashboard Live  : {RESET}http://0.0.0.0:8888")
        print(f"{BLUE}[*] Credentials     : {RESET}operator / {CUSTOMER}_{YEAR_STR}")
        print(f"{BLUE}[*] Press {RESET}Ctrl+C{BLUE} to stop the dashboard and see the Session Summary.{RESET}\n")
         
        # 3. Start the Web Server (This "Blocks" here until Ctrl+C)
        app.run(host='0.0.0.0', port=8888, debug=False, use_reloader=False)
         
    except Exception as e:
        # Catch-all for unexpected crashes
        print(f"{RED}[!] System Error:{RESET} {e}")
        print_session_summary()
        import os
        os._exit(1)
