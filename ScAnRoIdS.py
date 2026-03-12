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

# --- PREPARE ENVIRONMENT ---
exclude_flag = f"--exclude {LOCAL_IPS}" if LOCAL_IPS else ""
perf_switches = ""

# --- DEFINE LABELS AND PATHS (Crucial: Define these FIRST) ---
scan_label = choice.replace("0", "") if choice.startswith("0") else choice
file_prefix = f"{CUSTOMER}_{DATE_STR}_scan_{scan_label}"
nmap_out_base = os.path.join(BASE_DIR, f"{file_prefix}_discovery")
xml_out = nmap_out_base + ".xml"

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
