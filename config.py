#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  config.py
Purpose: Global configuration, port registries, scan definitions, 
         and tactical suggestions for the orchestrator and dashboard.

Banner Testing: python3 -c "from config import get_banner; print(get_banner())"
"""

from core.ui import BLUE, RED, YELLOW, CYAN, GREEN, RESET, BOLD

# --- PORT REGISTRY ---
JUICY_PORTS = [21, 22, 23, 443, 445, 1433, 2222, 3389, 5900]
DC_PORTS = [88, 389, 636]
WEB_PORTS = ["80", "443", "3000", "3128", "5000", "5001", "7001", "7002", "8000", "8080", "8081", "8118", "8443", "8888", "9000", "9090", "10000"]
SCADA_TCP = ["102", "500", "502", "1883", "4840", "8883", "9600", "20000", "44818"]
SCADA_UDP = ["2222", "9600", "20000", "47808"]
DB_TCP    = ["1433", "1521", "3050", "3306", "5000", "5432", "5984", "6379", "9042", "11211", "27017", "33060"]
MGMT_TCP  = ["22", "23", "80", "88", "389", "443", "135", "445", "636", "3389", "5985", "5986", "8080", "8443"]
MGMT_UDP  = ["161", "623", "123"]
WINDOWS_PORTS = ["135", "139", "445", "3389", "5985", "5986"]
LINUX_PORTS = ["22", "111", "2049", "3306", "5432"]

# --- TACTICAL SUGGESTIONS ---
# Mapped by Port ID (Int) for efficient dashboard lookups
TACTICAL_SUGGESTIONS = {
    # --- MGMT PORTS ---
    22:    "-vv -sV --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
    23:    "-vv -sV --script telnet-ntlm-info,telnet-encryption,telnet-brute --script-args userdb=user.lst,passdb=passwords.lst",
    53:    "-vv -sV --script dns-srv-enum,dns-zone-transfer,dns-recursion,dns-brute --script-args dns-brute.hostlist=wordlist.txt,dns-brute.threads=10 <domain.tld>",
    80:    "-vv --sV --script http-title,http-headers,http-methods,http-enum",
    443:   "-vv -sV --script ssl-cert,ssl-enum-ciphers,ssl-date",
    3389:  "-vv -sT -T2 --script rdp-ntlm-info,rdp-enum-encryption",
    5985:  "-vv -sV --script http-title,winrm-auth",
    # --- WINDOWS PORTS ---
    135:   "-vv -sV --script msrpc-enum,rpc-grind",
    445:   "-vv -sV --script smb-os-discovery,smb-enum-shares,smb-enum-users",
    # --- LINUX PORTS ---
    111:   "-vv -sV --script rpcinfo,rpc-grind",
    2049:  "-vv -sV --script nfs-showmount,nfs-ls,nfs-statfs,nfs-acl-get",
    # --- DB PORTS ---
    1433:  "-vv -sV --script ms-sql-info,ms-sql-config,ms-sql-ntlm-info",
    1521:  "-vv -sV --script oracle-tns-version,oracle-sid-brute",
    3306:  "-vv -sV --script mysql-empty-password,mysql-databases",
    5432:  "-vv -sV --script pgsql-introspection",
    6379:  "-vv -sV --script redis-info",
    27017: "-vv -sV --script mongodb-info,mongodb-databases",
    # --- SCADA/ICS PORTS ---
    502:   "-vv -sT -T2 --script modbus-discover,modbus-enum --script-args modbus-discover.aggressive=true",
    102:   "-vv -T2 --script s7-info,banner",
    44818: "-vv -sU -T2 --script modbus-discover",
    1911:  "-vv -sT -T2 --script fox-info",
    4911:  "-vv -sT -T2 --script fox-info"
}

# --- MENU INTERFACE ---
def get_banner():
    """Returns the formatted ASCII banner with ANSI colors"""
    banner = f"""
{BLUE}{BOLD}============================== - S - c - A - n - R - o - I - d - S - ==============================={RESET}

 [ DISCOVERY - NETWORK LAYER - HOSTS List Building Only ]
     01. Aggressive Discovery ...[N]: SYN/ACK/UDP/ICMP Egress Techniques

 [ PORT SCANNING & AUDITS - HOSTS Building -or- Supply HOSTS from earlier scans ]
    10. Full Audit (Live/Open) .[N]: Scripts (-sC) and Versioning (-sV) (only Discovered Hosts/Ports)

 [ CUSTOM USER DEFINED SCAN ]
    99. User Defined Option ....[?]: Enter your own flags...

 [ TERMINATE EXECUTION ]
     q. Nevermind ..................: Wait, Why am I here???

{BLUE}{BOLD}===================================================================================================={RESET}

{YELLOW}NOTES:{RESET}
*** Scans noted with a {YELLOW}[P]roxy{RESET} can be executed through Proxychains: Full TCP Connection (-sT).   ***
*** Scans noted with a {YELLOW}[E]vasive{RESET} make attemps to disguise the layer 2 and 3 source.              ***
*** Scans noted with a {YELLOW}[N]oisey{RESET} can be extremely loud on the net. Want stealth? This ain't it... ***
*** Scans noted with a {YELLOW}[S]ilent{RESET} are less intrusive. Discovery through passive segemnt traffic.   ***

    {YELLOW}Running a version scan (-sV) as sudo/root will defalut to a -sS scan before version checking!
    This script requires sudo/root, so DO NOT leverage Proxychains with -sV ONLY! {RESET}

{BLUE}{BOLD}===================================================================================================={RESET}

"""
    return banner

# --- SCAN DICTIONARY HELPERS ---
def get_p(port_list):
    """Converts list to comma-separated string for Nmap flags"""
    return ",".join(map(str, port_list))

SCAN_LIBRARY = {
    "01": {
        "name": "Aggressive Discovery",
        "category": "[N]",
        "phase": 1,
        "flags": f"-sn -vv -PS{get_p(MGMT_TCP)} -PA21,23,80 -PU53 -PE",
    },
    "10": {
        "name": "Full Audit (Host-by-Host)",
        "category": "[N]",
        "phase": 2,
        "flags": "-sV -sC -T4 --version-all",
    },
    "99": {
        "name": "User Defined Option",
        "category": "[?]",
        "phase": 1,  # Default to 1, user can specify flags
        "flags": None, # This will be filled by main.py
    }
}
