# ==============================================================================
# SCRIPT: registry.py
# PURPOSE: Configuration, Port Definitions, and Scan Syntax Library
# FUNCTIONALITY: 
#   - Stores the dictionary of all 20+ Nmap command flags and descriptions.
#   - Defines 'Juicy Ports', 'Web Ports', and 'DC Ports' for UI highlighting.
#   - Houses 'Tactical Suggestions' mapping Port IDs to specific attack strings.
#   - Centralizes all static lookup data to keep the Engine and Surgeon lean.
# ==============================================================================


def get_ports(port_list):
    """Joins a list of ports into a comma-separated string."""
    return ",".join(port_list)

# --- 1. ADD ANSI COLORS TO THE TOP ---
BLUE = "\033[94m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --- GLOBAL PORT DEFINITIONS  ---
JUICY_PORTS = [21, 22, 23, 443, 445, 1433, 2222, 3389, 5900]
DC_PORTS = [88, 389, 636]
WEB_PORTS = ["80", "443", "3000", "3128", "5000", "5001", "7001", "7002", "8000", "8080", "8081", "8118", "8443", "8888", "9000", "9090", "10000"]

# --- PORT REGISTRY ---
SCADA_TCP = ["102", "500", "502", "1883", "4840", "8883", "9600", "20000", "44818"]
SCADA_UDP = ["2222", "9600", "20000", "47808"]
DB_TCP    = ["1433", "1521", "3050", "3306", "5000", "5432", "5984", "6379", "9042", "11211", "27017", "33060"]
MGMT_TCP  = ["22", "23", "80", "88", "389", "443", "135", "445", "636", "3389", "5985", "5986", "8080", "8443"]
MGMT_UDP  = ["161", "623", "123"]
WEB_TCP   = ["80", "443", "3000", "3128", "5000", "5001", "7001", "7002", "8000", "8080", "8081", "8118", "8443", "8888", "9000", "9090", "10000"]
WINDOWS_PORTS = ["135", "139", "445", "3389", "5985", "5986"]
LINUX_PORTS = ["22", "111", "2049", "3306", "5432"]

# Modifing the scans dictionary below REQUIRES you to modify both: 'MENU' and 'VALID_CHOICES' in the main script!

scans = {
    # --- [S/N] NETWORK DISCOVERY LAYER ---
    "01": {"discovery": "-sn -vv -PS{get_ports(MGMT_TCP)} -PA21,23,80 -PU53 -PE"}, # Aggressive Host Discovery [N]
    "02": {"discovery": "-sn -vv -PA"},                 # ACK Discovery [S] (Firewall Bypass)
    "03": {"discovery": "-sn -vv -PR"}, 	        # Local ARP Discovery [S] (Subnet Mapping)
    "04": {"discovery": "-sL"},    	                # Reverse DNS [S] (Query Hostnames)
    "05": {"discovery": "-Pn -vv -sI"},                 # Zombie Idle Scan [S] (Stealth)
    # --- [S] NON-NMAP HOST DISCOVERY ---
    "06": {"cmd": "ping6 -I {IFACE} -c 4 ff02::1"}, 	# IPv6 Link-Local [N]
    "07": {"cmd": "ip neighbor"},                       # Neighbor Solicitation [S]
    # --- [P/N] PORT SCANNING & AUDIT ---
    "08": {"discovery": "-Pn -n -vv -sT -sV -T2 --randomize-hosts --max-retries 1 --scan-delay 1s --top-ports 1000"}, # Anti-Throttle [S]
    "09": {"discovery": f"-n -vv -sV -PS{get_ports(WINDOWS_PORTS)}", "scripts": f"-sV -sC --script smb-vuln*,rdp-vuln*,ms-sql-info"}, # Windows [P]
    "10": {"discovery": f"-n -vv -sT -sV -PS{get_ports(LINUX_PORTS)}", "scripts": f"-sV -sC --script ssh-auth-methods,nfs-showmount,mysql-info"}, # Linux [P]
    "11": {"discovery": "-Pn -n -vv -sS -sV -O --top-ports 1000", "scripts": "-vv -A --version-all --script default,vuln"}, # Aggressive 1k [N]
    "12": {"discovery": "-Pn -n -vv -sT -sV -p- -T4 --min-rate 1000", "scripts": "-sC --version-all -A"}, # Kitchen Sink [N]
    "13": {"discovery": "-Pn -n -vv -sT -sV -p 21,22,80,111,135,389,443,445,636,3389,5900,5985,8080,8443"}, # General Audit [P]
    "14": {"discovery": f"-n -vv -PS{get_ports(WEB_TCP)}", "scripts": f"-sV --script http-title,http-headers,http-methods,http-enum"}, # Web Discovery [P]
    "15": {"discovery": f"-n -vv -PS{get_ports(MGMT_TCP)} -PU{get_ports(MGMT_UDP)}", "scripts": f"-sV -A --script default,vuln"}, # Management Ports
    "16": {"discovery": f"-n -vv -sT -PS{get_ports(DB_TCP)}", "scripts": f"-sV --script mysql-info,ms-sql-info,mongodb-info"},
    "17": {"discovery": f"-n -vv -PS{get_ports(SCADA_TCP)} -PU{get_ports(SCADA_UDP)} -T2", "scripts": "-sV --script stuxnet-detect,modbus-discover,s7-info"}, # SCADA Discovery [N]
    # --- SPECIALIZED ---
    "18": {"discovery": "-O -v --max-retries 1 --host-timeout 1m"}, # Zombie Hunter [S]
    "19": {"discovery": "FIREWALK_STAGE_1"}, # Firewalk
    "20": {"discovery": ""} # Ghost Scan [E] (Populated dynamically at runtime)
}

'''
NOTE: Script scanning in general seems to create tagging issues with the outfile.xml
That file is required for parsing to write the dashboard, searchsploit ingestion and gowitness ingestion.
Script was modified into a 2 phase approach where --scripts, -sC or -A is needed.
nmap will continue the 2nd phase with switch -iX to focus only on discovered hosts and ports.
'''


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
#   --- SCADA PORTS ---
502:   "-vv -sT -T2 --script modbus-discover,modbus-enum --script-args modbus-discover.aggressive=true",
102:   "-vv -T2 --script s7-info,banner",
44818: "-vv -sU -T2 --script modbus-discover",
1911:  "-vv -sT -T2 --script fox-info",
4911:  "-vv -sT -T2 --script fox-info"
}
