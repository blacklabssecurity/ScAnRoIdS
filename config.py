#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  config.py
Purpose: Global configuration, port registries, scan definitions, 
         and tactical suggestions for the orchestrator and dashboard.

Banner Testing: python3 -c "from config import get_banner; print(get_banner())"
"""

from core.ui import BLUE, RED, YELLOW, CYAN, GREEN, RESET, BOLD, BULLET


# --- PORT REGISTRY ---

# Dashboard Styling
DC_PORTS = [88, 389, 636]
INTERESTING_PORTS = ["21", "22", "23", "111", "161", "443", "445", "1433", "2049", "2222", "3389", "5900"]

# Scannig Port Lists
DB_TCP    = ["1433", "1521", "3050", "3306", "5432", "5984", "6379", "9042", "11211", "27017", "33060"]
MGMT_TCP  = ["20", "21", "22", "23", "25", "80", "88", "135", "389", "443", "445", "465", "587", "636", "3389", "5985", "5986", "8080", "8443"]
MGMT_UDP  = ["161", "623", "123"]
WEB_PORTS = ["80", "443", "3000", "3128", "4443", "5000", "5001", "7001", "7002", "8000", "8080", "8081", "8118", "8443", "8888", "9000", "9090", "9443", "10000"]
SCADA_TCP = ["102", "500", "502", "1883", "4840", "8883", "9600", "20000", "44818"]
SCADA_UDP = ["2222", "9600", "20000", "47808"]
LINUX_PORTS = ["22", "111", "2049", "3306", "5432"]
WINDOWS_PORTS = ["135", "139", "445", "3389", "5985", "5986"]
SCTP_PORTS = ["80", "443", "2905", "3868", "7879", "5060", "5061", "7083", "7850", "38412"]

# SMB Enumeration
SMB_TCP_PORTS = [139, 445]
SMB_UDP_PORTS = [137, 138]

# NFS Enumeration
NFS_TCP_PORTS = [111, 2049, 20048]


# --- GLOBAL SETTINGS ---
# Set to True to bypass operator prompts for SMB/Looting
GREEDY_MODE = False

# Default shares to attempt if in Greedy Mode
AUTO_LOOT_SHARES = ["IPC$", "Public", "Backups", "Users"]


# --- TACTICAL SUGGESTIONS ---
# Mapped by Port ID (Int) for efficient dashboard lookups
TACTICAL_SUGGESTIONS = {
    # --- MGMT PORTS ---
    21:    "-vv -sV -p 21 --script ftp-anon,ftp-syst,ftp-bounce,ftp-proftpd-backdoor,ftp-brute",
    22:    "-vv -sV -p 22 --script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
    23:    "-vv -sV -p 23 --script telnet-ntlm-info,telnet-encryption,telnet-brute --script-args userdb=user.lst,passdb=passwords.lst",
    25:    "-vv -sV -p 25 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info",
    53:    "-vv -sV -p T:53 --script dns-srv-enum,dns-zone-transfer,dns-recursion,dns-brute --script-args dns-brute.hostlist=wordlist.txt,dns-brute.threads=10 <domain.tld>",
    80:    "-vv -sV --script http-title,http-headers,http-methods,http-enum",
    161:   "-vv -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat,snmp-processes",
    443:   "-vv -sV --script ssl-cert,ssl-enum-ciphers,ssl-date",
    3389:  "-vv -sT -p 3389 -T2 --script rdp-ntlm-info,rdp-enum-encryption",
    5985:  "-vv -sV --script http-auth,http-title,http-winrm-enumeraate,winrm-auth",
    # --- WINDOWS PORTS ---
    135:   "-vv -sV -p 135 --script msrpc-enum,rpc-grind",
    445:   "-vv -sV -p 445 --script smb-os-discovery,smb-enum-shares,smb-enum-users",
    # --- LINUX PORTS ---
    111:   "-vv -sV -p 111 --script rpcinfo,rpc-grind",
    2049:  "-vv -sV -p 2049 --script nfs-showmount,nfs-ls,nfs-statfs,nfs-acl-get",
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
    4911:  "-vv -sT -T2 --script fox-info",
    # --- SCTP PORTS ---
    2905:   "-vv -sY -sV -Pn -n --script sctp-info,banner",             # SS7 over IP
    3868:   "-vv -sY -sV -Pn -n --script sctp-info,sctp-enum-params",   # Diameter
    5600:   "-vv -sY -sV -Pn -n --script sip-methods,sip-enum-users"   # VoIP
}

# --- MENU INTERFACE ---
def get_banner():
    """Returns the formatted ASCII banner with ANSI colors"""
    banner = f"""
{BLUE}{BOLD}============================== - S - c - A - n - R - o - I - d - S - ==============================={RESET}

 [ GENERAL DISCOVERY - HOST BUILDING ONLY ]
    01. Aggressive Discovery ...[N]: SYN/ACK/UDP/ICMP Egress Techniques
    02. ACK Discovery ..........[N]: TCP ACK Ping (Stateless Firewall Check)
    03. Local ARP Discovery ....[N]: Layer 2 MAC Discovery-Local Subnet Only (Need [S]: arp -a)
    04. Reverse DNS Lookup .....[S]: Query Hostnames via Specific DNS Server
    05. Zombie Idle Discover ...[S]: Blind Stealth Scan (Requires Zombie IP)

 [ IPv6 DISCOVERY - HOST BUILDING ONLY ]
    10. IPv6 Link-Local ........[N]: Multicast Ping ff02::1 (Default Interface)
    11. Neighbor Solicitation ..[N]: ICMPv6 Ping Sweep (Need [S]: ip - neighbor show)
    12. SLAAC Discovery ........[N]: Stateless Address Autoconfiguration (SLAAC) requests
    13. IPv6 List Scan (ToDo)...[N]: DNS Query of provided IPv6 Range (Silent to Targets)

 [ NETWORK DEVICE DISCOVERY - HOST BUILDING ONLY ]
    20. SCTP INIT Ping .........[N]: Ping Probe for Host Discovery Only
    21. SCTP INIT Scan .........[N]: Half-Open Probe to 4-way Handshake (Older Firewalls)
    22. SCTP Cookie Echo........[S]: Analyze the Response to COOKIE ECHO chunks

 [ DETAILED DISCOVERY - PHASE 1: HOST & PORT BUILDING ]
    30. Top 1K Discovery .......[N]: Standard Top Services
    31. Windows ................[P]: RPC, SMB, RDP
    32. Linux ..................[P]: SSH, RPC, Web Mgmt
    33. Web Discovery ..........[P]: HTTP/S Title, Headers, Methods, Enum
    34. MGMT Ports .............[N]: SSH, Telnet, Web, VNC, SNMP, IPMI (Highly Monitored Ports)
    35. Database Discovery .....[P]: MSSQL, Oracle, MySQL, Postgres, NoSQL
    36. SCADA/ICS ..............[N]: Modbus, S7, BACnet, MQTT, Ethernet/IP

 [ EXTENDED SCANNING & AUDITS - PHASE 2 ONLY ]
    40. Aggressive Audit .......[N]: Scripts and Intense Versioning (Focus on Discovered Hosts/Ports)
    41. Anti-Throttling ........[S]: Slow & Steady (T2) with Randomized Targets
    42. Kitchen Sink ...........[N]: All Ports -p-

 [ SPECIALIZED - PHASE 1 & PHASE 2 ]
    50. Auto-Zombie Hunter .....[S]: Scan OS-Unknowns for Incremental IPID (Idle Scan Prep)
    51. Firewalk Scan ..........[N]: TTL Analysis to Gateway

 [ EVASION & SPOOFING - PHASE 1 & PHASE 2 ]
    60. Ghost Scan .............[E]: Decoy Army (RAND:10), MAC Spoof, & DNS Source Port
    61. Idle Scan ..............[E]: Decoy Army (RAND:10), MAC Spoof, & DNS Source Port
    62. Source Port Manip Scan .[E]: SRC Port Manipulation to evade FW (Trusted Ports ?)
    63. Fragmentation Scan .....[E]: IP Header Fragments (Packet Inspection ?)

 [ CUSTOM USER DEFINED SCAN - PHASE 1 -or- PHASE 2]
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
        "phases": [1],
        # -sn: No port scan (Discovery only)
        # -n: No dns resolution
        # -vv: Increased verbosity
        # -PE: Ping Echo
        # -PU: UDP Probe (port 40125)
        # -PS: TCP SYN Ping
        # -PA: TCP ACK Ping
        "flags": f"-sn -vv -PS{get_p(MGMT_TCP)} -PA21,23,80 -PU53 -PE", 
    },
    "02": {
        "name": "ACK 'Ping' Discovery",
        "category": "[S]",
        "phases": [1],
        # -sn: No port scan (Discovery only)
        # -n: No dns resolution
        # -vv: Increased verbosity
        # -PA uses TCP ACK Ping; we target common Win, Lin and MGMT ports
        "flags": f"-sn -n -vv -PA21,22,23,80,88,111,135,443,445,2049,3389", 
    },
    "03": {
        "name": "Local ARP Discovery",
        "category": "[S]",
        "phases": [1],
        # -PR: ARP Ping (Most reliable for local subnets)
        # -sn: No port scan (Discovery only)
        # -n: No dns resolution
        # -vv: Increased verbosity
        # --send-eth: Forces layer2 only
        # max-retries: Maximum retry attempts for host interaction
        "flags": "-sn -n -vv --send-eth --max-retries 0 -PR", 
    },
    "04": {
        "name": "Reverse DNS Lookup",
        "category": "[S]",
        "phases": [1],
        # -sL: List Scan (Resolves names, sends no packets to targets)
        # -vv: Increase verbosity
        "flags": "-sL -vv", 
    },
    "05": {
        "name": "Zombie Idle Discover",
        "category": "[S]",
        "phases": [1],
        # -Pn: No Ping
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sI: Idle scan
        "flags": "-Pn -n -vv -sI <zombie_ip> -p <target_ports>", 
    },
    # [ IPv6 Discovery ]
    "10": {
        "name": "IPv6 Link-Local",
        "category": "[N]",
        "phases": [1],
        # -6: Enable IPv6
        # -sn: Host discovery only (No port scan)
        #  -n: No DNS Resolution
        # -vv: Increased verbosity
        # ipv6-multicast-echo: Echo to ff02::1
        "flags": "-6 -sn -n -vv --script targets-ipv6-multicast-echo --script-args=newtargets", 
    },
    "11": {
        "name": "Neighbor Solicitation",
        "category": "[N]",
        "phases": [1],
        # -6: Enable IPv6
        # -sn: Host discovery only (No port scan)
        #  -n: No DNS Resolution
        "flags": "-6 -sn -n",
    },
    "12": {
        "name": "SLAAC Discovery",
        "category": "[N]",
        "phases": [1],
        # -6: Enable IPv6
        # -sn: Host discovery only (No port scan)
        # -vv: Increased verbosity
        # targets-ipv6-multicast-slaac: Auto configs via Router Advertisements
        "flags": "-6 -sn -vv --script targets-ipv6-multicast-slaac --script-args=newtargets",
    },
    "20": {
        "name": "SCTP INIT Ping",
        "category": "[N]",
        "phases": [1],
        # -PY: SCTP INIT Ping (Discovery only)
        # -sn: No port scan
        # -vv: Increased verbosity
        "flags": f"-sn -vv -PY{get_p(SCTP_PORTS)}",
    },
    "21": {
        "name": "SCTP INIT Scan",
        "category": "[N]",
        "phases": [1],
        # -PY: SCTP INIT Ping (Discovery only)
        # -sn: No port scan
        # -vv: Increased verbosity
        "flags": f"-sY -vv -p {get_p(SCTP_PORTS)}",
    },
    "22": {
        "name": "SCTP COOKIE Echo",
        "category": "[S]",
        "phases": [1],
        # -PY: SCTP INIT Ping (Discovery only)
        # -sn: No port scan
        # -vv: Increased verbosity
        "flags": f"-vv -sZ -p {get_p(SCTP_PORTS)}", 
    },
    # [ DETAILED DISCOVERY - PHASE 1 ]
    "30": {
        "name": "Top 1K Discovery",
        "category": "[N]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sS: Syn Scan only (no proxy support)
        # -- Top Ports 1000 (Default Top 1k ports)
        # --max-retries 0: Avoid delays on filtered ports
        "flags": "-n -vv -sS --top-ports 1000 --max-retries 1"
    },
    "31": {
        "name": "Windows Discovery",
        "category": "[P]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sT: Full TCP Connect scan {proxy friendly)
        # smb-os-discovery: If 445 is open ,this is a low cost/high value script
        "flags": f"-n -vv -sT -p {get_p(WINDOWS_PORTS)} --script smb-os-discovery"
    },
    "32": {
        "name": "Linux Discovery",
        "category": "[P]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sT: Full TCP Connect scan {proxy friendly)
        # ssh-hostkey: Provides value at 0 additional noise
        "flags": f"-n -vv -sT -p {get_p(LINUX_PORTS)} --script ssh-hostkey"
    },
    "33": {
        "name": "Web Discovery",
        "category": "[P]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sT: Full TCP Connect scan {proxy friendly)
        # http-title: Pulls Tag Title of page
        # http-headers: Pulls header of web server
        # max-parallelism: Wait for slow timeouts with web
        "flags": f"-n -vv -sT -p {get_p(WEB_PORTS)} --script http-title,http-headers,http-methods,http-enum --max-parallelism 20"
    },
    "34": {
        "name": "MGMT Ports",
        "category": "[N]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sS: Syn Scan only (no proxy support)
        "flags": f"-n -vv -sS -p {get_p(list(set(MGMT_TCP + MGMT_UDP)))}"
    },
    "35": {
        "name": "Database Discovery",
        "category": "[P]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sT: Full TCP Connect scan {proxy friendly)
        # banner: Safe technique bor DB banner retrieval
        "flags": f"-n -vv -sT -p {get_p(DB_TCP)} --script banner"
    },
    "36": {
        "name": "SCADA/ICS",
        "category": "[N]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sS: Syn Scan only (no proxy support)
        # max-retries: Maximum retry attempts for host interaction (scada is sensitive)
        # modbus-discover: Slave-ID checks (port T:502)
        # s7-info: metadata pull (port T:102)
        # enip-info: List identity request (port T:44818)
        # bacnet-info: ReadPoooroperty request (port U:47808)
        "flags": f"-n -vv -sS -T2 -p {get_p(list(set(SCADA_TCP + SCADA_UDP)))} --max-retries 1 --script modbus-discover,s7-info,enip-info,bacnet-info"
    },
    "37": {
        "name": "Anti-Throttling",
        "category": "[S]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sT: Full TCP Connect scan {IDS / IPS firendly)
        # data-length: Adds random to every packet
        # scan-delay: Adds delay between probes
        # host-time: Timeout of probe wait
        # max-retries: Maximum retry attempts for host interaction
        # randomize-hosts: randomize the target device to be probed
        "flags": "-n -vv -sT -T2 --scan-delay 1s --data-length 24 --host-timeout 5m --max-retries 1 --randomize-hosts"
    },
    "38": {
        "name": "Kitchen Sink",
        "category": "[N]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -sS: Syn Scan only (no proxy support)
        # min-rate: send atleast X number of packets per sec
        # max-rtt-timeout: timeout before moving on
        # max-retries: Maximum retry attempts for host interaction
        "flags": "-n -vv -sS -p- -T4 --min-rate 1000 --max-retries 1 --max-rtt-timeout 200ms"
    },
    "40": {
        "name": "Full Audit (Host-by-Host)",
        "category": "[N]",
        "phases": [2],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -A: OS (-O), versioning (-sV @ 7), safe scrits (-sC) and traceroute
        "flags": "-n -vv -sV --version-all -sC --script 'vuln,auth,default,discovery' --reason --script-trace",
    },
    "50": {
        "name": "Auto-Zombie Hunter",
        "category": "[S]",
        "phases": [1],
        # -n: No DNS Lookup
        # -vv: Increased verbosity
        # -p: only single port required open or closed
        # max-retries: Maximum retry attempts for host interaction
        # --script ipidseq: Specifically flags Idle Scan candidates
        "flags": f"-n -v -O -p20-23,80,443,445,515,631,9100-9102",
    },
    "51": {
        "name": "Firewalk Discovery",
        "category": "[S]",
        "phases": [1],
        "flags": "", # Handled dynamically by the firewalker module
    },
    "99": {
        "name": "User Defined Option",
        "category": "[?]",
        "phases": [1, 2],  # Default to 1, user can specify flags
        "flags": None, # This will be filled by main.py
    }
}
