#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: config.py
Purpose: Authoritative course menu, typed port groups and declarative scan profiles.
"""

from core.ui import BLUE, BOLD, RESET, YELLOW

DC_PORTS = {88, 389, 636, 3268, 3269, 9389}
INTERESTING_PORTS = {
    21,
    22,
    23,
    69,
    80,
    111,
    161,
    443,
    445,
    500,
    1433,
    2049,
    2222,
    3389,
    5900,
}
DB_PORTS = [1433, 1521, 3050, 3306, 5432, 5984, 6379, 9042, 11211, 27017, 33060]
MGMT_TCP = [
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    88,
    135,
    389,
    443,
    445,
    465,
    587,
    636,
    3389,
    5985,
    5986,
    8080,
    8443,
]
MGMT_UDP = [53, 67, 69, 123, 161, 500, 623]
WEB_PORTS = [
    80,
    443,
    3000,
    3128,
    4443,
    5000,
    5001,
    7001,
    7002,
    8000,
    8080,
    8081,
    8118,
    8443,
    8888,
    9000,
    9090,
    9443,
    10000,
]
SCADA_TCP = [102, 500, 502, 1883, 4840, 8883, 9600, 20000, 44818]
SCADA_UDP = [2222, 9600, 20000, 47808]
LINUX_PORTS = [22, 111, 2049, 3306, 5432]
WINDOWS_TCP_PORTS = [135, 137, 139, 445, 3389, 5985, 5986]
WINDOWS_UDP_PORTS = [135, 137, 138, 389]
SCTP_PORTS = [80, 443, 2905, 3868, 7879, 5060, 5061, 7083, 7850, 38412]
SMB_TCP_PORTS = [139, 445]
SMB_UDP_PORTS = [137, 138]
NFS_TCP_PORTS = [111, 2049, 20048]
IRC_PORTS = [194, 6667, 6697]
# Compatibility names for third-party adapters written against the earlier project.
DB_TCP = DB_PORTS
WINDOWS_PORTS = WINDOWS_TCP_PORTS
GREEDY_MODE = False
AUTO_LOOT_SHARES = ["Public", "Backups", "Users"]


def get_p(ports):
    return ",".join(str(p) for p in sorted(set(ports)))


def profile(
    name,
    flags,
    *,
    phase=1,
    capture="scope",
    scripts=(),
    root=True,
    local=False,
    discovery=False,
):
    return dict(
        name=name,
        flags=flags,
        phases=[phase],
        capture=capture,
        scripts=list(scripts),
        root=root,
        local=local,
        discovery=discovery,
    )


SCAN_LIBRARY = {
    "01": profile(
        "Aggressive Discovery",
        "-sn -vv -PS22,80,443 -PA21,23,80 -PU53 -PE",
        discovery=True,
    ),
    "02": profile(
        "ACK Discovery",
        "-sn -n -vv -PA21,22,23,80,88,111,135,443,445,2049,3389",
        discovery=True,
    ),
    "03": profile(
        "Local ARP Discovery",
        "-sn -n -vv -PR --send-eth",
        capture="arp",
        local=True,
        discovery=True,
    ),
    "04": profile("Reverse DNS Lookup", "-sL -vv", capture="dns", root=False, discovery=True),
    "05": profile("Zombie Idle Discover", "-Pn -n -vv", capture="zombie"),
    "10": profile("NULL Scan", "-n -vv -sN"),
    "11": profile("XMAS Scan", "-n -vv -sX"),
    "12": profile("FIN Scan", "-n -vv -sF"),
    "13": profile("SYN/FIN Scan", "-n -vv -sS --scanflags SYNFIN"),
    "14": profile("Custom Flags Scan", "-n -vv -sS"),
    "20": profile(
        "IPv6 Link-Local",
        "-6 -sn -n -vv --script targets-ipv6-multicast-echo --script-args newtargets",
        capture="icmp6",
        scripts=["targets-ipv6-multicast-echo"],
        local=True,
        discovery=True,
    ),
    "21": profile(
        "Neighbor Solicitation",
        "-6 -sn -n -vv",
        capture="icmp6",
        local=True,
        discovery=True,
    ),
    "22": profile(
        "SLAAC Discovery",
        "-6 -sn -n -vv --script targets-ipv6-multicast-slaac --script-args newtargets",
        capture="icmp6",
        scripts=["targets-ipv6-multicast-slaac"],
        local=True,
        discovery=True,
    ),
    "23": profile("IPv6 List Scan", "-6 -sL -vv", capture="dns", root=False, discovery=True),
    "30": profile(
        "SCTP INIT Ping",
        f"-sn -n -vv -PY{get_p(SCTP_PORTS)}",
        capture="sctp",
        discovery=True,
    ),
    "31": profile("SCTP INIT Scan", f"-n -vv -sY -p {get_p(SCTP_PORTS)}", capture="sctp"),
    "32": profile("SCTP Cookie Echo", f"-n -vv -sZ -p {get_p(SCTP_PORTS)}", capture="sctp"),
    "33": profile(
        "EIGRP Discovery",
        "-sn -n -vv --script broadcast-eigrp-discovery",
        capture="eigrp",
        scripts=["broadcast-eigrp-discovery"],
        local=True,
        discovery=True,
    ),
    "34": profile(
        "OSPF Discovery",
        "-sn -n -vv --script broadcast-ospf2-discover",
        capture="ospf",
        scripts=["broadcast-ospf2-discover"],
        local=True,
        discovery=True,
    ),
    "40": profile("Top 1K Discovery", "-n -vv -sS --top-ports 1000", capture="discovery"),
    "41": profile(
        "Windows Discovery",
        f"-n -vv -sT -p {get_p(WINDOWS_TCP_PORTS)}",
        capture="discovery",
        root=False,
    ),
    "42": profile(
        "Linux Discovery",
        f"-n -vv -sT -p {get_p(LINUX_PORTS)} --script ssh-hostkey",
        capture="discovery",
        scripts=["ssh-hostkey"],
        root=False,
    ),
    "43": profile(
        "Web Discovery",
        f"-n -vv -sT -p {get_p(WEB_PORTS)} --script http-title,http-headers,http-methods,http-enum",
        capture="discovery",
        scripts=["http-title", "http-headers", "http-methods", "http-enum"],
        root=False,
    ),
    "44": profile(
        "Management Discovery",
        f"-n -vv -sS -sU -p T:{get_p(MGMT_TCP)},U:{get_p(MGMT_UDP)}",
        capture="discovery",
    ),
    "45": profile(
        "Database Discovery",
        f"-n -vv -sT -p {get_p(DB_PORTS)} --script banner",
        capture="discovery",
        scripts=["banner"],
        root=False,
    ),
    "46": profile(
        "SCADA/ICS Discovery",
        f"-n -vv -sS -sU -T2 --max-retries 1 -p T:{get_p(SCADA_TCP)},U:{get_p(SCADA_UDP)}",
        capture="discovery",
    ),
    "50": profile(
        "Aggressive Audit",
        "-Pn -n -vv -sV --version-all --script vuln,auth,default,discovery --script-trace",
        phase=2,
    ),
    "51": profile(
        "Anti-Throttling Audit",
        "-Pn -n -vv -sV -T2 --scan-delay 1s --max-retries 1",
        phase=2,
    ),
    "52": profile("Kitchen Sink", "-Pn -n -vv -sS -p-", phase=2),
    "60": profile(
        "Auto-Zombie Hunter",
        "-n -vv -O --script ipidseq -p 20-23,80,443,445,515,631,9100-9102",
        scripts=["ipidseq"],
    ),
    "61": profile(
        "Firewalk",
        "-Pn -n -vv -sS --traceroute --script firewalk",
        scripts=["firewalk"],
    ),
    "70": profile("Ghost Scan", "-n -vv -sS -D RAND:10 --spoof-mac 0 -g 53"),
    "71": profile("Idle Scan", "-Pn -n -vv", capture="zombie"),
    "72": profile("Source Port Manipulation", "-n -vv -sS"),
    "73": profile("Fragmentation Scan", "-n -vv -sS -f"),
    "99": profile("User Defined Scan", "-n -vv", root=False),
}

# Copy suggestions are selected by (protocol, port) in the application. These TCP
# suggestions are deliberately explicit and checked against local NSE availability.
TACTICAL_SUGGESTIONS = {
    21: "--script ftp-anon,ftp-syst",
    22: "--script ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
    23: "--script telnet-encryption",
    25: "--script smtp-commands,smtp-ntlm-info",
    80: "--script http-title,http-headers,http-methods,http-enum",
    443: "--script ssl-cert,ssl-enum-ciphers,ssl-date",
    135: "--script msrpc-enum",
    445: "--script smb-os-discovery,smb-enum-shares,smb-enum-users",
    111: "--script rpcinfo",
    2049: "--script nfs-showmount,nfs-ls,nfs-statfs",
    1433: "--script ms-sql-info,ms-sql-ntlm-info",
    1521: "--script oracle-tns-version",
    3306: "--script mysql-info",
    5432: "--script banner",
    6379: "--script redis-info",
    27017: "--script mongodb-info",
    3389: "--script rdp-ntlm-info,rdp-enum-encryption",
    5900: "--script vnc-info",
    5985: "--script http-title,http-headers",
    102: "--script s7-info",
    502: "--script modbus-discover",
    44818: "--script enip-info",
}
UDP_SUGGESTIONS = {
    53: "--script dns-recursion",
    123: "--script ntp-info",
    161: "--script snmp-info,snmp-sysdescr",
    47808: "--script bacnet-info",
}


def get_banner():
    """The supplied specification's menu text and numbering are preserved verbatim."""
    banner = f"""
{BLUE}{BOLD}| ============================== - S - c - A - n - R - o - I - d - S - =============================== |{RESET}

 [ GENERAL DISCOVERY - HOST BUILDING ONLY ]
    01. Aggressive Discovery ...[N]: SYN/ACK/UDP/ICMP Egress Techniques
    02. ACK Discovery ..........[N]: TCP ACK Ping (Stateless Firewall Check)
    03. Local ARP Discovery ....[N]: Layer 2 MAC Discovery-Local Subnet Only (Need [S]: arp -a)
    04. Reverse DNS Lookup .....[S]: Query Hostnames via Specific DNS Server
    05. Zombie Idle Discover ...[S]: Blind Stealth Scan (Need Zombie? Try Scan 60)

 [ Inverse TCP DISCOVERY - HOST BUILDING ONLY (Non-Windows Targets Suggested) ]
    10. NULL Scan ..............[E]: Empty TCP Flags (-sN)
    11. XMAS Scan ..............[E]: FIN, URG, PSH Flags Set (-sX)
    12. FIN Scan ...............[E]: FIN Flag Set (-sF)
    13. SYN/FIN Scan ...........[E]: SYN and FIN Flags (Older Firewalls) (--scanflags SYNFIN)
    14. Custom Flag(s) Scan ....[E]: Get Creative: FN, SYN, RST, PSH, ACK, URG

 [ IPv6 DISCOVERY - HOST BUILDING ONLY ]
    20. IPv6 Link-Local ........[N]: Multicast Ping ff02::1 (Default Interface)
    21. Neighbor Solicitation ..[N]: ICMPv6 Ping Sweep (Need [S]: ip - neighbor show)
    22. SLAAC Discovery ........[N]: Stateless Address Autoconfiguration (SLAAC) requests
    23. IPv6 List Scan (ToDo)...[N]: DNS Query of provided IPv6 Range (Silent to Targets)

 [ NETWORK DEVICE DISCOVERY - HOST BUILDING ONLY ]
    30. SCTP INIT Ping .........[N]: Ping Probe for Host Discovery Only
    31. SCTP INIT Scan .........[N]: Half-Open Probe to 4-way Handshake (Older Firewalls)
    32. SCTP Cookie Echo........[S]: Analyze the Response to COOKIE ECHO chunks
    33. EIGRP Discovery ........[N]: Sends EIGRP Hello Packets to multicast 224.0.0.10
    34. OSPF Discovery .........[N]: Sends OSPF Hello Packets to multicast 224.0.0.5

 [ DETAILED DISCOVERY - HOST & PORT BUILDING ]
    40. Top 1K Discovery .......[N]: Standard Top Services
    41. Windows Discovery ......[P]: RPC, SMB, RDP
    42. Linux Discovery ........[P]: SSH, RPC, Web Mgmt
    43. Web Discovery ..........[P]: HTTP/S Title, Headers, Methods, Enum
    44. MGMT Discovery .........[N]: SSH, Telnet, Web, VNC, SNMP, IPMI (Highly Monitored Ports)
    45. Database Discovery .....[P]: MSSQL, Oracle, MySQL, Postgres, NoSQL
    46. SCADA/ICS Discovery ....[N]: Modbus, S7, BACnet, MQTT, Ethernet/IP

 [ EXTENDED SCANNING & AUDITS - PHASE 2 ONLY ]
    50. Aggressive Audit .......[N]: Scripts and Intense Versioning (Focus on Discovered Hosts/Ports)
    51. Anti-Throttling ........[S]: Slow & Steady (T2) with Randomized Targets
    52. Kitchen Sink ...........[N]: All Ports -p-

 [ SPECIALIZED SCANS ]
    60. Auto-Zombie Hunter .....[N]: Scan OS-Unknowns for Incremental IPID (Idle Scan Prep)
    61. Firewalk Scan ..........[N]: TTL Analysis to Gateway

 [ EVASION & SPOOFING - PHASE 1 & PHASE 2 ]
    70. Ghost Scan .............[E]: Decoy Army (RAND:10), MAC Spoof, & DNS Source Port
    71. Idle Scan ..............[E]: Decoy Army (RAND:10), MAC Spoof, & DNS Source Port
    72. Source Port Manip ......[E]: SRC Port Manipulation to evade FW (Trusted Ports ?)
    73. Fragmentation Scan .....[E]: IP Header Fragments (Packet Inspection ?)

 [ CUSTOM USER DEFINED SCAN - PHASE 1 -or- PHASE 2]
    99. User Defined Option ....[?]: Enter your own flags...

 [ TERMINATE EXECUTION ]
     q. Nevermind ..................: Wait, Why am I here???

{BLUE}{BOLD}| ==================================================================================================== |{RESET}

{YELLOW}NOTES:{RESET}
*** Scans noted with a {YELLOW}[P]roxy{RESET} can be executed through Proxychains: Full TCP Connection (-sT).   ***
*** Scans noted with a {YELLOW}[E]vasive{RESET} make attemps to disguise the layer 2 and 3 source.              ***
*** Scans noted with a {YELLOW}[N]oisey{RESET} can be extremely loud on the net. Want stealth? This ain't it... ***
*** Scans noted with a {YELLOW}[S]ilent{RESET} are less intrusive. Discovery through passive segemnt traffic.   ***

    {YELLOW}Running a version scan (-sV) as sudo/root will defalut to a -sS scan before version checking!
    This script requires sudo/root, so DO NOT leverage Proxychains with -sV ONLY! {RESET}

{BLUE}{BOLD}| ==================================================================================================== |{RESET}

"""
    return banner


"""
INPUT: Operator scan menu ID and typed port registries.
OUTPUT: Declarative profiles; no commands execute during import.
"""
