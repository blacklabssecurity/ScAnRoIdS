#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  core/system.py
Purpose: Gathers system-level telemetry, identifies the real operator, 
         maps network interfaces, and tracks VPN connection states.
"""

import os
import re
import fcntl
import socket
import struct
import getpass
import subprocess


def get_operator():
    """Identifies the actual user even when running under sudo."""
    return os.environ.get('SUDO_USER', getpass.getuser())


def get_local_ips():
    """Retrieves all assigned IP addresses for the --exclude flag."""
    try:
        output = subprocess.check_output("hostname -I", shell=True, text=True)
        return output.strip().split()
    except Exception:
        return []


def get_default_interface():
    """Determines the primary interface used for routing."""
    try:
        cmd = "ip route get 8.8.8.8 | grep -Po '(?<=dev )\\S+'"
        iface = subprocess.check_output(cmd, shell=True, text=True).strip()
        return iface if iface else "eth0"
    except Exception:
        return "eth0"


def get_interface_ip(ifname):
    """
    Retrieves the IPv4 address assigned to a specific interface name.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 0x8915 is the SIOCGIFADDR constant to get the interface address
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        # Fallback to 0.0.0.0 if the interface has no IP or error occurs
        return "0.0.0.0"


def check_vpn_state(iface, ips):
    """
    Determines if the system is currently routing via a VPN tunnel.
    Heuristics: Interface name (tun/tap/wg) or specific IP ranges.
    """
    vpn_prefixes = ['tun', 'tap', 'ppp', 'wg', 'vpn']
    is_vpn_iface = any(prefix in iface.lower() for prefix in vpn_prefixes)

    # Check for common VPN IP subnets (e.g., 10.8.0.0/24)
    is_vpn_ip = any(ip.startswith(('10.8.', '172.16.', '10.255.')) for ip in ips)

    return is_vpn_iface or is_vpn_ip


def nmap_to_bpf(target_str):
    """
    Converts Nmap shorthand (ranges, lists) into Tshark BPF syntax.
    """
    target_str = target_str.strip()

    # 1. Handle Standard CIDR (192.168.1.0/24)
    if "/" in target_str:
        return f"net {target_str}"

    # 2. Handle Simple Host or IP (192.168.1.1)
    if not any(char in target_str for char in "-,"):
        return f"host {target_str}"

    # 3. Handle Nmap Shorthand (192.168.1.1-8 or 192.168.1.3,6,9)
    # Regex: Matches Prefix (192.168.1) and Suffix (1-8 or 3,6,9)
    match = re.match(r"([\d\.]+)\.([\d\-\,]+)", target_str)
    if match:
        prefix, suffix = match.group(1), match.group(2)
        ips = []

        # Split by comma first (3,6,9)
        for part in suffix.split(','):
            if '-' in part: # Handle Range (1-8)
                start, end = map(int, part.split('-'))
                for i in range(start, end + 1):
                    ips.append(f"{prefix}.{i}")
            else: # Handle Single (3)
                ips.append(f"{prefix}.{part}")

        return " or ".join([f"host {ip}" for ip in ips])

    # Fallback for complex strings
    return f"host {target_str}"


# --- EXPORTED SYSTEM STATE ---
OPERATOR     = get_operator()
ALL_IPS      = get_local_ips()
LOCAL_IPS    = ",".join(ALL_IPS)
INTERFACE    = get_default_interface()
INTERFACE_IP = get_interface_ip(INTERFACE)
IS_VPN       = check_vpn_state(INTERFACE, ALL_IPS)
