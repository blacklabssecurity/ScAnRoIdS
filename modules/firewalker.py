#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module:  modules/firewalker.py
Purpose: Tool to stage firewalking efforts against a specified single target.
         Stage 1 gathers the ttl to the destination while stage 2 attempts to 
         test and evaluate ttl+1 queries.
"""

import re
import time
import subprocess
from core.ui import (
    log_task, log_success, log_error, log_note,
    log_warn, YELLOW, RESET, BLUE, BOLD
    )
from core.system import INTERFACE, nmap_to_bpf

def run_firewalk(ctx, target_ip):
    """
    Multi-stage logic to determine TTL and execute firewalking.
    Stage 1: Traceroute to find the last hop before target.
    Stage 2: Firewalk using (Hop + 1) to probe through the firewall.
    """
    # --- 0. Setup Naming and Packet Capture ---
    t_proc = None
    file_base = f"firewalk_{target_ip.replace('.','-')}_{ctx.date_str}_{ctx.time_str}"
    pcap_path = ctx.dirs['pcap'] / f"{file_base}.pcapng"

    # Surgical BPF: Target IP + ICMP (for TTL Exceeded) + TCP/UDP (for probes)
    ip_bpf = nmap_to_bpf(target_ip)
    cap_filter = f"({ip_bpf}) and (icmp or icmp6 or tcp or udp)"

    t_cmd = ["tshark", "-i", INTERFACE, "-w", str(pcap_path), "-f", cap_filter, "-q"]

    print(f"\n{YELLOW}--- [ FIREWALK PACKET CAPTURE ] ---{RESET}")
    # THE ECHO: Displaying the command to the operator
    log_task(f"Capture Start: {pcap_path.name}")
    log_task(f"Executing: {' '.join(t_cmd)}")
    log_note(f"Wireshark filter: {RESET}'ip.addr == {target_ip} && (icmp.type == 11)'")

    t_proc = subprocess.Popen(t_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) # Warmup


    try:
        # --- STAGE 1: TRACEROUTE ---
        log_task(f"Stage 1: Determining Hop Count to {target_ip}...")

        # We use -sn --traceroute for a fast ICMP/TCP hop discovery
        trace_cmd = ["nmap", "-sn", "--traceroute", target_ip]
        log_task(f"Executing: {' '.join(trace_cmd)}")

        try:
            proc = subprocess.run(trace_cmd, capture_output=True, text=True, timeout=60)

            # REGEX: Matches the hop number at the start of a line followed by the RTT (ms)
            # ^\s*(\d+)   : Start of line, optional spaces, capture the hop digit
            # \s+[\d\.]+  : Mandatory space followed by the RTT value (e.g. 0.45)
            # \s+ms       : Mandatory space followed by 'ms'
            hops = re.findall(r"^\s*(\d+)\s+[\d\.]+\s+ms", proc.stdout, re.MULTILINE)

            if not hops:
                # Only trigger 'SAME SUBNET' if we've explicitly checked local connectivity
                # and still found 0 intermediate hops.
                if "Host is up" in proc.stdout and "TRACEROUTE" not in proc.stdout:
                    log_success(f"Target {target_ip} is on the SAME SUBNET (0 hops).")
                    return "SKIPPED (Local Target)"
                elif "Host is up" in proc.stdout and "TRACEROUTE" in proc.stdout:
                    log_error("Traceroute table was found but regex failed to parse hops.")
                    return "FAILED (Parse Error)"
                else:
                    log_error("Target unreachable or traceroute failed.")
                    return "FAILED (Traceroute Error)"

            # Calculate TTL: The firewall is the last hop, so we test the target at (Hop + 1)
            last_hop = int(hops[-1])
            target_ttl = last_hop + 1
            log_success(f"Firewall detected at hop {last_hop}. Testing TTL {target_ttl}...")

            # --- STAGE 2: FIREWALK ---
            # Setup artifact pathing
            file_base = f"firewalk_{target_ip.replace('.','-')}_{ctx.date_str}_{ctx.time_str}"
            xml_path = ctx.dirs['artifacts'] / f"{file_base}.xml"
            log_task(f"Stage 2: Firewalk TTL {target_ttl} Probing...")

            # --ttl: Forces the packet to expire exactly at the target
            # --script firewalk: Checks if packets are dropped or passed
            fire_cmd = [
                "nmap", "-Pn", "--ttl", str(target_ttl), 
                "--script", "firewalk", 
                "--script-args", "firewalk.max-retries=1",
                "-oX", str(xml_path),
                "--reason", target_ip
            ]

            log_task(f"Executing: {' '.join(fire_cmd)}")
            subprocess.run(fire_cmd, capture_output=True, text=True)

            # --- STAGE 3: ANALYSIS ---
            return _analyze_firewalk_xml(xml_path)

        except Exception as e:
            log_error(f"Firewalk execution error: {e}")
            return "FINISHED (Error)"

    except Exception as e:
        log_error(f"Firewalk Module Outer Error: {e}")
        return "FINISHED (Init Error)"

    finally:
        # Ensure Tshark is always closed
        if 't_proc' in locals():
            t_proc.terminate()
            log_note(f"Capture Closed: {pcap_path.name}")


def _analyze_firewalk_xml(xml_path):
    """Surgical check of the XML for leaking vs filtered ports."""
    import xml.etree.ElementTree as ET

    if not xml_path.exists():
        return "FINISHED (XML Missing)"

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        found_open = False
        found_filtered = False

        for port in root.findall('.//port'):
            state_node = port.find('state')
            if state_node is not None:
               state = state_node.get('state')
               if state == 'open':
                    found_open = True
                    port_id = port.get('portid')
                    log_success(f"FIREWALK SUCCESS: Port {port_id} is LEAKING traffic at this TTL!")
               elif state == 'filtered':
                    found_filtered = True

        if found_open:
            return "SUCCESS: [OPEN] Firewall is LEAKING!"
        elif found_filtered:
            log_warn("FIREWALK: All probed ports are [FILTERED] (Firewall is blocking).")
            return "FINISHED (WARNING: [FILTERED] Dropping Packets)"
        else:
            return "FINISHED (No Open Paths Found)"

    except Exception as e:
        log_error(f"Analysis Error: {e}")
        return "FINISHED (Analysis Error)"
