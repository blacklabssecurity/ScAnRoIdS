# ==============================================================================
# SCRIPT: orchestrator.py
# PURPOSE: Menu Logic, Target Consolidation, and Specialized Scan Dispatcher
# ==============================================================================

import os, sys, subprocess, re, threading, time
from datetime import datetime
from engine import execute_subprocess_with_logging, run_scan, is_local_target
from surgeon import parse_and_sync_results, trigger_external_tools

BLUE, YELLOW, GREEN, RED, BOLD, RESET = "\033[94m", "\033[93m", "\033[92m", "\033[91m", "\033[1m", "\033[0m"

def handle_scan_logic(choice, DEFAULT_IFACE, LOCAL_IPS, BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock, scans):
    """The central switchboard that prepares and launches every scan type."""
    
    file_prefix = f"{CUSTOMER}_{DATE_STR}_scan_{choice}"
    nmap_out_base = os.path.join(BASE_DIR, f"{file_prefix}_discovery")
    exclude_flag = f"--exclude {LOCAL_IPS}" if LOCAL_IPS else ""
    perf_switches = ""
    
    # --- 1. TARGET CONSOLIDATION LOGIC ---
    if choice in ["03", "06", "07"]:
        # Auto-detect local subnet
        try:
            cmd = f"ip -4 addr show {DEFAULT_IFACE} | grep -oP '(?<=inet\\s)\\S+'"
            target_cmd = subprocess.check_output(cmd, shell=True, text=True).strip()
            print(f"{YELLOW}[*]{RESET} Detected Local Subnet: {target_cmd}")
        except:
            target_cmd = ".".join(LOCAL_IPS.split('.')[:-1]) + ".0/24"
        target_in = target_cmd
    else:
        target_in = input(f"\n{YELLOW}[?]{RESET} Enter Target (IP, Subnet, or File Path): ").strip()
        target_cmd = f"-iL {target_in}" if os.path.exists(target_in) else target_in

    # --- 2. PROCESS CHOICE LOGIC ---
    final_cmd = "Initializing..."

    # Choice 03: ARP Discovery
    if choice == "03":
        if any(x in DEFAULT_IFACE.lower() for x in ["tun", "ppp"]):
            print(f"\n{RED}[!] WARNING:{RESET} ARP Scanning on VPN interface '{DEFAULT_IFACE}' will likely fail.")
            if input(f"{YELLOW}[?]{RESET} Proceed anyway? (y/n): ").lower() != 'y': os._exit(0)
        
        final_cmd = f"nmap -sn -PR {target_cmd} -oA '{nmap_out_base}' --reason"
        threading.Thread(target=run_scan, args=(choice, target_cmd, exclude_flag, "", file_prefix, BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock), daemon=True).start()

    # Choice 04: Reverse DNS Lookup
    elif choice == "04":
        dns_server = input(f"{YELLOW}[?]{RESET} Enter DNS Server IP to query: ").strip()
        target_cmd = f"{target_cmd} --dns-servers {dns_server}"
        final_cmd = f"nmap -sL {target_cmd} -oA '{nmap_out_base}'"
        threading.Thread(target=run_scan, args=(choice, target_cmd, exclude_flag, "", file_prefix, BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock), daemon=True).start()

    # Choice 05: Zombie Idle Scan
    elif choice == "05":
        zombie_input = input(f"{YELLOW}[?]{RESET} Enter Zombie Host (IP or IP:PORT): ").strip()
        target_ports = input(f"{YELLOW}[?]{RESET} Enter Target Port(s): ").strip()
        zombie_ip, zombie_port = (zombie_input.split(':') + ["80"])[:2]
        
        print(f"{YELLOW}[*]{RESET} Checking {zombie_ip}:{zombie_port} suitability...")
        check_cmd = f"nmap -O -v -p {zombie_port} --max-retries 1 --host-timeout 30s {zombie_ip}"
        proc = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        
        if "Incremental" in proc.stdout and "open" in proc.stdout:
            print(f"{GREEN}[+]{RESET} SUCCESS: {zombie_ip} is suitable.")
        else:
            if input(f"{RED}[!] WARNING:{RESET} Suitability check failed. Attempt anyway? (y/n): ").lower() != 'y': os._exit(0)

        scans["05"]["discovery"] = f"-Pn -vv -sI {zombie_ip}:{zombie_port} -p {target_ports}"
        final_cmd = f"nmap {scans['05']['discovery']} {target_cmd} -oA '{nmap_out_base}' --reason --open"
        threading.Thread(target=run_scan, args=(choice, target_cmd, exclude_flag, "", file_prefix, BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock), daemon=True).start()

    # Choice 06: IPv6 Link-Local
    elif choice == "06":
        final_cmd = scans["06"]["cmd"].format(IFACE=DEFAULT_IFACE)
        def ipv6_auto_sequence(cmd):
            execute_subprocess_with_logging(cmd, live_logs, completion_lock)
            time.sleep(2)
            proc = subprocess.run("ip neighbor", shell=True, capture_output=True, text=True)
            
            with completion_lock:
                res_dict = dashboard_data.get('results_dict', {})
                for line in proc.stdout.splitlines():
                    match = re.match(r"^([a-fA-F0-9\.:]+)\s+dev", line)
                    if match:
                        ip = match.group(1)
                        if ip not in res_dict:
                            res_dict[ip] = {"host": ip, "os": "IPv6 Discovery", "port": "N/A", "service": "Host Discovery", "raw_ttl": 0, "ttl_display": "N/A", "css_class": ""}
                dashboard_data['results_dict'] = res_dict
                dashboard_data['results'] = list(res_dict.values())
                dashboard_data['host_count'] = len(set(d['host'] for d in dashboard_data['results']))
            
            dashboard_data['status'] = "FINISHED (IPv6 Discovery Complete)"
            dashboard_data['scan_active'] = False
        threading.Thread(target=ipv6_auto_sequence, args=(final_cmd,), daemon=True).start()

    # Choice 07: Neighbor Solicitation
    elif choice == "07":
        final_cmd = "ip neighbor"
        def neighbor_wrapper():
            print(f"{BLUE}[*]{RESET} Accessing Local Neighbor Cache...")
            proc = subprocess.run("ip neighbor", shell=True, capture_output=True, text=True)
            new_ips = set()
            
            with completion_lock:
                res_dict = dashboard_data.get('results_dict', {})
                for line in proc.stdout.splitlines():
                    live_logs.append(line)
                    match = re.match(r"^([a-fA-F0-9\.:]+)\s+dev", line)
                    if match:
                        ip = match.group(1)
                        new_ips.add(ip)
                        if ip not in res_dict:
                            res_dict[ip] = {
                                "host": ip, "os": "Neighbor Cache", "port": "N/A", 
                                "service": "Host Discovery", "raw_ttl": 0, "css_class": ""
                            }
                dashboard_data['results_dict'] = res_dict
                dashboard_data['results'] = list(res_dict.values())
                dashboard_data['host_count'] = len(res_dict)

            # High-speed batch write
            h_file = os.path.join(BASE_DIR, "hosts_all.txt")
            with open(h_file, "a") as f:
                for ip in new_ips: f.write(f"{ip}\n")

            dashboard_data['status'] = "FINISHED (Neighbor Cache Dump)"
            dashboard_data['scan_active'] = False
            print(f"{GREEN}[+]{RESET} Neighbor Discovery Complete. {len(new_ips)} targets synced.")

        threading.Thread(target=neighbor_wrapper, daemon=True).start()

    # Choice 18: Auto-Zombie Hunter
    elif choice == "18":
        unknown_file = os.path.join(BASE_DIR, "hosts_OS-unknown.txt")
        if not os.path.exists(unknown_file) or os.path.getsize(unknown_file) == 0:
            print(f"\n{RED}[!] ERROR:{RESET} No OS-Unknowns found. Run discovery first.")
            os._exit(0)
        
        def zombie_hunter_thread():
            with open(unknown_file, 'r') as f:
                targets = f.read().splitlines()
            
            found_count = 0
            for i, ip in enumerate(targets):
                with completion_lock:
                    dashboard_data['status'] = f"Hunting Zombies ({i+1}/{len(targets)})..."
                
                cmd = f"nmap -O -v --max-retries 0 --host-timeout 20s {ip}"
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "Incremental" in proc.stdout:
                    found_count += 1
                    with open(os.path.join(BASE_DIR, "zombie_candidates.txt"), "a") as zf:
                        zf.write(f"{ip}\n")
                    live_logs.append(f"[+] ZOMBIE FOUND: {ip}")

            dashboard_data['status'] = f"FINISHED ({found_count} Zombies Found)"
            dashboard_data['scan_active'] = False

        threading.Thread(target=zombie_hunter_thread, daemon=True).start()
        final_cmd = "Initializing Zombie Hunter..."

    # Choice 19: Firewalk
    elif choice == "19":
        from ScAnRoIdS import execute_firewalk # Ensure main script has this
        final_cmd = f"nmap -sn --traceroute {target_in}"
        fire_args = (target_in, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs)
        threading.Thread(target=execute_firewalk, args=fire_args, daemon=True).start()

    # Choice 20: Ghost Scan
    elif choice == "20":
        # Helper check (assuming imported from engine or defined locally)
        from engine import is_local_target 
        
        decoy_flag = "-D RAND:10,ME"
        spoof_flag = "--spoof-mac 0" if is_local_target(target_in, LOCAL_IPS) else ""
        scans["20"]["discovery"] = f"-sS -Pn -T2 {decoy_flag} {spoof_flag} -g 53 --data-length 24"
        
        final_cmd = f"nmap {scans['20']['discovery']} {target_cmd} -oA '{nmap_out_base}' --reason --open"
        threading.Thread(target=run_scan, args=(choice, target_cmd, exclude_flag, "", file_prefix, BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock), daemon=True).start()

    # Choice 99: User Defined
    elif choice == "99":
        user_flags = input(f"{YELLOW}[?]{RESET} Enter nmap flags: ").strip()
        ipv6_f = "-6" if ":" in target_in and "-6" not in user_flags else ""
        final_cmd = f"nmap {ipv6_f} {user_flags} {exclude_flag} {target_cmd} -oA '{nmap_out_base}' --reason --open"
        
        def manual_wrapper(cmd, xml_f, c_val):
            execute_subprocess_with_logging(cmd, live_logs, completion_lock)
            parse_and_sync_results(xml_f, dashboard_data, BASE_DIR)
            trigger_external_tools(xml_f, c_val, BASE_DIR, CUSTOMER, DATE_STR, dashboard_data, live_logs)
            dashboard_data['scan_active'] = False

        threading.Thread(target=manual_wrapper, args=(final_cmd, f"{nmap_out_base}.xml", choice), daemon=True).start()

    else:
        if choice in ["08", "11", "12"]: 
            if input(f"\n{YELLOW}[!] Add performance switches? (y/n): ").lower() == 'y':
                perf_switches = "--min-hostgroup 64 --min-parallelism 100 --min-rate 1000"
        
        disc_flags = scans[choice]["discovery"]
        actual_nmap_syntax = f"nmap {disc_flags} {exclude_flag} {perf_switches} {target_cmd} -oA '{nmap_out_base}' --reason --open"
        threading.Thread(target=run_scan, args=(choice, target_cmd, exclude_flag, perf_switches, file_prefix, BASE_DIR, CUSTOMER, DATE_STR, CURRENT_USER, dashboard_data, live_logs, completion_lock), daemon=True).start()

    # --- 3. FINAL DASHBOARD SYNC ---
    dashboard_data["meta_cmd"] = actual_nmap_syntax
    dashboard_data["meta_time"] = datetime.now().strftime('%H:%M:%S')
    
    return actual_nmap_syntax
