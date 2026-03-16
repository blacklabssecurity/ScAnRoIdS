#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  modules/searchsploit.py
Purpose: Automated exploit mapping based on Nmap service/kernel strings.
"""

import subprocess
from core.ui import log_note, log_task, log_success, log_error, YELLOW, RESET, BLUE, CYAN, RED, BULLET


def run_search(ctx, service_string, ip="Unknown"):
    """
    Executes searchsploit and appends to the session exploit log with IP context.
    """
    if not service_string or "unknown" in service_string.lower():
        return

    outfile = ctx.dirs['artifacts'] / f"searchsploit_{ctx.customer}_{ctx.date_str}.txt"
    cmd = ["searchsploit", service_string]

    # Terminal Output
    print(f"\n{YELLOW}--- [ EXPLOIT SEARCHING PHASE ] ---{RESET}")
    log_task(f"Attempting searchsploit Lookup: {' '.join(cmd)}")
    print(f"{YELLOW}------------------------------{RESET}")

    try:
        # Capture searchsploit output
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout

        # --- ROBUST RESULT CHECK ---
        # We only consider it "Empty" if ALL three categories say No Results
        is_empty = (
            "Exploits: No Results" in output and 
            "Shellcodes: No Results" in output and 
            "Papers: No Results" in output
        )
        has_results = not is_empty and len(output.strip()) > 0

        with open(outfile, "a") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"HOST: {ip:<20} | SERVICE: {service_string}\n")
            f.write(f"{'='*80}\n")

            if has_results:
                f.write(output)
                # Terminal Feedback: Success with actual data
                log_success(f"Vulnerabilities found for {ip} -> {service_string}")
            else:
                f.write("Exploits: No Results\nShellcodes: No Results\nPapers: No Results\n")
                # Terminal Feedback: Successful Query but Empty
                log_note(f"Successful query but no results found for: {service_string}")

            # Keep the requested footer
            f.write(f"\n{YELLOW}{'-'*30}{RESET}\n")

    except Exception as e:
        log_error(f"SearchSploit execution failed: {e}")
