#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  modules/boogies.py
Purpose: Used to search and parse soucre code of web pages for interesting
         keywords. Potential leakage of data.
"""

import requests
import csv
import os
from datetime import datetime

# Configuration
KEYWORDS = ["API_KEY", "secret", "admin", "/api/v1/", "isDebug", "TODO", "eval("]
OUTPUT_FILE = "recon_results.csv"
HEADERS = ["Keyword", "Location/URL", "Line Number", "Matching Line/Syntax", "Context (2 Before/2 After)", "Timestamp"]

def save_to_csv(data):
    file_exists = os.path.isfile(OUTPUT_FILE)
    with open(OUTPUT_FILE, mode='a', newline='', encoding='utf-8') as f:
        # Use DictWriter to match dictionary keys to CSV headers automatically
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        if not file_exists:
            writer.writeheader() # Write headers only if the file is new
        writer.writerow(data)

def scan_and_save(url, keywords, context_lines=2):
    try:
        response = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        lines = response.text.splitlines()

        for i, line in enumerate(lines):
            for word in keywords:
                if word.lower() in line.lower():
                    # Extract 2 lines before and 2 after
                    start = max(0, i - context_lines)
                    end = min(len(lines), i + context_lines + 1)
                    context_block = "\n".join(lines[start:end])

                    # Prepare the row data
                    result_entry = {
                        "Keyword": word,
                        "Location/URL": url,
                        "Line Number": i + 1,
                        "Matching Line/Syntax": line.strip(),
                        "Context (2 Before/2 After)": context_block,
                        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    save_to_csv(result_entry)
                    print(f"[+] Saved match: {word} at {url}")

    except Exception as e:
        print(f"[-] Error scanning {url}: {e}")

# Example Run
scan_and_save("http://example-target.com", KEYWORDS)
