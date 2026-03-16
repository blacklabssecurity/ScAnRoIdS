
# ScAnRoIdS 🛡️

**ScAnRoIdS** is a modular Python wrapper for Nmap, designed to simplify network scanning and security auditing. It programmatically executes Nmap commands and parses XML output into usable Python data structures.

## Features
* **Automated Scanning**: Trigger Nmap scans directly from Python scripts.
* **XML Parsing**: Automatically converts Nmap's XML output into clean, structured data.
* **Extensive Presets**: Easily configure and reuse scan parameters.

## Prerequisites
* [Python 3.x](https://www.python.org)
* [Nmap](https://nmap.org) (Must be installed and in your system PATH)
* [searchsploit](https://www.exploit-db.com/searchsploit) (Must be installed and in your system PATH)
* [gowitness](https://github.com/sensepost/gowitness/wiki/Installation) (Must be installed and in your system PATH)

## General Hieerarchy

<img width="1354" height="952" alt="image" src="https://github.com/user-attachments/assets/1ee9848d-65f3-423d-bf58-10d1c5dd5571" />



## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com

## Usage

from scanroids import Scanner

# Example: Run a quick scan on a target
results = Scanner.quick_scan("192.168.1.1")
print(results)


## Disclaimer
This tool is for educational and authorized security testing purposes only. Only scan networks you have explicit permission to audit.
These guides explain the importance of creating and regularly updating README files for your projects:

## Planned Features

1. Re-capturing TTL and OS Data
The .gnmap (grepable) format is deprecated and often omits data like TTL or complex OS guesses to keep everything on one line. 

    The Fix: Switch your surgeon parsing logic to use the XML output (.xml). It is the only format guaranteed to contain the full OS fingerprint and the initial TTL (stored in the <os> and <distance> elements).
    Action: In your parse_gnmap_version_update function, if you still want to use grepable for some parts, you'll need to "join" it with data from the XML file to fill the TTL/OS columns. 

2. Dashboard Sorting
Sorting issues in index.html are usually caused by empty cells or inconsistent data types (e.g., trying to sort a column that has both numbers and "NA").

    Action: Once you upload the index.html to GitHub, I can help you implement a robust JavaScript library like DataTables or a custom sort function to handle those "NA" values gracefully.

3. Screenshot Naming Logic
You'll need to pass the customer name and date variables into your searchsploit/screenshot module.

    Proposed Format: http-{customer}-{date}-{ip}-{port}.jpeg
    Python Snippet:
    python

    filename = f"http-{customer_name}-{current_date}-{target_ip}-{target_port}.jpeg"

    Use code with caution.
│   ├── screenshots
│   │   ├── http---192.168.199.8-443.jpeg

But should be like this: 
│   ├── screenshots
│   │   ├── http-<customer>-<date>-192.168.199.8-443.jpeg

4. DNS Hostname Extraction
Nmap includes the DNS hostname in the <hostnames> tag of the XML output. 

    Action: Add a loop in your parser to check for <hostname name="example.com" type="user"/>. If found, append the value to hosts_dnsHostName.txt.

5. Network Topology Visualizer
Since you want an operator-generated web page, the best path is to use a library like D3.js or Cytoscape.js. 

    How it works: Your Python script will convert the Nmap XML into a JSON file (nodes and edges).
    The Page: A simple HTML template will read that JSON and draw the map. I can provide the template once your XML-to-JSON logic is ready.

6. Automated Wireshark (Tshark) Capture
Using the full Wireshark GUI in a script is tricky; it’s better to use Tshark (the command-line version) for the capture and then let the user open the resulting file in Wireshark.

    Execution Order:
        Start Tshark: Use subprocess.Popen to start a capture in the background.
        Apply Filter: Use the -f flag (e.g., tshark -f "host 192.168.1.1 and port 80" -w output.pcapng).
        Run Nmap: Execute your scan.
        Stop Tshark: Use .terminate() on the Popen object once Nmap finishes.
