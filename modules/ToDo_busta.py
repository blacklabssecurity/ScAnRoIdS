#!/usr/bin/env python3
"""
Project: Scanroids Red Team Orchestrator
Module:  modules/busta.py
Purpose: Leverages gobuster to enumerate additional web related resources. 
"""

'''
gobuster.py setup

General Purpose: /Discovery/Web-Content/raft-medium-directories.txt.
Quick Wins: /Discovery/Web-Content/common.txt.
Large-Scale: /Discovery/Web-Content/directory-list-2.3-medium.txt

Syntax for File-Specific Discovery:
gobuster dir -u http://10.10.10.123 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,bak,old
Success Logic: Appending extensions like .bak or .old with the -x flag often uncovers sensitive source code backups or unpatched legacy scripts.
Syntax for Virtual Host (VHost) Enumeration:
gobuster vhost -u http://target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
'''
