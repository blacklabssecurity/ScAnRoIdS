#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/firewalker.py
Purpose: Execute the validated Firewalk profile without inventing firewall conclusions.
"""

from config import SCAN_LIBRARY
from core.scanner import deploy_scan


def run_firewalk(ctx, target_ip):
    return deploy_scan(ctx, [target_ip], SCAN_LIBRARY["61"], 1, "61")


"""
INPUT: Single lab target and session context.
OUTPUT: Raw Nmap Firewalk evidence, captured traffic and execution status.
"""
