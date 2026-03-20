#!/usr/bin/env python3

"""
Project: Scanroids Red Team Orchestrator
Module:  core/ui.py
Purpose: Centralizes terminal user interface elements, including ANSI color 
         standardization, standardized logging prefixes, and screen management.
         Ensures consistent visual feedback for operators across all tool modules.

Color Testing: python3 -c 'print("\033[1;34m[*] TASKING: (BLUE)\033[0m \033[1;32m[*] SUCCESS: (GREEN)\033[0m \033[1;31m[X] WARNING: / ERRORS: (RED)\033[0m \033[1;33m[+] NOTES: (YELLOW)\033[0m \033[1;36m[?] QUESTION: (CYAN)\033[0m \033[1;35m[=] SPARE color (MAGENTA) \033[0m")' 
"""

import os
import sys

# --- ANSI COLOR CODES ---
BLUE    = "\033[1;34m"   # Tasking
GREEN   = "\033[1;32m"   # Success
RED     = "\033[1;31m"   # Warning / Error / X
YELLOW  = "\033[1;33m"   # Notes
ORANGE  = "\033[38;5;208m" # Highlight / Alternate (256-color)
CYAN    = "\033[1;36m"   # Questions
MAGENTA = "\033[1;35m"   # Fallback / Future Use
BULLET  = "\033[1;34m"   # Bullet for pointed details
RESET   = "\033[0m"
BOLD    = "\033[1m"

def log_task(message):
    """{BLUE}[*] TASKING:{RESET} message"""
    print(f"{BLUE}[*] TASKING:{RESET} {message}")

def log_success(message):
    """{GREEN}[:)] SUCCESS:{RESET} message"""
    print(f"{GREEN}[:)] SUCCESS:{RESET} {message}")

def log_warn(message):
    """{RED}[X] WARNING:{RESET} message"""
    print(f"\n{RED}[X] WARNING:{RESET} {message}\n")

def log_error(message):
    """{RED}[!] ERROR:{RESET} message"""
    print(f"\n{RED}[!] ERROR:{RESET} {message}\n")

def log_question(message):
    """{CYAN}[?] QUESTION:{RESET} message"""
    return input(f"\n{CYAN}[?] QUESTION:{RESET} {message} ")

def log_note(message):
    """{YELLOW}[i] NOTE:{RESET} message"""
    print(f"{YELLOW}[i] NOTE:{RESET} {message}")

def clear_screen():
    """Clears terminal screen for clean transitions"""
    os.system('clear' if os.name != 'nt' else 'cls')

def print_banner(header_text):
    """Prints the main application banner with bold formatting"""
    print(f"{BOLD}{header_text}{RESET}")


# --- IMPACT CHECK ---
# This module allows us to replace 'print' with 'log_task' across the project.
# It ensures that 'operator' logs are visually distinct from 'tool' logs.

