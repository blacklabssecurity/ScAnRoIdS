#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/ui.py
Purpose: Consistent terminal colors and session-backed application logging.
"""

import sys

BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
ORANGE = "\033[38;5;208m"
CYAN = "\033[1;36m"
MAGENTA = "\033[1;35m"
BULLET = BLUE
RESET = "\033[0m"
BOLD = "\033[1m"
_DB = None


def attach_log(db):
    global _DB
    _DB = db


def _log(label, message, color):
    text = f"{label} {message}"
    print(f"{color}{label}{RESET} {message}" if sys.stdout.isatty() else text, flush=True)
    if _DB:
        from core.database import event

        event(_DB, text)


def log_task(message):
    _log("[*] TASKING:", message, BLUE)


def log_success(message):
    _log("[:)] SUCCESS:", message, GREEN)


def log_warn(message):
    _log("[!] WARNING:", message, RED)


def log_error(message):
    _log("[:(] ERROR:", message, RED)


def log_note(message):
    _log("[i] NOTE:", message, YELLOW)


def log_question(message):
    return input(f"{CYAN}[?]{RESET} {message} ").strip()


def clear_screen():
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def print_banner(header_text):
    print(header_text)


"""
INPUT: Operator prompts, status messages and optional attached session database.
OUTPUT: Colored terminal messages and durable dashboard events.
"""
