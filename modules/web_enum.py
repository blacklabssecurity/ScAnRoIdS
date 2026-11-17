#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: modules/web_enum.py
Purpose: Bounded optional HTTP content discovery with an operator-selected wordlist.
"""

from pathlib import Path
from urllib.parse import urlsplit
from modules.tools import artifact_output, execute


def run_web_enum(ctx, url, wordlist):
    parts = urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
    ):
        raise ValueError("Provide an HTTP(S) URL without credentials")
    path = Path(wordlist).expanduser().resolve()
    if not path.is_file():
        raise ValueError("Web wordlist does not exist")
    result = execute(
        ctx,
        [
            "gobuster",
            "dir",
            "-u",
            url,
            "-w",
            str(path),
            "-t",
            "4",
            "--timeout",
            "5s",
            "--no-progress",
        ],
        ip=parts.hostname,
        timeout=300,
    )
    return artifact_output(ctx, result, "web_content", f"URL: {url}\n")


"""
INPUT: Explicit lab URL and local wordlist selected from the terminal.
OUTPUT: Bounded content-discovery report and job history.
"""
