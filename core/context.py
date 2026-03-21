#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module:  core/context.py
Purpose: Handles session initialization and "Adoption" of existing session 
         directories to support resumption of audits and dashboards.
"""

import os
import datetime
from pathlib import Path
from core.system import get_operator
from core.ui import (
    log_task, log_success, log_error,
    log_note, YELLOW, BLUE, RED, CYAN,
    BOLD, RESET, BULLET
    )


class ScanContext:
    def __init__(self, customer_name, resume_path=None):
        """
        :param customer_name: Standardized customer string.
        :param resume_path: If provided, 'Adopts' this existing directory.
        """
        self.customer = customer_name.strip().replace(" ", "_")
        self.operator = get_operator() 

        if resume_path:
            # --- ADOPT MODE ---
            self.base_path = Path(resume_path)
            self.session_name = self.base_path.name
            log_note(f"Adopting existing session: {self.session_name}")
        else:
            # --- NEW SESSION MODE ---
            date_str = datetime.datetime.now().strftime("%Y%m%d")
            time_str = datetime.datetime.now().strftime("%H%M")
            self.session_name = f"{self.customer}_{date_str}_{time_str}"
            self.base_path = Path(f"/tools/scans/{self.session_name}")
            self._create_structure()

        # Map internal directories (Consistent for New and Adopted)
        self.dirs = {
            "artifacts": self.base_path / "artifacts",
            "pcap":      self.base_path / "pcap",
            "targets":   self.base_path / "targets",
            "logs":      self.base_path / "logs"
        }

        # Capture date/time strings from the folder name for file naming
        # This ensures audit files match the original discovery date
        try:
            parts = self.session_name.split('_')
            self.date_str = parts[-2]
            self.time_str = parts[-1]
        except:
            self.date_str = datetime.datetime.now().strftime("%Y%m%d")
            self.time_str = datetime.datetime.now().strftime("%H%M")

    def _create_structure(self):
        """Creates physical folders only for fresh sessions."""
        log_task(f"Initializing new workspace: {self.session_name}")
        try:
            for dir_path in [self.base_path, self.base_path / "artifacts", 
                            self.base_path / "pcap", self.base_path / "targets", 
                            self.base_path / "logs"]:
                dir_path.mkdir(parents=True, exist_ok=True)
            log_success(f"Workspace ready at {self.base_path}")
        except Exception as e:
            log_error(f"Failed to create workspace: {e}")
            raise SystemExit(1)


    def get_file_path(self, category, filename):
        """Helper to get a full path for a specific file type"""
        if category in self.dirs:
            return self.dirs[category] / filename
        return self.base_path / filename

# --- IMPACT CHECK ---
# 'self.date_str' is now extracted from the FOLDER name if resuming.
# This prevents Phase 2 files from having a different date than Phase 1.
