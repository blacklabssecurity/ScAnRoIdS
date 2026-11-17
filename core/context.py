#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/context.py
Purpose: Create unique session workspaces or adopt existing sessions without data loss.
"""

from datetime import datetime
import json
import os
from pathlib import Path
import re
from uuid import uuid4
from core.system import get_operator

DEFAULT_ROOT = Path(os.environ.get("SCANROIDS_DATA_DIR", "/tools/scans/ScAnRoIdS"))


def slug(value):
    value = re.sub(r"[^A-Za-z0-9_-]+", "_", value.strip()).strip("_-")
    if not value:
        raise ValueError("Customer name must contain letters or digits")
    return value[:80]


class ScanContext:
    def __init__(self, customer_name="", resume_path=None, root=None):
        stamp = datetime.now()
        self.operator = get_operator()
        if resume_path:
            self.base_path = Path(resume_path).expanduser().resolve()
            if not self.base_path.is_dir():
                raise ValueError("Session directory does not exist")
            manifest = self.base_path / "session.json"
            if manifest.exists():
                saved = json.loads(manifest.read_text())
                self.customer = saved["customer"]
                self.date_str, self.time_str = saved["date"], saved["time"]
            else:
                # Legacy folder: customer may contain underscores.
                match = re.match(r"(.+)_(\d{8})_(\d{4,6})(?:_[a-f0-9]+)?$", self.base_path.name)
                if not match:
                    raise ValueError("Legacy session name must be customer_YYYYMMDD_HHMM[SS]")
                self.customer, self.date_str, self.time_str = match.groups()
        else:
            self.customer = slug(customer_name)
            self.date_str, self.time_str = (
                stamp.strftime("%Y%m%d"),
                stamp.strftime("%H%M%S"),
            )
            name = f"{self.customer}_{self.date_str}_{self.time_str}_{uuid4().hex[:6]}"
            self.base_path = (Path(root or DEFAULT_ROOT).expanduser() / name).resolve()
            self.base_path.mkdir(parents=True, exist_ok=False)
        self.session_name = self.base_path.name
        self.dirs = {key: self.base_path / key for key in ("artifacts", "pcap", "targets", "logs")}
        for path in self.dirs.values():
            path.mkdir(parents=True, exist_ok=True)
        manifest = self.base_path / "session.json"
        if not manifest.exists():
            manifest.write_text(
                json.dumps(
                    {
                        "customer": self.customer,
                        "date": self.date_str,
                        "time": self.time_str,
                        "version": 2,
                    },
                    indent=2,
                )
                + "\n"
            )
        self.interface = None
        self.capture = True
        self.greedy = False
        self.timeout = 3600
        self.db_path = None

    def get_file_path(self, category, filename):
        return self.dirs.get(category, self.base_path) / filename

    def artifact_name(self, phase, scan_id):
        return f"{phase}_{self.customer}_{datetime.now():%Y%m%d_%H%M%S}_{scan_id}_{uuid4().hex[:6]}"


"""
INPUT: Customer, optional data root or existing session path.
OUTPUT: Persistent manifest and normalized paths; no network or scan side effects.
"""
