#!/usr/bin/env bash
# Project: ScAnRoIdS Red Team Orchestrator
# Module: setup_scanRoids.sh
# Purpose: Install Python dependencies relative to this checkout; leave OS packages to the operator.
set -euo pipefail
scanroids_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$scanroids_dir"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py --doctor
printf '\nSetup complete. See README.md and docs/TOOLS.md for system packages and usage.\n'
# INPUT: python3 and python3-venv. OUTPUT: Local .venv and executable dependency report.
