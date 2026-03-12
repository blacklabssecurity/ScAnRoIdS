# ==============================================================================
# SCRIPT: web_interface.py
# PURPOSE: Flask Blueprint & API Presentation Layer
# FUNCTIONALITY: 
#   - Defines the Web UI routes and serves the index.html dashboard.
#   - Provides the /api/status endpoint for the JavaScript Heartbeat.
#   - Safely serves scan artifacts (logs, snapshots, TXTs) via /artifacts/ route.
#   - Implements Operator authentication and links shared memory to the UI.
# ==============================================================================

from flask import Blueprint, render_template, jsonify, request, send_from_directory, redirect, url_for, flash
from flask_login import login_required, current_user, UserMixin, login_user
import os, datetime

class User(UserMixin):
    def __init__(self, id): 
        self.id = id

# 1. Define the Blueprint
web_bp = Blueprint('web', __name__)

# 2. These will be linked to your main script's globals
dashboard_data = None
config_ref = None
live_logs_ref = None


def init_web_data(data_dict, config_dict, logs_list):
    global dashboard_data, config_ref, live_logs_ref
    dashboard_data = data_dict
    config_ref = config_dict
    live_logs_ref = logs_list


@web_bp.route('/')
@login_required
def index():
    """Consolidated Dashboard: Metrics, SID, and CVEs."""
    from surgeon import get_top_cves

    # Access BASE_DIR via config_ref
    base_path = config_ref['BASE_DIR'] 

    # Pull Latest CVEs / EDB-IDs
    sploit_path = os.path.join(config_ref['BASE_DIR'], f"{config_ref['CUSTOMER']}_{config_ref['DATE_STR']}_exploits.txt")
    top_cves = get_top_cves(sploit_path) if os.path.exists(sploit_path) else []

    # Grab Domain SID from File
    sid_val = "NOT YET CAPTURED"
    sid_path = os.path.join(config_ref['BASE_DIR'], "domain_sid.txt")
    if os.path.exists(sid_path):
        try:
            with open(sid_path, 'r') as f:
                line = f.readline()
                # Check for the standard SID pattern
                if "-5-21-" in line and "]" in line: 
                    sid_val = line.split("] ")[1].strip()
        except: pass

    # MERGE DATA (The "payload" method prevents the 'Multiple Values' error)
    payload = dashboard_data | config_ref
    payload['domain_sid'] = sid_val
    payload['top_cves'] = top_cves
    payload['path'] = os.path.abspath(base_path) # Use local base_path variable
    payload['logs'] = live_logs_ref if live_logs_ref is not None else []

    return render_template('index.html', **payload)


@web_bp.route('/api/status')
@login_required
def get_status():
    # --- THE FIX: BRING IN THE GLOBAL REFERENCE ---
    global live_logs_ref, config_ref

    from surgeon import get_top_cves
    sploit_path = os.path.join(config_ref['BASE_DIR'], f"{config_ref['CUSTOMER']}_{config_ref['DATE_STR']}_exploits.txt")

    # We use list() to create a thread-safe snapshot for the JSON response
    current_logs = list(live_logs_ref) if live_logs_ref is not None else []

    return jsonify({
        "scan_active": dashboard_data.get('scan_active', True), 
        "status": dashboard_data.get('status', ''),
        "results": dashboard_data.get('results', []),
        "logs": current_logs,
        "exploits_found": dashboard_data.get('exploits_found', False),
        "top_cves": get_top_cves(sploit_path) if os.path.exists(sploit_path) else []
    })


@web_bp.route('/artifacts/<path:filename>')
@login_required
def serve_artifact(filename):
    """Maps the virtual /artifacts/ URL to the physical CUSTOMER_DATE folder."""
    target_path = os.path.abspath(config_ref['BASE_DIR'])
    # Security Check: Prevent directory traversal
    if ".." in filename or filename.startswith("/"):
        return "Access Denied", 403

    # Point directly to the BASE_DIR (e.g., test99_11MAR2026)
    # Flask will now look for 'filename' INSIDE that folder.
    return send_from_directory(target_path, filename)


@web_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Simple Auth with Customer-based password."""
    if request.method == 'POST':
        if request.form['u'] == 'operator' and request.form['p'] == f"{config_ref['CUSTOMER']}_{config_ref['YEAR_STR']}":
            login_user(User('operator'))
            return redirect(url_for('web.index'))
        else:
            flash("ACCESS DENIED: INVALID CREDENTIALS", "error")
    return render_template('login.html', customer=config_ref['CUSTOMER'], year=config_ref['YEAR_STR'])
