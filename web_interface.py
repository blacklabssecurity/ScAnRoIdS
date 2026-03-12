# ==============================================================================
# SCRIPT: web_interface.py (FINAL CONSOLIDATED VERSION)
# PURPOSE: Flask Blueprint & API Presentation Layer
# ==============================================================================

from flask import Blueprint, render_template, jsonify, request, send_from_directory, redirect, url_for, flash
from flask_login import login_required, current_user, UserMixin, login_user
import os, datetime

# --- 1. LOGIN UTILITIES ---
class User(UserMixin):
    def __init__(self, id): 
        self.id = id

# --- 2. BLUEPRINT & SHARED STATE ---
web_bp = Blueprint('web', __name__)

dashboard_data = None
config_ref = None
live_logs_ref = None

def init_web_data(data_dict, config_dict, logs_list):
    """Links the main script's shared memory to this blueprint."""
    global dashboard_data, config_ref, live_logs_ref
    dashboard_data = data_dict
    config_ref = config_dict
    live_logs_ref = logs_list

# --- 3. MAIN DASHBOARD ROUTE ---
@web_bp.route('/')
@login_required
def index():
    """Renders the main dashboard with initial scan state."""
    # Access BASE_DIR via config_ref
    base_path = config_ref['BASE_DIR'] 

    # Grab Domain SID from File (using safe split logic)
    sid_val = "NOT YET CAPTURED"
    sid_path = os.path.join(base_path, "domain_sid.txt")
    if os.path.exists(sid_path):
        try:
            with open(sid_path, 'r') as f:
                line = f.readline()
                if "] " in line:
                    sid_val = line.split("] ")[1].strip()
        except: pass

    # Prepare payload for Jinja2 template
    payload = dashboard_data | config_ref
    payload['domain_sid'] = sid_val
    payload['path'] = os.path.abspath(base_path)
    payload['logs'] = live_logs_ref if live_logs_ref is not None else []
    
    # Note: top_cves and exploits_found are now managed via the API for real-time updates
    return render_template('index.html', **payload)

# --- 4. HEARTBEAT API (FOR LIVE UPDATES) ---
@web_bp.route('/api/status')
@login_required
def get_status():
    """Feeds the JavaScript heartbeat with live scan data."""
    global live_logs_ref
    
    # Send only the last 50 lines of logs to keep the response fast
    current_logs = list(live_logs_ref)[-50:] if live_logs_ref is not None else []

    return jsonify({
        "scan_active": dashboard_data.get('scan_active', True), 
        "status": dashboard_data.get('status', ''),
        "results": dashboard_data.get('results', []), # Required for Cytoscape Visualizer
        "host_count": dashboard_data.get('host_count', 0),
        "service_count": dashboard_data.get('service_count', 0),
        "logs": current_logs,
        "exploits_found": dashboard_data.get('exploits_found', False),
        "top_cves": dashboard_data.get('top_cves', []), # Pulled from memory, not disk
        "visual_recon_live": dashboard_data.get('visual_recon_live', False),
        "juicy_target": dashboard_data.get('juicy_target', 'N/A')
    })

# --- 5. ARTIFACTS & PCAP SERVER ---
@web_bp.route('/artifacts/<path:filename>')
@login_required
def serve_artifact(filename):
    """Serves text logs, screenshots, and triggers download for PCAPs."""
    target_path = os.path.abspath(config_ref['BASE_DIR'])
    
    # Security: Prevent directory traversal
    if ".." in filename or filename.startswith("/"):
        return "Access Denied", 403

    # Force download for packet captures (.pcapng)
    is_pcap = filename.endswith('.pcapng')
    return send_from_directory(target_path, filename, as_attachment=is_pcap)

# --- 6. AUTHENTICATION ---
@web_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Standard Operator Login."""
    if request.method == 'POST':
        user_in = request.form.get('u')
        pass_in = request.form.get('p')
        expected_pass = f"{config_ref['CUSTOMER']}_{config_ref['YEAR_STR']}"
        
        if user_in == 'operator' and pass_in == expected_pass:
            login_user(User('operator'))
            return redirect(url_for('web.index'))
        
        flash("ACCESS DENIED: INVALID CREDENTIALS", "error")
    return render_template('login.html', customer=config_ref['CUSTOMER'], year=config_ref['YEAR_STR'])
