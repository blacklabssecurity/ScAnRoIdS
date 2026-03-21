#./scanroids/core/dashboard.py
"""
Project: Scanroids Red Team Orchestrator
Module:  core/dashboard.py
Purpose: Flask web engine for the ScanRoids Dashboard.
"""

import os
import datetime
import sqlite3
import logging
import threading
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from core.database import init_db

app = Flask(__name__, template_folder='../web/templates', static_folder='../web/static')
app.secret_key = os.urandom(24)

# --- Logging Setup ---
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- Auth Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# --- Global State ---
SCAN_ACTIVE = True 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "operator" and password == app.config.get('SCAN_PASSWORD'):
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/')
@login_required
def index():
    db_path = app.config.get('DB_PATH')
    if not db_path:
        return "Database path not configured.", 500
        
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    try:
        meta = conn.execute('SELECT * FROM session_info WHERE id=1').fetchone()
        results = conn.execute('SELECT * FROM scan_results ORDER BY last_seen DESC').fetchall()
    except sqlite3.OperationalError:
        meta = None
        results = []
    finally:
        conn.close()
    
    return render_template('dashboard.html', meta=meta, results=results, heartbeat=SCAN_ACTIVE)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

def start_dashboard(ctx):
    """Entry point to start the dashboard thread."""
    init_db(ctx) 
    
    year = datetime.datetime.now().year
    app.config['SCAN_PASSWORD'] = f"{ctx.customer}_{year}"
    app.config['DB_PATH'] = ctx.dirs['artifacts'] / "session.db"
    
    # Session logging
    log_file = ctx.base_path / "logs" / "dashboard_access.log"
    file_handler = logging.FileHandler(log_file)
    log.addHandler(file_handler)
    
    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8888, debug=False, use_reloader=False), daemon=True).start()
