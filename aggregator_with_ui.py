#!/usr/bin/env python3
"""
aggregator_with_ui.py (v88 - Self-signup + StatusBar + TopBar + Friendly errors)

Key additions:
 - Self-signup settings & flow (enable/disable + default role) with username/email uniqueness
 - Status bar item config (status_summary_items) + top bar color persisted in config
 - 'view_file_names' permission + gating in dashboard
 - Graceful error handling for 500s (won't lock users out)
 - 'admin_stop_print' endpoint for live-status table
 - No placeholder images when printer has none
"""

import os
import json
import time
import requests
import logging
import shutil
import datetime
from urllib.parse import urlparse
from flask import (
    Flask, jsonify, request, redirect, url_for, render_template,
    session, flash, Response
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS

# --- CONFIGURATION ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRINTERS_FILE = os.path.join(BASE_DIR, 'printers.json')
OVERRIDES_FILE = os.path.join(BASE_DIR, 'overrides.json')
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
ROLES_FILE = os.path.join(BASE_DIR, 'roles.json')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
KIOSK_DIR = os.path.join(BASE_DIR, 'kiosks')
LOG_FILE = os.path.join(BASE_DIR, 'activity.log')
PRINTER_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/printer_images')
KIOSK_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/kiosk_images')
GCODE_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'gcode_uploads')
PRINT_JOBS_FILE = os.path.join(BASE_DIR, 'print_jobs.json')
ASSETS_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/assets')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
ALLOWED_GCODE_EXTENSIONS = {'gcode', 'g', 'gco'}
CACHE_TTL = 5
HTTP_PORT = int(os.environ.get("HTTP_PORT", 80))

# Add 'view_file_names' so we can gate filename visibility
BASE_PERMISSIONS = [
    'view_dashboard', 'admin_panel_access', 'set_overrides', 'view_logs',
    'add_printer', 'edit_printer', 'delete_printer',
    'add_user', 'edit_user', 'delete_user', 'change_user_password', 'change_user_role',
    'add_role', 'edit_role', 'delete_role',
    'manage_appearance', 'manage_statuses', 'manage_aliases',
    'add_kiosk', 'delete_kiosk', 'rename_kiosk',
    'manage_kiosk_settings', 'manage_printer_kiosks', 'manage_image_kiosks',
    'manage_kiosk_images', 'upload_gcode', 'approve_prints',
    'view_file_names'
]

def get_available_permissions():
    kiosks = []
    if os.path.isdir(KIOSK_DIR):
        kiosks = [f.split('.')[0] for f in os.listdir(KIOSK_DIR) if f.endswith('.json')]
    kiosk_perms = [f'manage_kiosk_{k}' for k in kiosks]
    return BASE_PERMISSIONS + kiosk_perms

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = 'a-very-secret-and-random-key-that-you-should-change'
app.config['PRINTER_UPLOAD_FOLDER'] = PRINTER_UPLOAD_FOLDER
app.config['KIOSK_UPLOAD_FOLDER'] = KIOSK_UPLOAD_FOLDER
app.config['GCODE_UPLOAD_FOLDER'] = GCODE_UPLOAD_FOLDER
app.config['ASSETS_UPLOAD_FOLDER'] = ASSETS_UPLOAD_FOLDER
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

PRINTER_TYPE_DISPLAY = {
    'prusa': 'Prusa',
    'klipper': 'Klipper',
    'bambu': 'Bambu Labs',
    'centauri': 'Elegoo'
}

def type_display(t):
    return PRINTER_TYPE_DISPLAY.get((t or '').lower(), (t or '').title())

app.jinja_env.filters['type_display'] = type_display

# --- LOGGING SETUP ---------------------------------------------------------
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- DATA HANDLING ---------------------------------------------------------
def allowed_file(filename, allowed_set=ALLOWED_EXTENSIONS):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def load_data(file_path, default_data):
    if not os.path.exists(file_path):
        save_data(default_data, file_path)
    try:
        with open(file_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        logging.error(f"Could not read or decode JSON from {file_path}. Returning default data.")
        return default_data

def save_data(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2, sort_keys=True)

def normalize_username(username):
    return (username or '').strip().lower()

def load_users():
    users = load_data(USERS_FILE, {})
    normalized = {normalize_username(k): v for k, v in users.items()}
    if normalized != users:
        save_data(normalized, USERS_FILE)
    return normalized

def get_full_config():
    defaults = {
        "dashboard_title": "Printer Dashboard",
        "dashboard_title_image": "",
        "dashboard_title_image_height": 40,
        "dashboard_title_image_position": "left",
        "manual_statuses": ["Ready", "Printing", "Under Maintenance", "Offline"],
        "status_colors": {
            "ready": "#28a745", "idle": "#28a745", "operational": "#28a745",
            "printing": "#007bff", "finished": "#007bff", "offline": "#6c757d",
            "error": "#dc3545", "under_maintenance": "#ffc107", "paused": "#6c757d",
            "unsupported": "#6c757d", "config_error": "#dc3545"
        },
        "status_aliases": {},
        "status_order": ["Printing", "Ready", "Finished", "Offline", "Error", "Under Maintenance", "Unsupported"],
        "status_summary_items": ["Ready", "Printing", "Maintenance", "Offline", "Total"],
        "card_size": "medium",
        "font_family": "sans-serif",
        "sort_by": "manual",
        "printer_order": [],
        "progress_bar_color": "#007bff",
        "progress_bar_text_color": "#ffffff",
        "refresh_interval_sec": 30,
        "top_bar_color": "#007bff",
        "enable_self_signup": False,
        "default_signup_role": "member"
    }
    user_config = load_data(CONFIG_FILE, defaults)
    full_config = defaults.copy()
    full_config.update(user_config)
    # Ensure keys exist (for older configs)
    for k, v in defaults.items():
        full_config.setdefault(k, v)
    return full_config

DEFAULT_KIOSK_CONFIG = {
    "name": "Main Kiosk", "kiosk_printers_per_page": 6, "kiosk_printer_page_time": 10,
    "kiosk_image_page_time": 5, "kiosk_image_frequency": 2, "kiosk_images_per_slot": 1,
    "kiosk_images": [], "kiosk_background_color": "#000000", "kiosk_sort_by": "manual",
    "kiosk_title": "", "kiosk_header_image": "", "kiosk_header_height_px": 150,
    "show_printers": True, "kiosk_dark_mode": False, "kiosk_font_size": 100
}

def get_kiosk_config(kiosk_id='default'):
    if not os.path.isdir(KIOSK_DIR):
        os.makedirs(KIOSK_DIR, exist_ok=True)
    config_path = os.path.join(KIOSK_DIR, f"{kiosk_id}.json")
    user_config = load_data(config_path, DEFAULT_KIOSK_CONFIG)
    if user_config.get('kiosk_images') and all(isinstance(img, str) for img in user_config['kiosk_images']):
        default_time = user_config.get('kiosk_image_page_time', 5)
        user_config['kiosk_images'] = [{'url': url, 'time': default_time, 'active': True} for url in user_config['kiosk_images']]
    config = DEFAULT_KIOSK_CONFIG.copy()
    config.update(user_config)
    if 'show_printers' not in config:
        config['show_printers'] = True
    return config

def list_kiosk_configs():
    if not os.path.isdir(KIOSK_DIR):
        os.makedirs(KIOSK_DIR, exist_ok=True)
    kiosks = {}
    for file in os.listdir(KIOSK_DIR):
        if file.endswith('.json'):
            kid = file.split('.')[0]
            kiosks[kid] = get_kiosk_config(kid)
    return kiosks

def has_kiosk_permission(user_permissions, kiosk_id):
    kiosk_cfg = get_kiosk_config(kiosk_id)
    if 'manage_kiosk_settings' in user_permissions or 'manage_all_kiosks' in user_permissions:
        return True
    if kiosk_cfg.get('show_printers', True) and 'manage_printer_kiosks' in user_permissions:
        return True
    if not kiosk_cfg.get('show_printers', True) and 'manage_image_kiosks' in user_permissions:
        return True
    return f'manage_kiosk_{kiosk_id}' in user_permissions

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('root'))
            user_role_name = session.get('role', '')
            roles = load_data(ROLES_FILE, {})
            user_permissions = roles.get(user_role_name, {}).get('permissions', [])
            if '*' in user_permissions:
                user_permissions = get_available_permissions()
            if permission not in user_permissions and '*' not in user_permissions:
                flash('You do not have sufficient permissions for this action.', 'danger')
                return redirect(request.referrer or url_for('root'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- PRINTER COMMANDS ------------------------------------------------------
def start_klipper_print(printer_config, gcode_filename):
    if not printer_config.get('url'):
        return False, "Printer URL is not configured."
    try:
        gcode_path = os.path.join(app.config['GCODE_UPLOAD_FOLDER'], gcode_filename)
        with open(gcode_path, 'rb') as f:
            files = {'file': (gcode_filename, f, 'application/octet-stream')}
            upload_url = f"{printer_config['url']}/server/files/upload"
            response = requests.post(upload_url, files=files, timeout=30)
            response.raise_for_status()
    except Exception as e:
        logging.error(f"Klipper upload failed for '{printer_config['name']}': {e}")
        return False, f"File upload failed: {e}"
    try:
        start_print_url = f"{printer_config['url']}/printer/print/start?filename={gcode_filename}"
        response = requests.post(start_print_url, timeout=10)
        response.raise_for_status()
        logging.info(f"Started print '{gcode_filename}' on Klipper printer '{printer_config['name']}'.")
        return True, "Print started successfully."
    except Exception as e:
        logging.error(f"Klipper start print failed for '{printer_config['name']}': {e}")
        return False, f"Failed to start print: {e}"

def start_prusa_print(printer_config, gcode_filename):
    if not printer_config.get('ip') or not printer_config.get('api_key'):
        return False, "Printer IP or API Key is not configured."
    try:
        gcode_path = os.path.join(app.config['GCODE_UPLOAD_FOLDER'], gcode_filename)
        headers = {'X-Api-Key': printer_config['api_key']}
        with open(gcode_path, 'rb') as f:
            files = {'file': (gcode_filename, f, 'text/x-gcode')}
            upload_url = f"http://{printer_config['ip']}/api/v1/files/local"
            form_data = {'print': 'true'}
            response = requests.post(upload_url, headers=headers, files=files, data=form_data, timeout=30)
            response.raise_for_status()
        logging.info(f"Uploaded and started print '{gcode_filename}' on Prusa '{printer_config['name']}'.")
        return True, "Print started successfully."
    except Exception as e:
        logging.error(f"PrusaLink print failed for '{printer_config['name']}': {e}")
        return False, f"Failed to start print: {e}"

def start_bambu_print(printer_config, gcode_filename):
    if not printer_config.get('ip') or not printer_config.get('access_code'):
        return False, "Printer IP or Access Code is not configured."
    try:
        gcode_path = os.path.join(app.config['GCODE_UPLOAD_FOLDER'], gcode_filename)
        headers = {'X-Access-Code': printer_config['access_code']}
        with open(gcode_path, 'rb') as f:
            files = {'file': (gcode_filename, f, 'application/octet-stream')}
            upload_url = f"http://{printer_config['ip']}/api/v1/upload"
            response = requests.post(upload_url, headers=headers, files=files, timeout=30)
            response.raise_for_status()
        start_url = f"http://{printer_config['ip']}/api/v1/print/start"
        response = requests.post(start_url, headers=headers, json={'file': gcode_filename}, timeout=10)
        response.raise_for_status()
        logging.info(f"Started print '{gcode_filename}' on Bambu printer '{printer_config['name']}'.")
        return True, "Print started successfully."
    except Exception as e:
        logging.error(f"Bambu print failed for '{printer_config['name']}': {e}")
        return False, f"Failed to start print: {e}"

def start_centauri_print(printer_config, gcode_filename):
    # Centauri printers use a Klipper-compatible API
    return start_klipper_print(printer_config, gcode_filename)

def stop_klipper_print(printer_config):
    if not printer_config.get('url'):
        return False, "Printer URL is not configured."
    try:
        stop_url = f"{printer_config['url']}/printer/print/cancel"
        response = requests.post(stop_url, timeout=10)
        response.raise_for_status()
        logging.info(f"Stopped print on Klipper '{printer_config['name']}'.")
        return True, "Print stopped successfully."
    except Exception as e:
        logging.error(f"Klipper stop failed for '{printer_config['name']}': {e}")
        return False, f"Failed to stop print: {e}"

def stop_prusa_print(printer_config):
    if not printer_config.get('ip') or not printer_config.get('api_key'):
        return False, "Printer IP or API Key is not configured."
    try:
        headers = {'X-Api-Key': printer_config['api_key']}
        stop_url = f"http://{printer_config['ip']}/api/v1/print/stop"
        response = requests.post(stop_url, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info(f"Stopped print on Prusa '{printer_config['name']}'.")
        return True, "Print stopped successfully."
    except Exception as e:
        logging.error(f"Prusa stop failed for '{printer_config['name']}': {e}")
        return False, f"Failed to stop print: {e}"

def stop_bambu_print(printer_config):
    if not printer_config.get('ip') or not printer_config.get('access_code'):
        return False, "Printer IP or Access Code is not configured."
    try:
        headers = {'X-Access-Code': printer_config['access_code']}
        stop_url = f"http://{printer_config['ip']}/api/v1/print/stop"
        response = requests.post(stop_url, headers=headers, timeout=10)
        response.raise_for_status()
        logging.info(f"Stopped print on Bambu '{printer_config['name']}'.")
        return True, "Print stopped successfully."
    except Exception as e:
        logging.error(f"Bambu stop failed for '{printer_config['name']}': {e}")
        return False, f"Failed to stop print: {e}"

def stop_centauri_print(printer_config):
    return stop_klipper_print(printer_config)

# --- FETCHERS --------------------------------------------------------------
def fetch_klipper_data(p):
    if not p.get('url'):
        return {'state': 'Config Error', 'error': 'Missing URL'}
    try:
        r = requests.get(
            f"{p['url']}/printer/objects/query?print_stats&display_status&heater_bed&extruder&virtual_sdcard",
            timeout=5
        )
        r.raise_for_status()
        res = r.json()['result']['status']
        print_stats = res.get('print_stats', {})
        state = (print_stats.get('state', 'unknown') or 'unknown').title()
        filename = print_stats.get('filename')
        prog = res.get('virtual_sdcard', {}).get('progress')
        time_elapsed = print_stats.get('print_duration')
        file_progress = res.get('virtual_sdcard', {}).get('progress', 0)
        time_remaining = (time_elapsed / file_progress - time_elapsed) if file_progress > 0 and time_elapsed else None
        return {
            'state': state,
            'filename': filename,
            'progress': round(prog * 100, 1) if prog else None,
            'bed_temp': round(res.get('heater_bed', {}).get('temperature', 0), 1),
            'nozzle_temp': round(res.get('extruder', {}).get('temperature', 0), 1),
            'time_elapsed': int(time_elapsed) if time_elapsed else None,
            'time_remaining': int(time_remaining) if time_remaining and time_remaining > 0 else None
        }
    except Exception as e:
        logging.error(f"Klipper fetch for '{p.get('name')}': {e}")
        return {'state': 'Offline', 'error': str(e)}

def fetch_prusalink_data(p):
    if not p.get('ip') or not p.get('api_key'):
        return {'state': 'Config Error', 'error': 'Missing IP or API Key'}
    try:
        headers = {'X-Api-Key': p['api_key']}
        base_url = f"http://{p['ip']}/api/v1"
        resp = requests.get(f"{base_url}/status", headers=headers, timeout=5)
        resp.raise_for_status()
        status = resp.json()
        printer = status.get('printer', {}) or {}
        job_status = status.get('job', {}) or {}
        state = (printer.get('state', 'Unknown') or 'Unknown').title()
        file_obj = job_status.get('file', {}) if isinstance(job_status, dict) else {}
        filename = (file_obj.get('display_name') or file_obj.get('name') or
                    job_status.get('file_name') or job_status.get('filename') or file_obj.get('path'))

        # If no filename was returned in the status response, try the dedicated job endpoint
        if not filename:
            try:
                job_resp = requests.get(f"{base_url}/job", headers=headers, timeout=5)
                job_resp.raise_for_status()
                job_data = job_resp.json()
                file_obj2 = job_data.get('file', {}) if isinstance(job_data, dict) else {}
                filename = (file_obj2.get('display_name') or file_obj2.get('name') or
                            job_data.get('file_name') or job_data.get('filename') or file_obj2.get('path'))
            except Exception as e:
                logging.debug(f"PrusaLink job fetch failed for '{p.get('name')}': {e}")

        prog = job_status.get('progress')
        if prog is not None:
            try:
                prog = float(prog)
                prog = round(prog * 100, 1) if prog <= 1 else round(prog, 1)
            except (ValueError, TypeError):
                prog = None

        return {
            'state': state,
            'filename': filename,
            'progress': prog,
            'bed_temp': round(printer.get('temp_bed'), 1) if printer.get('temp_bed') is not None else None,
            'nozzle_temp': round(printer.get('temp_nozzle'), 1) if printer.get('temp_nozzle') is not None else None,
            'time_elapsed': int(job_status.get('time_printing')) if job_status.get('time_printing') is not None else None,
            'time_remaining': int(job_status.get('time_remaining')) if job_status.get('time_remaining') is not None else None
        }
    except Exception as e:
        logging.error(f"PrusaLink fetch for '{p.get('name')}': {e}")
        return {'state': 'Offline', 'error': str(e)}

def fetch_bambu_data(p):
    if not p.get('ip'):
        return {'state': 'Config Error', 'error': 'Missing IP'}
    try:
        headers = {}
        if p.get('access_code'):
            headers['X-Access-Code'] = p['access_code']
        resp = requests.get(f"http://{p['ip']}/api/v1/status", headers=headers, timeout=5)
        resp.raise_for_status()
        status = resp.json()
        return {
            'state': (status.get('state') or 'unknown').title(),
            'filename': status.get('file'),
            'progress': status.get('progress'),
            'bed_temp': status.get('bed_temp'),
            'nozzle_temp': status.get('nozzle_temp'),
            'time_elapsed': status.get('time_elapsed'),
            'time_remaining': status.get('time_remaining')
        }
    except Exception as e:
        logging.error(f"Bambu fetch for '{p.get('name')}': {e}")
        return {'state': 'Offline', 'error': str(e)}

def fetch_centauri_data(p):
    return fetch_klipper_data(p)

def fetch_printer(p):
    ptype = p.get('type')
    if ptype == 'klipper':
        return fetch_klipper_data(p)
    if ptype == 'prusa':
        return fetch_prusalink_data(p)
    if ptype == 'bambu':
        return fetch_bambu_data(p)
    if ptype == 'centauri':
        return fetch_centauri_data(p)
    return {'state': 'Config Error', 'error': f"Unknown type '{ptype}'"}

def get_image_src(printer_config):
    # Do NOT use placeholders; return empty when there is no image.
    if printer_config.get('local_image_filename'):
        return url_for('static', filename=f"printer_images/{printer_config['local_image_filename']}")
    if printer_config.get('image_url'):
        return printer_config['image_url']
    return ""

def fetch_all(printers):
    result = {}
    for p in printers:
        data = fetch_printer(p)
        if not p.get('show_filename', True):
            data['filename'] = None
        result[p['name']] = {
            **data,
            'image_src': get_image_src(p),
            'show_filename': p.get('show_filename', True),
            'type': p.get('type'),
            'accepts_uploads': p.get('accepts_uploads', True)
        }
    return result

# --- HELPERS (signup feedback) --------------------------------------------
def _stash_signup_feedback(errors, values):
    """Preserve signup input and errors across the redirect to reopen signup modal."""
    session['signup_errors'] = errors
    session['signup_values'] = {k: v for k, v in values.items() if k != 'password'}
    session['open_signup_modal'] = True

# --- FLASK ROUTES ----------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def root():
    config = get_full_config()
    users = load_users()

    # LOGIN
    if request.method == 'POST':
        username = normalize_username(request.form.get('username'))
        password = request.form.get('password')
        user_data = users.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            session['username'] = username
            session['role'] = user_data.get('role', 'intern')
            logging.info(f"User '{username}' (Role: {session['role']}) logged in.")
            flash('Logged in successfully!', 'success')
        else:
            logging.warning(f"Failed login for username: '{username}'.")
            flash('Invalid username or password.', 'danger')
        return redirect(url_for('root'))

    dashboard_title = config.get('dashboard_title', 'Printer Dashboard')

    # permissions for current user
    user_permissions = []
    user_can_upload = False
    user_can_view_filenames = False
    if 'username' in session:
        roles = load_data(ROLES_FILE, {})
        user_role = session.get('role', '')
        user_permissions = roles.get(user_role, {}).get('permissions', [])
        if '*' in user_permissions:
            user_permissions = get_available_permissions()
        if 'upload_gcode' in user_permissions:
            user_can_upload = True
        if 'view_file_names' in user_permissions:
            user_can_view_filenames = True

    # signup UX handoff
    allow_signup = bool(config.get('enable_self_signup', False))
    signup_values = session.pop('signup_values', {})
    signup_errors = session.pop('signup_errors', {})
    open_signup_modal = session.pop('open_signup_modal', False)

    return render_template(
        'public_dashboard.html',
        dashboard_title=dashboard_title,
        config=config,
        users=users,
        user_permissions=user_permissions,
        user_can_upload=user_can_upload,
        user_can_view_filenames=user_can_view_filenames,
        allow_signup=allow_signup,
        signup_values=signup_values,
        signup_errors=signup_errors,
        open_signup_modal=open_signup_modal
    )

@app.route('/logout')
def logout():
    if 'original_role' in session:
        original_role = session.pop('original_role')
        session['role'] = original_role
        flash(f"Returned to your original account ({original_role}).", 'info')
        return redirect(url_for('admin'))

    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('root'))

@app.route('/login_as/<role_name>', methods=['POST'])
def login_as(role_name):
    if 'username' not in session:
        return redirect(url_for('root'))

    actual_role = session.get('original_role', session.get('role'))

    if actual_role not in ['system', 'super_user']:
        flash('You do not have permission to use this feature.', 'danger')
        return redirect(url_for('admin'))

    roles = load_data(ROLES_FILE, {})
    if role_name not in roles:
        flash(f"Role '{role_name}' does not exist.", 'danger')
        return redirect(url_for('admin'))

    if 'original_role' not in session:
        session['original_role'] = session['role']

    session['role'] = role_name
    flash(f"You are now viewing the dashboard as a '{role_name}'. Use Logout to return.", 'success')
    return redirect(url_for('root'))

# --- ACCOUNT ---------------------------------------------------------------
@app.route('/account')
@require_permission('view_dashboard')
def manage_account():
    users = load_users()
    user_data = users.get(session['username'])
    return render_template('account.html', user=user_data)

@app.route('/update_account', methods=['POST'])
@require_permission('view_dashboard')
def update_account():
    users = load_users()
    username = session['username']

    users[username]['name'] = request.form.get('full_name')
    users[username]['email'] = request.form.get('email')

    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if new_password:
        if new_password == confirm_password:
            users[username]['password'] = generate_password_hash(new_password)
            flash('Your account details and password have been updated.', 'success')
        else:
            flash('Passwords do not match. Your name and email were updated, but your password was not.', 'danger')
    else:
        flash('Your account details have been updated.', 'success')

    save_data(users, USERS_FILE)
    return redirect(url_for('manage_account'))

# --- STATUS API ------------------------------------------------------------
def get_status_data():
    printers = load_data(PRINTERS_FILE, [])
    now = time.time()
    cache = app.config.get('cache', {'ts': 0, 'data': {}})
    if now - cache['ts'] > CACHE_TTL:
        app.config['cache'] = {'ts': now, 'data': fetch_all(printers)}
    return app.config['cache'].get('data', {})

@app.route('/status_json')
def status_json():
    try:
        status_data = get_status_data()
        config = get_full_config()
        overrides = load_data(OVERRIDES_FILE, {})
        aliases = config.get('status_aliases', {})

        # Determine if current user has permission to view file names
        roles = load_data(ROLES_FILE, {})
        user_permissions = []
        if 'username' in session:
            user_role = session.get('role', '')
            user_permissions = roles.get(user_role, {}).get('permissions', [])
            if '*' in user_permissions:
                user_permissions = get_available_permissions()
        can_view_filenames = 'view_file_names' in user_permissions

        processed_data = {}
        for name, data in status_data.items():
            processed = data.copy()
            if name in overrides and overrides[name].get('status'):
                processed['state'] = overrides[name]['status']
            original_state = processed.get('state')
            if original_state in aliases and aliases[original_state]:
                processed['state'] = aliases[original_state]
            if not can_view_filenames or not processed.get('show_filename', True):
                processed['filename'] = None
            processed_data[name] = processed

        kiosk_id = request.args.get('kiosk')
        response = {**processed_data, 'config': config, 'can_view_filenames': can_view_filenames}
        if kiosk_id:
            response['kiosk_config'] = get_kiosk_config(kiosk_id)
        return jsonify(response)
    except Exception as e:
        logging.exception("status_json failed")
        return jsonify({"error": "status_unavailable"}), 500

# --- ADMIN -----------------------------------------------------------------
@app.route('/admin')
@require_permission('admin_panel_access')
def admin():
    printers = load_data(PRINTERS_FILE, [])
    overrides = load_data(OVERRIDES_FILE, {})
    users = load_users()
    roles = load_data(ROLES_FILE, {})
    config = get_full_config()
    kiosk_configs = list_kiosk_configs()

    user_role_name = session.get('role', '')
    user_permissions = roles.get(user_role_name, {}).get('permissions', [])
    if '*' in user_permissions:
        user_permissions = get_available_permissions()

    can_manage_users = any(p in user_permissions for p in [
        'add_user', 'edit_user', 'delete_user', 'change_user_password', 'change_user_role'
    ])
    can_manage_roles = any(p in user_permissions for p in [
        'add_role', 'edit_role', 'delete_role'
    ])

    # live statuses + all statuses for config UI
    live_statuses = fetch_all(printers)

    all_statuses = set(config.get('manual_statuses', []))
    for status_key in config.get('status_colors', {}).keys():
        # convert snake to Title
        all_statuses.add(status_key.replace('_', ' ').title())
    for printer_data in live_statuses.values():
        if printer_data.get('state'):
            all_statuses.add(printer_data['state'])

    # ensure alias targets/sources are in all_statuses
    for src, tgt in (config.get('status_aliases') or {}).items():
        if src: all_statuses.add(src)
        if tgt: all_statuses.add(tgt)

    log_content = ""
    if 'view_logs' in user_permissions:
        try:
            with open(LOG_FILE, 'r') as f:
                log_content = f.read()
        except FileNotFoundError:
            log_content = "Log file not found."

    perms = get_available_permissions()
    permitted_kiosks = {kid: conf for kid, conf in kiosk_configs.items() if has_kiosk_permission(user_permissions, kid)}
    active_tab = request.args.get('tab', 'printer-config')
    selected_kiosk = request.args.get('kiosk', 'default')

    print_jobs = load_data(PRINT_JOBS_FILE, [])
    pending_jobs = [job for job in print_jobs if job['status'] == 'pending']

    # Friendly labels (if you choose to use them in the template)
    permission_labels = {
        'view_dashboard': 'View Dashboard',
        'admin_panel_access': 'Access Admin Panel',
        'set_overrides': 'Set Status Overrides',
        'view_logs': 'View Logs',
        'add_printer': 'Add Printer',
        'edit_printer': 'Edit Printer',
        'delete_printer': 'Delete Printer',
        'add_user': 'Add User',
        'edit_user': 'Edit User',
        'delete_user': 'Delete User',
        'change_user_password': 'Change User Password',
        'change_user_role': 'Change User Role',
        'add_role': 'Add Role',
        'edit_role': 'Edit Role',
        'delete_role': 'Delete Role',
        'manage_appearance': 'Manage Appearance',
        'manage_statuses': 'Manage Statuses',
        'manage_aliases': 'Manage Status Aliases',
        'add_kiosk': 'Add Kiosk',
        'delete_kiosk': 'Delete Kiosk',
        'rename_kiosk': 'Rename Kiosk',
        'manage_kiosk_settings': 'Manage Kiosk Settings',
        'manage_printer_kiosks': 'Manage Printer Kiosks',
        'manage_image_kiosks': 'Manage Image Kiosks',
        'manage_kiosk_images': 'Manage Kiosk Images',
        'upload_gcode': 'Upload G-code',
        'approve_prints': 'Approve/Stop Prints',
        'view_file_names': 'View File Names'
    }

    return render_template(
        'admin.html',
        printers=printers, overrides=overrides, users=users, roles=roles,
        config=config,
        kiosk_configs=kiosk_configs, permitted_kiosks=permitted_kiosks,
        manual_statuses=config.get('manual_statuses', []),
        all_statuses=sorted(list(all_statuses)),
        available_permissions=perms,
        permission_labels=permission_labels,
        log_content=log_content,
        user_permissions=user_permissions,
        can_manage_users=can_manage_users,
        can_manage_roles=can_manage_roles,
        active_tab=active_tab, selected_kiosk=selected_kiosk,
        pending_jobs=pending_jobs, live_statuses=live_statuses
    )

# --- ADMIN: printer management --------------------------------------------
@app.route('/admin/printers', methods=['POST'])
def manage_printers():
    active_tab = request.form.get('active_tab', 'printer-config')
    action = request.form.get('action')
    if action == 'add_printer':
        return add_printer(active_tab)
    elif action == 'delete_printer':
        return delete_printer(active_tab)
    elif action == 'edit_printer':
        return edit_printer_modal(active_tab)
    flash('Invalid action specified.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('add_printer')
def add_printer(active_tab):
    printers = load_data(PRINTERS_FILE, [])
    new_printer = {k: request.form.get(k) for k in
                   ['name', 'type', 'url', 'ip', 'api_key', 'access_code', 'serial', 'image_url', 'toolheads']}
    new_printer['show_filename'] = 'show_filename' in request.form
    new_printer['accepts_uploads'] = 'accepts_uploads' in request.form
    if 'image_file' in request.files:
        file = request.files['image_file']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['PRINTER_UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['PRINTER_UPLOAD_FOLDER'], filename))
            new_printer['local_image_filename'] = filename
            new_printer['image_url'] = ''
    required = {
        'prusa': ['ip', 'api_key'],
        'klipper': ['url'],
        'bambu': ['ip', 'access_code'],
        'centauri': ['url']
    }
    missing = [f for f in required.get(new_printer.get('type'), []) if not new_printer.get(f)]
    if missing:
        flash(f"Missing required fields for {new_printer.get('type')} printer: {', '.join(missing)}.", 'danger')
        return redirect(url_for('admin', tab=active_tab))
    if any(p['name'] == new_printer['name'] for p in printers):
        flash(f"A printer with the name '{new_printer['name']}' already exists.", 'danger')
    else:
        printers.append({k: v for k, v in new_printer.items() if v not in [None, ""]} | {
            'show_filename': new_printer['show_filename'],
            'accepts_uploads': new_printer['accepts_uploads']
        })
        save_data(printers, PRINTERS_FILE)
        flash(f"Printer '{new_printer['name']}' added.", 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('delete_printer')
def delete_printer(active_tab):
    printers = load_data(PRINTERS_FILE, [])
    printer_name = request.form.get('name')
    printers = [p for p in printers if p.get('name') != printer_name]
    save_data(printers, PRINTERS_FILE)
    flash(f"Printer '{printer_name}' deleted.", 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('edit_printer')
def edit_printer_modal(active_tab):
    printers = load_data(PRINTERS_FILE, [])
    original_name = request.form.get('original_name')
    printer_to_edit = next((p for p in printers if p['name'] == original_name), None)
    if not printer_to_edit:
        flash('Printer not found.', 'danger')
        return redirect(url_for('admin', tab=active_tab))

    updated_data = printer_to_edit.copy()
    form_data = {k: request.form.get(k) for k in
                 ['name', 'type', 'url', 'ip', 'api_key', 'access_code', 'serial', 'image_url', 'toolheads']}
    updated_data.update(form_data)
    updated_data['show_filename'] = 'show_filename' in request.form
    updated_data['accepts_uploads'] = 'accepts_uploads' in request.form
    if 'image_file' in request.files:
        file = request.files['image_file']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(app.config['PRINTER_UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['PRINTER_UPLOAD_FOLDER'], filename))
            updated_data['local_image_filename'] = filename
            updated_data['image_url'] = ''
    required = {
        'prusa': ['ip', 'api_key'],
        'klipper': ['url'],
        'bambu': ['ip', 'access_code'],
        'centauri': ['url']
    }
    missing = [f for f in required.get(updated_data.get('type'), []) if not updated_data.get(f)]
    if missing:
        flash(f"Missing required fields for {updated_data.get('type')} printer: {', '.join(missing)}.", 'danger')
        return redirect(url_for('admin', tab=active_tab))
    for i, p in enumerate(printers):
        if p['name'] == original_name:
            printers[i] = {k: v for k, v in updated_data.items() if v not in [None, ""]} | {
                'show_filename': updated_data['show_filename'],
                'accepts_uploads': updated_data['accepts_uploads']
            }
    save_data(printers, PRINTERS_FILE)
    flash(f"Printer '{updated_data['name']}' updated.", 'success')
    return redirect(url_for('admin', tab=active_tab))

# --- ADMIN: overrides ------------------------------------------------------
@app.route('/admin/overrides', methods=['POST'])
@require_permission('set_overrides')
def manage_overrides():
    active_tab = request.form.get('active_tab', 'printer-config')
    overrides = load_data(OVERRIDES_FILE, {})
    printer_name = request.form.get('name')
    status_override = request.form.get('status_override')
    if status_override:
        overrides[printer_name] = {'status': status_override}
    elif printer_name in overrides:
        del overrides[printer_name]
    save_data(overrides, OVERRIDES_FILE)
    flash(f"Override for '{printer_name}' updated.", 'success')
    return redirect(url_for('admin', tab=active_tab))

# --- ADMIN: users ----------------------------------------------------------
@app.route('/admin/users', methods=['POST'])
def manage_users():
    active_tab = request.form.get('active_tab', 'user-role')
    action = request.form.get('action')
    if action == 'add_user':
        return add_user(active_tab)
    elif action == 'delete_user':
        return delete_user(active_tab)
    elif action == 'edit_user':
        return edit_user(active_tab)
    flash('Invalid user action.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('add_user')
def add_user(active_tab):
    users = load_users()
    roles = load_data(ROLES_FILE, {})
    logged_in_role_level = int(roles.get(session.get('role'), {}).get('level', 0))
    username = normalize_username(request.form.get('username'))
    password = request.form.get('password')
    role = request.form.get('role')
    full_name = request.form.get('full_name', username).strip()
    email = (request.form.get('email', '') or '').strip()

    if not username or not password or not role:
        flash('Username, password, and role are required.', 'danger')
        return redirect(url_for('admin', tab=active_tab))

    if username in users:
        flash('That username is already taken.', 'danger')
        return redirect(url_for('admin', tab=active_tab))

    if email:
        email_lower = email.lower()
        for u in users.values():
            if (u.get('email') or '').strip().lower() == email_lower:
                flash('An account with that email already exists.', 'danger')
                return redirect(url_for('admin', tab=active_tab))

    if int(roles.get(role, {}).get('level', 999)) >= logged_in_role_level and session.get('role') != 'system':
        flash('You cannot create a user with a role equal to or higher than your own.', 'danger')
    else:
        users[username] = {
            'password': generate_password_hash(password),
            'role': role,
            'name': full_name,
            'email': email
        }
        save_data(users, USERS_FILE)
        flash(f"User '{username}' added.", 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('edit_user')
def edit_user(active_tab):
    users = load_users()
    original_username = normalize_username(request.form.get('original_username'))
    new_username = normalize_username(request.form.get('new_username')) or original_username

    if original_username not in users:
        flash('User not found.', 'danger')
        return redirect(url_for('admin', tab=active_tab))

    # username collision
    if new_username != original_username and new_username in users:
        flash(f"Username '{new_username}' already exists.", 'danger')
        return redirect(url_for('admin', tab=active_tab))

    user_data = users.pop(original_username)

    # email uniqueness if changed
    new_email = (request.form.get('email') or '').strip()
    if new_email:
        email_lower = new_email.lower()
        for uname, u in users.items():
            if (u.get('email') or '').strip().lower() == email_lower:
                flash('Another account already uses that email.', 'danger')
                users[original_username] = user_data  # revert pop
                return redirect(url_for('admin', tab=active_tab))

    user_data['name'] = request.form.get('full_name') or user_data.get('name', '')
    user_data['email'] = new_email
    user_data['role'] = request.form.get('role') or user_data.get('role', '')

    new_password = request.form.get('new_password')
    if new_password:
        user_data['password'] = generate_password_hash(new_password)

    users[new_username] = user_data
    save_data(users, USERS_FILE)
    flash(f"User '{original_username}' updated successfully.", 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('delete_user')
def delete_user(active_tab):
    users = load_users()
    roles = load_data(ROLES_FILE, {})
    logged_in_role_level = int(roles.get(session.get('role'), {}).get('level', 0))
    username_to_delete = normalize_username(request.form.get('username'))
    if username_to_delete in users and int(roles.get(users[username_to_delete]['role'], {}).get('level', 999)) < logged_in_role_level:
        del users[username_to_delete]
        save_data(users, USERS_FILE)
        flash(f"User '{username_to_delete}' deleted.", 'success')
    else:
        flash('Cannot delete that user.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

# --- ADMIN: roles ----------------------------------------------------------
@app.route('/admin/roles', methods=['POST'])
def manage_roles():
    active_tab = request.form.get('active_tab', 'user-role')
    action = request.form.get('action')
    if action == 'add_role':
        return add_role(active_tab)
    elif action == 'delete_role':
        return delete_role(active_tab)
    elif action == 'edit_role':
        return edit_role_post(active_tab)
    flash('Invalid role action.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('add_role')
def add_role(active_tab):
    roles = load_data(ROLES_FILE, {})
    role_name = (request.form.get('role_name') or '').lower().replace(' ', '_')
    permissions = request.form.getlist('permissions')
    level = int(request.form.get('level', 1))
    user_role_name = session.get('role', '')
    user_permissions = roles.get(user_role_name, {}).get('permissions', [])
    if '*' in user_permissions:
        user_permissions = get_available_permissions()
    if role_name and role_name not in roles:
        allowed_perms = [p for p in permissions if p in user_permissions]
        roles[role_name] = {'permissions': allowed_perms, 'level': level}
        save_data(roles, ROLES_FILE)
        flash(f"Role '{role_name}' created.", 'success')
    else:
        flash('Invalid name or role already exists.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('delete_role')
def delete_role(active_tab):
    roles = load_data(ROLES_FILE, {})
    role_name = request.form.get('role_name')
    if role_name in roles and role_name not in ['system', 'super_user', 'admin', 'intern']:
        del roles[role_name]
        save_data(roles, ROLES_FILE)
        flash(f"Role '{role_name}' deleted.", 'success')
    else:
        flash('Cannot delete a core role.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('edit_role')
def edit_role_post(active_tab):
    roles = load_data(ROLES_FILE, {})
    role_name = request.form.get('role_name')
    role_to_edit = roles.get(role_name)
    if not role_to_edit or role_name == 'system':
        flash('Role not found or cannot be edited.', 'danger')
        return redirect(url_for('admin', tab=active_tab))
    permissions = request.form.getlist('permissions')
    level = int(request.form.get('level', 1))
    user_role_name = session.get('role', '')
    user_permissions = set(roles.get(user_role_name, {}).get('permissions', []))
    if '*' in user_permissions:
        user_permissions = set(get_available_permissions())
    current_perms = set(role_to_edit.get('permissions', []))
    final_perms = set(current_perms)
    requested_perms = set(permissions)
    for perm in user_permissions:
        if perm in requested_perms:
            final_perms.add(perm)
        else:
            final_perms.discard(perm)
    roles[role_name]['permissions'] = sorted(final_perms)
    roles[role_name]['level'] = level
    save_data(roles, ROLES_FILE)
    flash(f"Role '{role_name}' updated.", 'success')
    return redirect(url_for('admin', tab='user-role'))

# --- ADMIN: config ---------------------------------------------------------
@app.route('/admin/config', methods=['POST'])
def manage_config():
    active_tab = request.form.get('active_tab', 'printer-config')
    action = request.form.get('action')
    if action == 'update_appearance':
        return update_appearance(active_tab)
    elif action == 'update_kiosk':
        return update_kiosk(active_tab)
    elif action == 'update_colors':
        return update_colors(active_tab)
    elif action == 'add_status':
        return add_status(active_tab)
    elif action == 'delete_status':
        return delete_status(active_tab)
    elif action == 'update_aliases':
        return update_aliases(active_tab)
    elif action == 'update_signup_settings':
        return update_signup_settings(active_tab)
    flash('Invalid config action.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('manage_appearance')
def update_appearance(active_tab):
    config = get_full_config()
    config['dashboard_title'] = request.form.get('dashboard_title', 'Printer Dashboard')
    if 'dashboard_title_image_file' in request.files:
        file = request.files['dashboard_title_image_file']
        if file and file.filename and allowed_file(file.filename):
            os.makedirs(app.config['ASSETS_UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(f"title_logo_{file.filename}")
            file.save(os.path.join(app.config['ASSETS_UPLOAD_FOLDER'], filename))
            config['dashboard_title_image'] = url_for('static', filename=f"assets/{filename}")
    config['dashboard_title_image_height'] = int(request.form.get('dashboard_title_image_height', config.get('dashboard_title_image_height', 40)))
    config['dashboard_title_image_position'] = request.form.get('dashboard_title_image_position', config.get('dashboard_title_image_position', 'left'))
    config['card_size'] = request.form.get('card_size', 'medium')
    config['font_family'] = request.form.get('font_family', 'sans-serif')
    config['sort_by'] = request.form.get('sort_by', 'manual')
    # manual orders
    po = request.form.get('printer_order', '') or ''
    so = request.form.get('status_order', '') or ''
    config['printer_order'] = [name.strip() for name in po.split(',') if name.strip()]
    config['status_order'] = [name.strip() for name in so.split(',') if name.strip()]
    # progress colors
    config['progress_bar_color'] = request.form.get('progress_bar_color', '#007bff')
    config['progress_bar_text_color'] = request.form.get('progress_bar_text_color', '#ffffff')
    config['refresh_interval_sec'] = int(request.form.get('refresh_interval_sec', 30))
    # top bar color
    config['top_bar_color'] = request.form.get('top_bar_color', config.get('top_bar_color', '#007bff'))
    # status bar items (multi-value)
    items = request.form.getlist('status_summary_items')
    if items:
        config['status_summary_items'] = items
    save_data(config, CONFIG_FILE)
    flash('Dashboard appearance and layout updated.', 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('manage_kiosk_settings')
def update_kiosk(active_tab):
    kiosk_id = request.form.get('kiosk_id', 'default')
    kiosk_config = get_kiosk_config(kiosk_id)
    kiosk_specific_dir = os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], kiosk_id)
    os.makedirs(kiosk_specific_dir, exist_ok=True)
    if kiosk_config.get('show_printers'):
        kiosk_config['kiosk_printers_per_page'] = int(request.form.get('kiosk_printers_per_page', 6))
        kiosk_config['kiosk_printer_page_time'] = int(request.form.get('kiosk_printer_page_time', 10))
        kiosk_config['kiosk_image_frequency'] = int(request.form.get('kiosk_image_frequency', 2))
        kiosk_config['kiosk_images_per_slot'] = int(request.form.get('kiosk_images_per_slot', 1))
        kiosk_config['kiosk_sort_by'] = request.form.get('kiosk_sort_by', 'manual')
        kiosk_config['kiosk_title'] = request.form.get('kiosk_title', '')
        kiosk_config['kiosk_header_height_px'] = int(request.form.get('kiosk_header_height_px', 150))
        if 'kiosk_header_image_file' in request.files:
            file = request.files['kiosk_header_image_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"header_{file.filename}")
                file.save(os.path.join(kiosk_specific_dir, filename))
                kiosk_config['kiosk_header_image'] = url_for('static', filename=f"kiosk_images/{kiosk_id}/{filename}")
    kiosk_config['kiosk_image_page_time'] = int(request.form.get('kiosk_image_page_time', 5))
    kiosk_config['kiosk_background_color'] = request.form.get('kiosk_background_color', '#000000')
    kiosk_config['kiosk_font_size'] = int(request.form.get('kiosk_font_size', 100))
    kiosk_config['kiosk_dark_mode'] = 'kiosk_dark_mode' in request.form
    name = request.form.get('kiosk_name')
    if name:
        kiosk_config['name'] = name
    save_data(kiosk_config, os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))
    flash(f"Kiosk '{kiosk_id}' settings updated.", 'success')
    return redirect(url_for('admin', tab=active_tab, kiosk=kiosk_id))

@require_permission('manage_statuses')
def update_colors(active_tab):
    config = get_full_config()
    # take all submitted colors except control fields
    new_colors = {}
    for key, value in request.form.items():
        if key in ['active_tab', 'action']:
            continue
        # store lower_snake keys
        new_colors[key] = value
    config['status_colors'] = new_colors
    save_data(config, CONFIG_FILE)
    flash('Status colors updated.', 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('manage_statuses')
def add_status(active_tab):
    config = get_full_config()
    new_status = request.form.get('new_status_name')
    if new_status and new_status not in config.get('manual_statuses', []):
        config.setdefault('manual_statuses', []).append(new_status)
        config.setdefault('status_colors', {})[new_status.lower().replace(' ', '_')] = '#6c757d'
        save_data(config, CONFIG_FILE)
        flash(f"Status '{new_status}' added.", 'success')
    else:
        flash('Invalid name or status already exists.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('manage_statuses')
def delete_status(active_tab):
    config = get_full_config()
    status_to_delete = request.form.get('status_name')
    if status_to_delete in config.get('manual_statuses', []):
        config['manual_statuses'].remove(status_to_delete)
        config.get('status_colors', {}).pop(status_to_delete.lower().replace(' ', '_'), None)
        save_data(config, CONFIG_FILE)
        flash(f"Status '{status_to_delete}' deleted.", 'success')
    else:
        flash('Status not found.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('manage_aliases')
def update_aliases(active_tab):
    config = get_full_config()
    aliases = {}
    for key, value in request.form.items():
        if key.startswith('alias_'):
            original_status = key.replace('alias_', '')
            aliases[original_status] = value or None
    config['status_aliases'] = {k: v for k, v in aliases.items() if v}
    save_data(config, CONFIG_FILE)
    flash('Status aliases updated.', 'success')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('add_user')
def update_signup_settings(active_tab):
    """Enable/disable self-signup and set default signup role."""
    config = get_full_config()
    enable = bool(request.form.get('enable_self_signup'))
    default_role = request.form.get('default_signup_role') or config.get('default_signup_role', 'member')
    roles = load_data(ROLES_FILE, {})
    if default_role not in roles:
        flash(f"Default signup role '{default_role}' does not exist.", 'danger')
        return redirect(url_for('admin', tab=active_tab))
    config['enable_self_signup'] = enable
    config['default_signup_role'] = default_role
    save_data(config, CONFIG_FILE)
    flash('Signup settings updated.', 'success')
    return redirect(url_for('admin', tab=active_tab))

# --- ADMIN: kiosk images ---------------------------------------------------
@app.route('/admin/kiosk_images', methods=['POST'])
@require_permission('manage_kiosk_images')
def manage_kiosk_images():
    active_tab = request.form.get('active_tab', 'kiosk-control')
    kiosk_id = request.form.get('kiosk_id', 'default')
    kiosk_config = get_kiosk_config(kiosk_id)
    kiosk_specific_dir = os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], kiosk_id)
    os.makedirs(kiosk_specific_dir, exist_ok=True)

    new_kiosk_images = []
    image_urls = request.form.getlist('url')
    image_times = request.form.getlist('time')
    image_actives = set(request.form.getlist('active'))
    delete_urls = set(request.form.getlist('delete_url'))

    for i in range(len(image_urls)):
        url = image_urls[i]
        if url in delete_urls:
            continue
        new_kiosk_images.append({
            'url': url,
            'time': int(image_times[i]),
            'active': url in image_actives
        })

    kiosk_config['kiosk_images'] = new_kiosk_images

    if 'kiosk_image_files' in request.files:
        files = request.files.getlist('kiosk_image_files')
        default_time = kiosk_config.get('kiosk_image_page_time', 5)
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(kiosk_specific_dir, filename))
                image_url = url_for('static', filename=f"kiosk_images/{kiosk_id}/{filename}")
                if not any(img['url'] == image_url for img in kiosk_config['kiosk_images']):
                    kiosk_config['kiosk_images'].append({'url': image_url, 'time': default_time, 'active': True})

    save_data(kiosk_config, os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))

    for del_url in delete_urls:
        filename = os.path.basename(urlparse(del_url).path)
        file_path = os.path.join(kiosk_specific_dir, filename)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            logging.warning(f"Failed to delete kiosk image {file_path}")

    flash(f"Kiosk '{kiosk_id}' images updated.", 'success')
    return redirect(url_for('admin', tab='kiosk-control', kiosk=kiosk_id))

@app.route('/admin/kiosks', methods=['POST'], endpoint='manage_kiosks')
def manage_kiosks():
    active_tab = request.form.get('active_tab', 'kiosk-management')
    action = request.form.get('action')
    if action == 'add_kiosk':
        return add_kiosk(active_tab)
    elif action == 'delete_kiosk':
        return delete_kiosk(active_tab)
    elif action == 'rename_kiosk':
        return rename_kiosk(active_tab)
    elif action == 'edit_kiosk':
        return edit_kiosk(active_tab)
    flash('Invalid kiosk action.', 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('add_kiosk')
def add_kiosk(active_tab):
    kiosk_id = secure_filename((request.form.get('kiosk_id') or '').strip())
    if not kiosk_id:
        flash('Kiosk ID required.', 'danger')
        return redirect(url_for('admin', tab=active_tab))
    path = os.path.join(KIOSK_DIR, f"{kiosk_id}.json")
    if os.path.exists(path):
        flash(f"Kiosk with ID '{kiosk_id}' already exists.", 'danger')
    else:
        kiosk_image_dir = os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], kiosk_id)
        os.makedirs(kiosk_image_dir, exist_ok=True)
        config = DEFAULT_KIOSK_CONFIG.copy()
        config['name'] = request.form.get('kiosk_name', kiosk_id)
        config['show_printers'] = 'show_printers' in request.form
        save_data(config, path)
        flash(f"Kiosk '{kiosk_id}' added and image directory created.", 'success')
    return redirect(url_for('admin', tab=active_tab, kiosk=kiosk_id))

@require_permission('delete_kiosk')
def delete_kiosk(active_tab):
    kiosk_id = secure_filename((request.form.get('kiosk_id') or '').strip())
    try:
        os.remove(os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))
        kiosk_image_dir = os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], kiosk_id)
        if os.path.isdir(kiosk_image_dir):
            shutil.rmtree(kiosk_image_dir)
        flash(f"Kiosk '{kiosk_id}' and its assets have been deleted.", 'success')
    except FileNotFoundError:
        flash(f"Kiosk '{kiosk_id}' not found.", 'danger')
    return redirect(url_for('admin', tab=active_tab))

@require_permission('rename_kiosk')
def rename_kiosk(active_tab):
    old_kiosk_id = secure_filename((request.form.get('old_kiosk_id') or '').strip())
    new_kiosk_id = secure_filename((request.form.get('new_kiosk_id') or '').strip())
    new_kiosk_name = request.form.get('new_kiosk_name', new_kiosk_id)
    if not old_kiosk_id or not new_kiosk_id:
        flash('Both old and new Kiosk IDs are required.', 'danger')
        return redirect(url_for('admin', tab=active_tab))
    old_json_path = os.path.join(KIOSK_DIR, f"{old_kiosk_id}.json")
    new_json_path = os.path.join(KIOSK_DIR, f"{new_kiosk_id}.json")
    old_asset_path = os.path.join(KIOSK_UPLOAD_FOLDER, old_kiosk_id)
    new_asset_path = os.path.join(KIOSK_UPLOAD_FOLDER, new_kiosk_id)
    if not os.path.exists(old_json_path):
        flash(f"Kiosk '{old_kiosk_id}' not found.", 'danger')
        return redirect(url_for('admin', tab=active_tab))
    if os.path.exists(new_json_path):
        flash(f"A kiosk with the ID '{new_kiosk_id}' already exists.", 'danger')
        return redirect(url_for('admin', tab=active_tab))
    try:
        os.rename(old_json_path, new_json_path)
        if os.path.isdir(old_asset_path):
            os.rename(old_asset_path, new_asset_path)
        kiosk_config = load_data(new_json_path, {})
        kiosk_config['name'] = new_kiosk_name
        if kiosk_config.get('kiosk_header_image'):
            kiosk_config['kiosk_header_image'] = kiosk_config['kiosk_header_image'].replace(f'/{old_kiosk_id}/', f'/{new_kiosk_id}/')
        if kiosk_config.get('kiosk_images'):
            for img in kiosk_config['kiosk_images']:
                img['url'] = img['url'].replace(f'/{old_kiosk_id}/', f'/{new_kiosk_id}/')
        save_data(kiosk_config, new_json_path)
        roles = load_data(ROLES_FILE, {})
        old_perm = f"manage_kiosk_{old_kiosk_id}"
        new_perm = f"manage_kiosk_{new_kiosk_id}"
        for role_name, role_data in roles.items():
            if 'permissions' in role_data and old_perm in role_data['permissions']:
                role_data['permissions'].remove(old_perm)
                if new_perm not in role_data['permissions']:
                    role_data['permissions'].append(new_perm)
        save_data(roles, ROLES_FILE)
        flash(f"Kiosk '{old_kiosk_id}' successfully renamed to '{new_kiosk_id}'.", 'success')
    except Exception as e:
        flash(f"An error occurred while renaming: {e}", 'danger')
        if os.path.exists(new_json_path) and not os.path.exists(old_json_path):
            os.rename(new_json_path, old_json_path)
        if os.path.isdir(new_asset_path) and not os.path.isdir(old_asset_path):
            os.rename(new_asset_path, old_asset_path)
    return redirect(url_for('admin', tab=active_tab))

@require_permission('manage_kiosk_settings')
def edit_kiosk(active_tab):
    kiosk_id = secure_filename((request.form.get('kiosk_id') or '').strip())
    if not kiosk_id:
        flash('Kiosk ID is required.', 'danger')
        return redirect(url_for('admin', tab=active_tab))
    kiosk_config = get_kiosk_config(kiosk_id)
    kiosk_config['show_printers'] = 'show_printers' in request.form
    save_data(kiosk_config, os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))
    flash(f"Kiosk '{kiosk_id}' display type updated.", 'success')
    return redirect(url_for('admin', tab=active_tab, kiosk=kiosk_id))

# --- PRINT APPROVALS & ADMIN STOP -----------------------------------------
@app.route('/admin/handle_approval', methods=['POST'])
@require_permission('approve_prints')
def handle_approval():
    job_id = request.form.get('job_id')
    action = request.form.get('action')
    jobs = load_data(PRINT_JOBS_FILE, [])
    target_job = next((job for job in jobs if job['id'] == job_id), None)
    if not target_job:
        flash('Print job not found.', 'danger')
        return redirect(url_for('admin', tab='approvals'))
    if action == 'approve':
        printers = load_data(PRINTERS_FILE, [])
        printer_config = next((p for p in printers if p['name'] == target_job['printer_name']), None)
        if not printer_config:
            flash(f"Printer '{target_job['printer_name']}' not found.", 'danger')
            target_job['status'] = 'failed'
            target_job['approved_by'] = session.get('username')
            save_data(jobs, PRINT_JOBS_FILE)
            return redirect(url_for('admin', tab='approvals'))
        success, message = False, "Unknown printer type"
        if printer_config['type'] == 'klipper':
            success, message = start_klipper_print(printer_config, target_job['gcode_filename'])
        elif printer_config['type'] == 'prusa':
            success, message = start_prusa_print(printer_config, target_job['gcode_filename'])
        elif printer_config['type'] == 'bambu':
            success, message = start_bambu_print(printer_config, target_job['gcode_filename'])
        elif printer_config['type'] == 'centauri':
            success, message = start_centauri_print(printer_config, target_job['gcode_filename'])
        if success:
            target_job['status'] = 'approved'
            target_job['approved_by'] = session.get('username')
            flash(f"Print '{target_job['original_filename']}' approved and sent to printer. {message}", 'success')
            logging.info(f"User '{session.get('username')}' approved print job '{target_job['id']}' for printer '{target_job['printer_name']}'.")
        else:
            target_job['status'] = 'failed'
            target_job['approved_by'] = session.get('username')
            flash(f"Failed to start print: {message}", 'danger')
            logging.error(f"Failed to start print job '{target_job['id']}' on printer '{target_job['printer_name']}': {message}")
    elif action == 'reject':
        target_job['status'] = 'rejected'
        target_job['approved_by'] = session.get('username')
        flash(f"Print '{target_job['original_filename']}' rejected.", 'warning')
        logging.info(f"User '{session.get('username')}' rejected print job '{target_job['id']}'.")
    save_data(jobs, PRINT_JOBS_FILE)
    return redirect(url_for('admin', tab='approvals'))

@app.route('/admin/stop_print', methods=['POST'])
@require_permission('approve_prints')
def admin_stop_print():
    printer_name = request.form.get('printer_name')
    printers = load_data(PRINTERS_FILE, [])
    printer_config = next((p for p in printers if p['name'] == printer_name), None)
    if not printer_config:
        flash('Printer not found.', 'danger')
        return redirect(url_for('admin', tab='approvals'))
    if printer_config['type'] == 'klipper':
        ok, msg = stop_klipper_print(printer_config)
    elif printer_config['type'] == 'prusa':
        ok, msg = stop_prusa_print(printer_config)
    elif printer_config['type'] == 'bambu':
        ok, msg = stop_bambu_print(printer_config)
    elif printer_config['type'] == 'centauri':
        ok, msg = stop_centauri_print(printer_config)
    else:
        ok, msg = False, 'Unknown printer type'
    if ok:
        flash(f"Stopped print on '{printer_name}'.", 'success')
    else:
        flash(f"Failed to stop print on '{printer_name}': {msg}", 'danger')
    return redirect(url_for('admin', tab='approvals'))

# --- UPLOADS ---------------------------------------------------------------
@app.route('/handle_upload', methods=['POST'])
@require_permission('upload_gcode')
def handle_upload():
    printer_name = request.form.get('printer_name')
    comments = request.form.get('comments', '')
    color = request.form.get('color', 'Default')
    priority = request.form.get('priority', 'Normal')
    if 'gcode_file' not in request.files:
        flash('No file part in the request.', 'danger')
        return redirect(request.referrer or url_for('root'))
    file = request.files['gcode_file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(request.referrer or url_for('root'))
    if file and allowed_file(file.filename, ALLOWED_GCODE_EXTENSIONS):
        os.makedirs(app.config['GCODE_UPLOAD_FOLDER'], exist_ok=True)
        original_filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{original_filename}"
        file.save(os.path.join(app.config['GCODE_UPLOAD_FOLDER'], unique_filename))
        jobs = load_data(PRINT_JOBS_FILE, [])
        new_job = {
            "id": unique_filename, "timestamp": datetime.datetime.now().isoformat(),
            "username": session.get('username'), "user_role": session.get('role'),
            "printer_name": printer_name, "original_filename": original_filename,
            "gcode_filename": unique_filename, "comments": comments, "status": "pending",
            "color": color, "priority": priority
        }
        jobs.append(new_job)
        save_data(jobs, PRINT_JOBS_FILE)
        logging.info(f"User '{session.get('username')}' uploaded file '{original_filename}' for printer '{printer_name}'.")
        flash('Print job submitted for approval!', 'success')
        return redirect(url_for('root'))
    else:
        flash('Invalid file type. Only .gcode, .g, .gco are allowed.', 'danger')
        return redirect(request.referrer or url_for('root'))

# --- KIOSK -----------------------------------------------------------------
@app.route('/kiosk')
@app.route('/kiosk/<kiosk_id>')
def kiosk(kiosk_id='default'):
    kiosk_config = get_kiosk_config(kiosk_id)
    # Filter for active images only
    kiosk_config['kiosk_images'] = [img for img in kiosk_config.get('kiosk_images', []) if img.get('active', True)]
    if not kiosk_config.get('show_printers', True):
        return render_template('display.html', kiosk_id=kiosk_id, kiosk_config=kiosk_config)
    return render_template('kiosk.html', kiosk_id=kiosk_id, kiosk_config=kiosk_config)

# --- SELF SIGNUP -----------------------------------------------------------
@app.route('/register', methods=['POST'])
def register():
    cfg = get_full_config()
    if not cfg.get('enable_self_signup', False):
        flash('Self sign-up is currently disabled.', 'danger')
        session['open_signup_modal'] = True
        return redirect(url_for('root'))

    username  = normalize_username(request.form.get('username'))
    password  = (request.form.get('password') or '')
    full_name = (request.form.get('full_name') or username).strip()
    email     = (request.form.get('email') or '').strip()

    errors = {}
    if not username:
        errors['username'] = 'Please enter a username.'
    if not password:
        errors['password'] = 'Please enter a password.'

    users = load_users()

    if username and username in users:
        errors['username'] = 'That username is taken.'

    if email:
        email_lower = email.lower()
        for u in users.values():
            if (u.get('email') or '').strip().lower() == email_lower:
                errors['email'] = 'An account with that email already exists.'
                break

    if errors:
        _stash_signup_feedback(errors, {
            'username': username, 'full_name': full_name, 'email': email, 'password': password
        })
        return redirect(url_for('root'))

    roles = load_data(ROLES_FILE, {})
    default_role = cfg.get('default_signup_role', 'member')
    if default_role not in roles:
        errors['general'] = f"Default signup role '{default_role}' is misconfigured. Ask an admin to fix it."
        _stash_signup_feedback(errors, {
            'username': username, 'full_name': full_name, 'email': email, 'password': password
        })
        return redirect(url_for('root'))

    users[username] = {
        'password': generate_password_hash(password),
        'role': default_role,
        'name': full_name,
        'email': email
    }
    save_data(users, USERS_FILE)
    flash('Account created! You can now log in.', 'success')
    return redirect(url_for('root'))

# Alias so templates can use url_for('signup')
@app.route('/signup', methods=['POST'], endpoint='signup')
def signup_alias():
    return register()

# --- FRIENDLY ERROR HANDLERS ----------------------------------------------
@app.errorhandler(500)
def handle_500(e):
    # If the JSON endpoint fails, return JSON; otherwise, don't lock users out
    logging.exception("Server error")
    if request.path.startswith('/status_json'):
        return jsonify({"error": "internal_server_error"}), 500
    flash('Something went wrong. Please try again.', 'danger')
    # Try to redirect back where they were, otherwise home
    try:
        ref = request.referrer
        if ref:
            return redirect(ref)
    except Exception:
        pass
    return redirect(url_for('root'))

# --- MAIN ------------------------------------------------------------------
if __name__ == '__main__':
    os.makedirs(PRINTER_UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(KIOSK_UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(GCODE_UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(ASSETS_UPLOAD_FOLDER, exist_ok=True)

    if not os.path.exists(ROLES_FILE):
        print("First run: Creating default roles.")
        default_roles = {
            "system": {"permissions": ["*"], "level": 100},
            "super_user": {"permissions": get_available_permissions(), "level": 100},
            "admin": {"permissions": [
                'view_dashboard', 'admin_panel_access', 'set_overrides', 'view_logs',
                'add_printer', 'edit_printer', 'delete_printer',
                'add_kiosk', 'delete_kiosk', 'rename_kiosk',
                'manage_kiosk_settings', 'manage_printer_kiosks', 'manage_image_kiosks', 'manage_kiosk_images',
                'approve_prints', 'edit_user', 'add_user', 'add_role', 'edit_role', 'delete_role',
                'manage_appearance', 'manage_statuses', 'manage_aliases',
                'view_file_names'
            ], "level": 50},
            "member": {"permissions": ["view_dashboard", "upload_gcode", "view_file_names"], "level": 20},
            "assisted_member": {"permissions": ["view_dashboard", "upload_gcode", "view_file_names"], "level": 15},
            "intern": {"permissions": ["view_dashboard", "set_overrides"], "level": 10}
        }
        save_data(default_roles, ROLES_FILE)
    if not os.path.exists(USERS_FILE):
        print("First run: Creating default 'system' and 'admin' users.")
        default_users = {
            'system': {'password': generate_password_hash('changeme'), 'role': 'system', 'name': 'System', 'email': ''},
            'admin': {'password': generate_password_hash('changeme'), 'role': 'admin', 'name': 'Admin', 'email': ''}
        }
        save_data(default_users, USERS_FILE)
    if not os.path.exists(CONFIG_FILE):
        print("First run: Creating default configuration.")
        save_data(get_full_config(), CONFIG_FILE)
    if not os.path.isdir(KIOSK_DIR):
        os.makedirs(KIOSK_DIR, exist_ok=True)
    if not os.path.exists(os.path.join(KIOSK_DIR, 'default.json')):
        print("First run: Creating default kiosk configuration.")
        save_data(get_kiosk_config(), os.path.join(KIOSK_DIR, 'default.json'))
        os.makedirs(os.path.join(KIOSK_UPLOAD_FOLDER, 'default'), exist_ok=True)

    app.run(host='0.0.0.0', port=HTTP_PORT, debug=True)
