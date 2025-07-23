#!/bin/bash
#
# setup_printers.sh (v62 - User-Provided Kiosk Fix)
#
# This script updates the printer aggregator application WITHOUT deleting existing data.
# It will:
# 1. Kill any previously running instance of the app.
# 2. Update the core application files (Python script and HTML templates).
# 3. FIX: Implemented user-provided JavaScript logic for a robust, cycling kiosk view.
#

echo "--- Printer Aggregator Setup (v62 - User-Provided Kiosk Fix) ---"

# --- 1. Stop any existing server process ---
echo "[*] Searching for and stopping any existing server process..."
PIDS=$(pgrep -f "aggregator_with_ui.py")
if [ -n "$PIDS" ]; then
    kill $PIDS
    echo "    > Stopped process(es) with PIDs: $PIDS"
else
    echo "    > No existing process found."
fi

# --- 2. Clean up old application files (PRESERVING DATA) ---
echo "[*] Removing old log file. Your user and printer data will be preserved."
rm -f activity.log
echo "    > Old log file removed."

# Backup existing config file before overwriting
if [ -f config.json ]; then
    mv config.json config.json.bak
    echo "    > Backed up existing config.json to config.json.bak"
fi
rm -f config.json kiosk_config.json

# Recreate directories for templates and images to ensure they are clean
rm -rf templates
mkdir -p templates
echo "    > 'templates' directory is ready."
mkdir -p static/printer_images
chmod 777 static/printer_images
echo "    > 'static/printer_images' directory is ready for uploads."
mkdir -p static/kiosk_images
chmod 777 static/kiosk_images
echo "    > 'static/kiosk_images' directory is ready for uploads."


# --- 4. Write the Python Flask application ---
echo "[*] Writing aggregator_with_ui.py..."
cat > aggregator_with_ui.py << 'EOF'
#!/usr/bin/env python3
"""
aggregator_with_ui.py (v62 - User-Provided Kiosk Fix)

Flask app that:
 - Implements a granular, permission-based RBAC system.
 - Adds a dedicated Kiosk Settings tab and a functional slideshow view.
 - Supports direct uploading of printer and kiosk images.
 - Adds a dedicated sorting option for the kiosk view.
 - The admin panel now dynamically discovers all current printer statuses.
 - Aliased statuses are now hidden from the sort order list for a cleaner UI.
 - Status aliasing is now a dropdown and inherits the target color.
 - Kiosk permissions are more granular.
 - Dashboard and Kiosk views now re-sort automatically on data refresh.
 - Added a configurable refresh interval setting to the admin panel.
 - FIX: Implemented user-provided JavaScript logic for a robust, cycling kiosk view.
 - All other features from previous versions are retained.
"""

import os
import json
import time
import requests
import logging
from flask import Flask, jsonify, request, redirect, url_for, render_template, session, flash, Response
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- CONFIGURATION ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRINTERS_FILE = os.path.join(BASE_DIR, 'printers.json')
OVERRIDES_FILE = os.path.join(BASE_DIR, 'overrides.json')
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
ROLES_FILE = os.path.join(BASE_DIR, 'roles.json')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
KIOSK_CONFIG_FILE = os.path.join(BASE_DIR, 'kiosk_config.json')
LOG_FILE = os.path.join(BASE_DIR, 'activity.log')
PRINTER_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/printer_images')
KIOSK_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/kiosk_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
CACHE_TTL = 5 # Lower TTL for more responsive status discovery
HTTP_PORT = 8080

AVAILABLE_PERMISSIONS = [
    'view_dashboard', 'set_overrides', 'view_logs', 
    'add_printer', 'edit_printer', 'delete_printer',
    'add_user', 'delete_user', 'change_user_password', 'change_user_role',
    'manage_roles', 'manage_config', 'manage_kiosk', 'manage_kiosk_frequency'
]

app = Flask(__name__)
app.secret_key = 'a-very-secret-and-random-key-that-you-should-change'
app.config['PRINTER_UPLOAD_FOLDER'] = PRINTER_UPLOAD_FOLDER
app.config['KIOSK_UPLOAD_FOLDER'] = KIOSK_UPLOAD_FOLDER

# --- LOGGING SETUP ---------------------------------------------------------
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- DATA HANDLING & AUTH --------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_data(file_path, default_data):
    if not os.path.exists(file_path): save_data(default_data, file_path)
    with open(file_path) as f: return json.load(f)

def save_data(data, file_path):
    with open(file_path, 'w') as f: json.dump(data, f, indent=2, sort_keys=True)

def get_full_config():
    """Loads user config and merges it with defaults to ensure all keys exist."""
    defaults = {
        "dashboard_title": "Printer Dashboard",
        "manual_statuses": ["Ready", "Printing", "Under Maintenance", "Offline"],
        "status_colors": {
            "ready": "#28a745", "idle": "#28a745", "operational": "#28a745",
            "printing": "#007bff", "finished": "#007bff", "offline": "#6c757d",
            "error": "#dc3545", "under_maintenance": "#ffc107", "paused": "#6c757d",
            "unsupported": "#6c757d", "config_error": "#dc3545"
        },
        "card_size": "medium", 
        "font_size_printer_name_px": 20,
        "font_size_filename_px": 14,
        "font_size_status_px": 12,
        "font_size_details_px": 14,
        "font_family": "sans-serif",
        "sort_by": "manual", "printer_order": [],
        "status_order": ["Printing", "Ready", "Finished", "Offline", "Error", "Under Maintenance", "Unsupported"],
        "progress_bar_color": "#007bff", "progress_bar_text_color": "#ffffff",
        "progress_bar_font_size_px": 12, "progress_bar_height_px": 14,
        "progress_bar_text_shadow": True, "status_aliases": {"complete": "Finished", "standby": "Ready"},
        "refresh_interval_sec": 30
    }
    user_config = load_data(CONFIG_FILE, defaults)
    full_config = defaults.copy()
    full_config.update(user_config)
    return full_config

def get_kiosk_config():
    defaults = {
        "kiosk_printers_per_page": 6, "kiosk_printer_page_time": 10,
        "kiosk_image_page_time": 5, "kiosk_image_frequency": 2,
        "kiosk_images_per_slot": 1, "kiosk_images": [],
        "kiosk_background_color": "#000000", "kiosk_sort_by": "manual",
        "kiosk_title": "", "kiosk_header_image": ""
    }
    user_config = load_data(KIOSK_CONFIG_FILE, defaults)
    
    if user_config.get('kiosk_images') and all(isinstance(img, str) for img in user_config['kiosk_images']):
        default_time = user_config.get('kiosk_image_page_time', 5)
        user_config['kiosk_images'] = [{'url': url, 'time': default_time} for url in user_config['kiosk_images']]

    full_config = defaults.copy()
    full_config.update(user_config)
    return full_config

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('login'))
            user_role_name = session.get('role', '')
            roles = load_data(ROLES_FILE, {})
            user_permissions = roles.get(user_role_name, {}).get('permissions', [])
            if permission not in user_permissions and '*' not in user_permissions:
                flash('You do not have sufficient permissions for this action.', 'danger')
                return redirect(url_for('admin'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- PRINTER DATA FETCHING -------------------------------------------------
def apply_status_alias(state, aliases):
    return aliases.get(state, state)

def fetch_klipper_data(p):
    if not p.get('url'): return {'state': 'Config Error', 'error': 'Missing URL'}
    try:
        r = requests.get(f"{p['url']}/printer/objects/query?print_stats&display_status&heater_bed&extruder&virtual_sdcard", timeout=5)
        r.raise_for_status()
        res = r.json()['result']['status']
        print_stats = res.get('print_stats', {})
        state = print_stats.get('state', 'unknown').title()
        filename = print_stats.get('filename')
        prog = res.get('virtual_sdcard', {}).get('progress')
        time_elapsed = print_stats.get('print_duration')
        file_progress = res.get('virtual_sdcard', {}).get('progress', 0)
        time_remaining = (time_elapsed / file_progress - time_elapsed) if file_progress > 0 and time_elapsed else None
        return {'state': state, 'filename': filename, 'progress': round(prog * 100, 1) if prog else None, 'bed_temp': round(res.get('heater_bed', {}).get('temperature', 0), 1), 'nozzle_temp': round(res.get('extruder', {}).get('temperature', 0), 1), 'time_elapsed': int(time_elapsed) if time_elapsed else None, 'time_remaining': int(time_remaining) if time_remaining and time_remaining > 0 else None}
    except Exception as e:
        logging.error(f"Klipper fetch for '{p['name']}': {e}")
        return {'state': 'Offline', 'error': str(e)}

def fetch_prusalink_data(p):
    if not p.get('ip') or not p.get('api_key'):
        return {'state': 'Config Error', 'error': 'Missing IP or API Key'}
    try:
        headers = {'X-Api-Key': p['api_key']}
        resp = requests.get(
            f"http://{p['ip']}/api/v1/status",
            headers=headers,
            timeout=5,
        )
        resp.raise_for_status()
        status = resp.json()
        printer = status.get('printer', {})
        job_status = status.get('job', {}) or {}
        state = printer.get('state', 'Unknown').title()

        file_obj = job_status.get('file', {}) if isinstance(job_status, dict) else {}
        filename = (
            file_obj.get('display_name')
            or file_obj.get('name')
            or job_status.get('file_name')
            or job_status.get('filename')
            or file_obj.get('path')
        )

        # If filename is not provided in status, fetch detailed job info
        if not filename and job_status:
            try:
                job_resp = requests.get(
                    f"http://{p['ip']}/api/v1/job",
                    headers=headers,
                    timeout=5,
                )
                if job_resp.status_code == 200:
                    job_data = job_resp.json()
                    file_obj = job_data.get('file', {}) if isinstance(job_data, dict) else {}
                    filename = (
                        file_obj.get('display_name')
                        or file_obj.get('name')
                        or job_data.get('file_name')
                        or job_data.get('filename')
                        or file_obj.get('path')
                    )
            except Exception as e:
                logging.error(f"PrusaLink extra job fetch for '{p['name']}': {e}")

        return {
            'state': state,
            'filename': filename,
            'progress': int(job_status.get('progress')) if job_status.get('progress') is not None else None,
            'bed_temp': round(printer.get('temp_bed'), 1) if printer.get('temp_bed') is not None else None,
            'nozzle_temp': round(printer.get('temp_nozzle'), 1) if printer.get('temp_nozzle') is not None else None,
            'time_elapsed': int(job_status.get('time_printing')) if job_status.get('time_printing') is not None else None,
            'time_remaining': int(job_status.get('time_remaining')) if job_status.get('time_remaining') is not None else None,
        }
    except Exception as e:
        logging.error(f"PrusaLink fetch for '{p['name']}': {e}")
        return {'state': 'Offline', 'error': str(e)}

def fetch_bambulab_data(p):
    return {'state': 'Unsupported', 'error': 'Bambu Lab integration not fully supported.'}

def fetch_printer(p):
    ptype = p.get('type')
    if ptype == 'klipper': return fetch_klipper_data(p)
    if ptype == 'prusa': return fetch_prusalink_data(p)
    if ptype == 'bambulab': return fetch_bambulab_data(p)
    return {'state': 'Config Error', 'error': f"Unknown type '{ptype}'"}

def get_image_src(printer_config):
    if printer_config.get('local_image_filename'):
        return url_for('static', filename=f"printer_images/{printer_config['local_image_filename']}")
    if printer_config.get('image_url'):
        return printer_config['image_url']
    return f"https://via.placeholder.com/400x200/dee2e6/6c757d?text={printer_config.get('name', 'Printer')}"

def fetch_all(printers):
    result = {}
    for p in printers:
        data = fetch_printer(p)
        if not p.get('show_filename', True):
            data['filename'] = None
        result[p['name']] = {**data, 'image_src': get_image_src(p), 'show_filename': p.get('show_filename', True)}
    return result

# --- FLASK ROUTES ----------------------------------------------------------
@app.route('/')
def root(): return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session: return redirect(url_for('admin'))
    if request.method == 'POST':
        users = load_data(USERS_FILE, {})
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = users.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            session['username'] = username
            session['role'] = user_data.get('role', 'intern')
            logging.info(f"User '{username}' (Role: {session['role']}) logged in.")
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin'))
        else:
            logging.warning(f"Failed login for username: '{username}'.")
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def get_status_data():
    """Helper function to fetch and cache printer status data."""
    printers = load_data(PRINTERS_FILE, [])
    now = time.time()
    cache = app.config.get('cache', {'ts': 0, 'data': {}})
    if now - cache['ts'] > CACHE_TTL:
        app.config['cache'] = {'ts': now, 'data': fetch_all(printers)}
    return app.config['cache'].get('data', {})

@app.route('/status')
def status():
    status_data = get_status_data()
    config = get_full_config()
    kiosk_config = get_kiosk_config()
    overrides = load_data(OVERRIDES_FILE, {})
    aliases = config.get('status_aliases', {})

    processed_data = {}
    for name, data in status_data.items():
        processed_data[name] = data.copy()
        if name in overrides and overrides[name].get('status'):
            processed_data[name]['state'] = overrides[name]['status']
            processed_data[name]['override'] = True
        
        original_state = processed_data[name].get('state')
        if original_state in aliases and aliases[original_state]:
            processed_data[name]['state'] = aliases[original_state]

    return jsonify({**processed_data, 'config': config, 'kiosk_config': kiosk_config})

@app.route('/admin')
@require_permission('view_dashboard')
def admin():
    printers = load_data(PRINTERS_FILE, [])
    overrides = load_data(OVERRIDES_FILE, {})
    users = load_data(USERS_FILE, {})
    roles = load_data(ROLES_FILE, {})
    config = get_full_config()
    kiosk_config = get_kiosk_config()
    
    # Always fetch fresh data for the admin page to discover all statuses
    live_statuses = fetch_all(printers)
    
    all_statuses = set(config.get('manual_statuses', []))
    for status_key in config.get('status_colors', {}).keys():
        all_statuses.add(status_key.replace('_', ' ').title())
    
    for printer_data in live_statuses.values():
        if printer_data.get('state'):
            all_statuses.add(printer_data['state'])

    log_content = ""
    if 'view_logs' in roles.get(session.get('role'), {}).get('permissions', []) or '*' in roles.get(session.get('role'), {}).get('permissions', []):
        try:
            with open(LOG_FILE, 'r') as f: log_content = f.read()
        except FileNotFoundError: log_content = "Log file not found."
    return render_template('admin.html', printers=printers, overrides=overrides, users=users, roles=roles, config=config, kiosk_config=kiosk_config, manual_statuses=config.get('manual_statuses', []), all_statuses=sorted(list(all_statuses)), available_permissions=AVAILABLE_PERMISSIONS, log_content=log_content)

@app.route('/admin/printers', methods=['POST'])
def manage_printers():
    action = request.form.get('action')
    printers = load_data(PRINTERS_FILE, [])
    user_permissions = load_data(ROLES_FILE, {}).get(session.get('role', ''), {}).get('permissions', [])
    
    def check_perm(perm):
        return perm in user_permissions or '*' in user_permissions

    if action == 'add_printer' and check_perm('add_printer'):
        new_printer = {k: request.form.get(k) for k in ['name', 'type', 'url', 'ip', 'api_key', 'access_code', 'serial', 'image_url', 'toolheads']}
        new_printer['show_filename'] = 'show_filename' in request.form
        
        if 'image_file' in request.files:
            file = request.files['image_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['PRINTER_UPLOAD_FOLDER'], filename))
                new_printer['local_image_filename'] = filename
                new_printer['image_url'] = ''

        if any(p['name'] == new_printer['name'] for p in printers):
            flash(f"A printer with the name '{new_printer['name']}' already exists.", 'danger')
        else:
            printers.append({k: v for k, v in new_printer.items() if v})
            save_data(printers, PRINTERS_FILE)
            flash(f"Printer '{new_printer['name']}' added.", 'success')
    elif action == 'delete_printer' and check_perm('delete_printer'):
        printer_name = request.form.get('name')
        printers = [p for p in printers if p.get('name') != printer_name]
        save_data(printers, PRINTERS_FILE)
        flash(f"Printer '{printer_name}' deleted.", 'success')
    else:
        flash('You do not have permission to perform this action.', 'danger')
    return redirect(url_for('admin'))

@app.route('/admin/edit_printer/<original_name>', methods=['GET', 'POST'])
@require_permission('edit_printer')
def edit_printer(original_name):
    printers = load_data(PRINTERS_FILE, [])
    printer_to_edit = next((p for p in printers if p['name'] == original_name), None)
    if not printer_to_edit:
        flash('Printer not found.', 'danger')
        return redirect(url_for('admin'))

    if request.method == 'POST':
        updated_data = printer_to_edit.copy()
        form_data = {k: request.form.get(k) for k in ['name', 'type', 'url', 'ip', 'api_key', 'access_code', 'serial', 'image_url', 'toolheads']}
        updated_data.update(form_data)
        updated_data['show_filename'] = 'show_filename' in request.form

        if 'image_file' in request.files:
            file = request.files['image_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['PRINTER_UPLOAD_FOLDER'], filename))
                updated_data['local_image_filename'] = filename
                updated_data['image_url'] = ''

        for i, p in enumerate(printers):
            if p['name'] == original_name:
                printers[i] = {k: v for k, v in updated_data.items() if v}
        
        save_data(printers, PRINTERS_FILE)
        flash(f"Printer '{updated_data['name']}' updated.", 'success')
        return redirect(url_for('admin'))

    return render_template('edit_printer.html', printer=printer_to_edit)

@app.route('/admin/overrides', methods=['POST'])
@require_permission('set_overrides')
def manage_overrides():
    overrides = load_data(OVERRIDES_FILE, {})
    printer_name = request.form.get('name')
    status_override = request.form.get('status_override')
    if status_override: overrides[printer_name] = {'status': status_override}
    elif printer_name in overrides: del overrides[printer_name]
    save_data(overrides, OVERRIDES_FILE)
    flash(f"Override for '{printer_name}' updated.", 'success')
    return redirect(url_for('admin'))

@app.route('/admin/users', methods=['POST'])
def manage_users():
    users = load_data(USERS_FILE, {})
    roles = load_data(ROLES_FILE, {})
    action = request.form.get('action')
    logged_in_user = session.get('username')
    logged_in_role_level = roles.get(session.get('role'), {}).get('level', 0)
    user_permissions = roles.get(session.get('role'), {}).get('permissions', [])
    
    def check_perm(perm):
        return perm in user_permissions or '*' in user_permissions

    if action == 'add_user' and check_perm('add_user'):
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if username and password and role and username not in users:
            if roles.get(role, {}).get('level', 999) >= logged_in_role_level:
                flash('You cannot create a user with a role equal to or higher than your own.', 'danger')
            else:
                users[username] = {'password': generate_password_hash(password), 'role': role}
                save_data(users, USERS_FILE)
                flash(f"User '{username}' added.", 'success')
        else:
            flash('Invalid input or user already exists.', 'danger')
    elif action == 'delete_user' and check_perm('delete_user'):
        username_to_delete = request.form.get('username')
        if username_to_delete in users and roles.get(users[username_to_delete]['role'], {}).get('level', 999) < logged_in_role_level:
            del users[username_to_delete]
            save_data(users, USERS_FILE)
            flash(f"User '{username_to_delete}' deleted.", 'success')
        else:
            flash('Cannot delete that user.', 'danger')
    elif action == 'change_password' and check_perm('change_user_password'):
        username_to_change = request.form.get('username')
        new_password = request.form.get('new_password')
        target_user_level = roles.get(users.get(username_to_change, {}).get('role'), {}).get('level', 999)
        if username_to_change in users and new_password and (target_user_level < logged_in_role_level or logged_in_user == username_to_change):
            users[username_to_change]['password'] = generate_password_hash(new_password)
            save_data(users, USERS_FILE)
            flash(f"Password for '{username_to_change}' has been changed.", 'success')
        else:
            flash('Action not permitted or user not found.', 'danger')
    elif action == 'change_role' and check_perm('change_user_role'):
        username_to_change = request.form.get('username')
        new_role = request.form.get('role')
        if username_to_change in users and new_role in roles and roles[new_role].get('level', 999) < logged_in_role_level:
            users[username_to_change]['role'] = new_role
            save_data(users, USERS_FILE)
            flash(f"Role for '{username_to_change}' updated.", 'success')
        else:
            flash('Cannot change role for this user.', 'danger')
    else:
        flash('You do not have permission to perform this action.', 'danger')
    return redirect(url_for('admin'))

@app.route('/admin/roles', methods=['POST'])
@require_permission('manage_roles')
def manage_roles():
    roles = load_data(ROLES_FILE, {})
    action = request.form.get('action')
    if action == 'add_role':
        role_name = request.form.get('role_name').lower().replace(' ', '_')
        permissions = request.form.getlist('permissions')
        if role_name and role_name not in roles:
            roles[role_name] = {'permissions': permissions, 'level': int(request.form.get('level', 1))}
            save_data(roles, ROLES_FILE)
            flash(f"Role '{role_name}' created.", 'success')
        else:
            flash('Invalid name or role already exists.', 'danger')
    elif action == 'delete_role':
        role_name = request.form.get('role_name')
        if role_name in roles and role_name not in ['system', 'super_user', 'admin', 'intern']:
            del roles[role_name]
            save_data(roles, ROLES_FILE)
            flash(f"Role '{role_name}' deleted.", 'success')
        else:
            flash('Cannot delete a core role.', 'danger')
    return redirect(url_for('admin'))

@app.route('/admin/edit_role/<role_name>', methods=['GET', 'POST'])
@require_permission('manage_roles')
def edit_role(role_name):
    roles = load_data(ROLES_FILE, {})
    role_to_edit = roles.get(role_name)
    if not role_to_edit or role_name == 'system':
        flash('Role not found or cannot be edited.', 'danger')
        return redirect(url_for('admin'))
    if request.method == 'POST':
        permissions = request.form.getlist('permissions')
        level = int(request.form.get('level', 1))
        roles[role_name]['permissions'] = permissions
        roles[role_name]['level'] = level
        save_data(roles, ROLES_FILE)
        flash(f"Role '{role_name}' updated.", 'success')
        return redirect(url_for('admin'))
    return render_template('edit_role.html', role_name=role_name, role_data=role_to_edit, available_permissions=AVAILABLE_PERMISSIONS)

@app.route('/admin/config', methods=['POST'])
@require_permission('manage_config')
def manage_config():
    config = get_full_config()
    action = request.form.get('action')

    if action == 'update_appearance':
        config['dashboard_title'] = request.form.get('dashboard_title', 'Printer Dashboard')
        config['card_size'] = request.form.get('card_size', 'medium')
        config['font_family'] = request.form.get('font_family', 'sans-serif')
        config['sort_by'] = request.form.get('sort_by', 'manual')
        config['printer_order'] = [name.strip() for name in request.form.get('printer_order', '').split(',') if name.strip()]
        config['status_order'] = [name.strip() for name in request.form.get('status_order', '').split(',') if name.strip()]
        config['progress_bar_color'] = request.form.get('progress_bar_color', '#007bff')
        config['progress_bar_text_color'] = request.form.get('progress_bar_text_color', '#ffffff')
        config['progress_bar_font_size_px'] = int(request.form.get('progress_bar_font_size_px', 12))
        config['progress_bar_height_px'] = int(request.form.get('progress_bar_height_px', 14))
        config['progress_bar_text_shadow'] = 'progress_bar_text_shadow' in request.form
        config['refresh_interval_sec'] = int(request.form.get('refresh_interval_sec', 30))
        config['font_size_printer_name_px'] = int(request.form.get('font_size_printer_name_px', 20))
        config['font_size_filename_px'] = int(request.form.get('font_size_filename_px', 14))
        config['font_size_status_px'] = int(request.form.get('font_size_status_px', 12))
        config['font_size_details_px'] = int(request.form.get('font_size_details_px', 14))
        save_data(config, CONFIG_FILE)
        flash('Dashboard appearance and layout updated.', 'success')
    elif action == 'update_kiosk':
        kiosk_config = get_kiosk_config()
        kiosk_config['kiosk_printers_per_page'] = int(request.form.get('kiosk_printers_per_page', 6))
        kiosk_config['kiosk_printer_page_time'] = int(request.form.get('kiosk_printer_page_time', 10))
        kiosk_config['kiosk_image_page_time'] = int(request.form.get('kiosk_image_page_time', 5))
        kiosk_config['kiosk_image_frequency'] = int(request.form.get('kiosk_image_frequency', 2))
        kiosk_config['kiosk_images_per_slot'] = int(request.form.get('kiosk_images_per_slot', 1))
        
        kiosk_config['kiosk_background_color'] = request.form.get('kiosk_background_color', '#000000')
        kiosk_config['kiosk_sort_by'] = request.form.get('kiosk_sort_by', 'manual')
        kiosk_config['kiosk_title'] = request.form.get('kiosk_title', '')

        if 'kiosk_header_image_file' in request.files:
            file = request.files['kiosk_header_image_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"header_{file.filename}")
                file.save(os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], filename))
                kiosk_config['kiosk_header_image'] = url_for('static', filename=f"kiosk_images/{filename}")

        save_data(kiosk_config, KIOSK_CONFIG_FILE)
        flash('Kiosk settings updated.', 'success')
    elif action == 'update_colors':
        config['status_colors'] = {key: value for key, value in request.form.items() if key != 'action'}
        save_data(config, CONFIG_FILE)
        flash('Status colors updated.', 'success')
    elif action == 'add_status':
        new_status = request.form.get('new_status_name')
        if new_status and new_status not in config.get('manual_statuses', []):
            config.setdefault('manual_statuses', []).append(new_status)
            config.setdefault('status_colors', {})[new_status.lower().replace(' ', '_')] = '#6c757d'
            save_data(config, CONFIG_FILE)
            flash(f"Status '{new_status}' added.", 'success')
        else:
            flash('Invalid name or status already exists.', 'danger')
    elif action == 'delete_status':
        status_to_delete = request.form.get('status_name')
        if status_to_delete in config.get('manual_statuses', []):
            config['manual_statuses'].remove(status_to_delete)
            config.get('status_colors', {}).pop(status_to_delete.lower().replace(' ', '_'), None)
            save_data(config, CONFIG_FILE)
            flash(f"Status '{status_to_delete}' deleted.", 'success')
        else:
            flash('Status not found.', 'danger')
    elif action == 'update_aliases':
        aliases = {}
        for key, value in request.form.items():
            if key.startswith('alias_') and value:
                original_status = key.replace('alias_', '')
                aliases[original_status] = value
        config['status_aliases'] = aliases
        save_data(config, CONFIG_FILE)
        flash('Status aliases updated.', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/kiosk_images', methods=['POST'])
@require_permission('manage_kiosk')
def manage_kiosk_images():
    kiosk_config = get_kiosk_config()
    
    # Handle updates and removals
    new_kiosk_images = []
    for i in range(len(kiosk_config['kiosk_images'])):
        if f'remove_{i}' in request.form:
            continue # Skip this image to remove it
        
        url = request.form.get(f'url_{i}')
        try:
            time = int(request.form.get(f'time_{i}', 5))
        except ValueError:
            time = 5
        
        new_kiosk_images.append({'url': url, 'time': time})
    kiosk_config['kiosk_images'] = new_kiosk_images

    # Handle new uploads
    if 'kiosk_image_files' in request.files:
        files = request.files.getlist('kiosk_image_files')
        default_time = kiosk_config.get('kiosk_image_page_time', 5)
        existing_urls = {img['url'] for img in kiosk_config.get('kiosk_images', [])}

        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], filename))
                image_url = url_for('static', filename=f"kiosk_images/{filename}")
                if image_url not in existing_urls:
                    kiosk_config['kiosk_images'].append({'url': image_url, 'time': default_time})

    save_data(kiosk_config, KIOSK_CONFIG_FILE)
    flash("Kiosk images updated.", 'success')
    return redirect(url_for('admin'))


@app.route('/dashboard')
def dashboard():
    config = get_full_config()
    dashboard_title = config.get('dashboard_title', 'Printer Dashboard')
    return render_template('dashboard.html', dashboard_title=dashboard_title)

@app.route('/kiosk')
def kiosk():
    return render_template('kiosk.html')

if __name__ == '__main__':
    if not os.path.exists(ROLES_FILE):
        print("First run: Creating default roles.")
        default_roles = {
            "system": {"permissions": ["*"], "level": 100}, 
            "super_user": {"permissions": ['view_dashboard', 'set_overrides', 'view_logs', 'add_printer', 'edit_printer', 'delete_printer', 'add_user', 'delete_user', 'change_user_password', 'change_user_role', 'manage_roles', 'manage_config', 'manage_kiosk', 'manage_kiosk_frequency'], "level": 90}, 
            "admin": {"permissions": ['view_dashboard', 'set_overrides', 'view_logs', 'add_printer', 'edit_printer', 'delete_printer', 'manage_kiosk'], "level": 50}, 
            "intern": {"permissions": ["view_dashboard", "set_overrides"], "level": 10}
        }
        save_data(default_roles, ROLES_FILE)
    if not os.path.exists(USERS_FILE):
        print("First run: Creating default 'system' and 'admin' users.")
        default_users = {'system': {'password': generate_password_hash('changeme'), 'role': 'system'}, 'admin': {'password': generate_password_hash('changeme'), 'role': 'admin'}}
        save_data(default_users, USERS_FILE)
    if not os.path.exists(CONFIG_FILE):
        print("First run: Creating default configuration.")
        get_full_config() # This will create and save the default config
    if not os.path.exists(KIOSK_CONFIG_FILE):
        print("First run: Creating default kiosk configuration.")
        get_kiosk_config() # This will create and save the default kiosk config
    
    app.run(host='0.0.0.0', port=HTTP_PORT, debug=True)
EOF
echo "    > aggregator_with_ui.py created."

# --- 5. Write the Login HTML template ---
echo "[*] Writing templates/login.html..."
cat > templates/login.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login</title>
    <style>
        body { display: flex; align-items: center; justify-content: center; min-height: 100vh; background-color: #f0f2f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; }
        .login-container { background: #fff; padding: 2.5rem; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 380px; text-align: center; }
        h1 { color: #333; margin-top: 0; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1.5rem; text-align: left; }
        label { font-weight: 600; margin-bottom: 0.5rem; display: block; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border-radius: 4px; border: 1px solid #ced4da; box-sizing: border-box; }
        button { cursor: pointer; background: #007bff; color: white; border: none; padding: 12px 20px; border-radius: 4px; font-size: 1rem; width: 100%; }
        button:hover { background: #0056b3; }
        .flash { padding: 1rem; margin-bottom: 1rem; border-radius: 4px; border: 1px solid transparent; }
        .flash-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
        .flash-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .flash-info { color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Admin Login</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash flash-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" required>
            </div>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
EOF
echo "    > templates/login.html created."

# --- 6. Write the Admin HTML template ---
echo "[*] Writing templates/admin.html..."
cat > templates/admin.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Panel</title>
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; background-color: #f8f9fa; color: #343a40; margin: 0; padding: 2rem; }
        .container { max-width: 1200px; margin: auto; background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #dee2e6; padding-bottom: 1rem; margin-bottom: 1rem;}
        h1, h2, h3 { color: #0056b3; margin-top: 0; }
        h2 { margin-top: 2rem; border-bottom: 1px solid #e9ecef; padding-bottom: 0.5rem; }
        h3 { color: #495057; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #dee2e6; vertical-align: middle; }
        th { background-color: #e9ecef; }
        .form-section { background: #f1f3f5; padding: 1.5rem; border-radius: 8px; margin-top: 1rem; }
        .form-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 1rem; }
        label { font-weight: bold; margin-bottom: 5px; display: block; }
        input, select, textarea { width: 100%; padding: 10px; border-radius: 4px; border: 1px solid #ced4da; box-sizing: border-box; }
        button { cursor: pointer; background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; font-size: 1rem; }
        button:hover { background: #0056b3; }
        button.delete { background: #dc3545; }
        button.delete:hover { background: #c82333; }
        a.button, button.edit { display: inline-block; background: #6c757d; color: white; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-size: 0.9rem; border: none; }
        a.button:hover, button.edit:hover { background: #5a6268; }
        .flash { padding: 1rem; margin-bottom: 1rem; border-radius: 4px; border: 1px solid transparent; }
        .flash-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .flash-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
        .nav-tabs { border-bottom: 1px solid #dee2e6; margin-bottom: 1rem; }
        .nav-tabs button { background: none; border: none; padding: 10px 15px; cursor: pointer; font-size: 1rem; color: #6c757d; }
        .nav-tabs button.active { border-bottom: 3px solid #007bff; font-weight: bold; color: #0056b3; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .permissions-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
        #log-viewer { width: 100%; height: 600px; border: 1px solid #dee2e6; border-radius: 4px; white-space: pre-wrap; background: #212529; color: #f8f9fa; padding: 1rem; box-sizing: border-box; }
        #sortable-printers li, #sortable-statuses li { padding: 10px; background-color: #e9ecef; margin-bottom: 5px; border-radius: 4px; cursor: grab; }
        #sortable-printers li:active, #sortable-statuses li:active { cursor: grabbing; }
        small { color: #6c757d; font-size: 0.85em; }
        .kiosk-image-item { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .kiosk-image-item input[type="text"] { flex-grow: 1; }
        .kiosk-image-item input[type="number"] { width: 80px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Admin Panel</h1>
            <div>Logged in as <strong>{{ session.username }}</strong> ({{ session.role }}) &nbsp; <a href="/logout" class="button">Logout</a></div>
        </div>
        <p>View public dashboard: <a href="/dashboard" target="_blank">/dashboard</a> | <a href="/kiosk" target="_blank">Kiosk View</a></p>

        {% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}
            {% for category, message in messages %}<div class="flash flash-{{ category }}">{{ message }}</div>{% endfor %}
        {% endif %}{% endwith %}

        <div class="nav-tabs">
            <button class="tab-button active" onclick="showTab('printers')">Printers</button>
            {% if 'add_user' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}<button class="tab-button" onclick="showTab('users')">User Management</button>{% endif %}
            {% if 'manage_roles' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}<button class="tab-button" onclick="showTab('roles')">Role Management</button>{% endif %}
            {% if 'manage_config' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}<button class="tab-button" onclick="showTab('config')">Configuration</button>{% endif %}
            {% if 'manage_kiosk' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}<button class="tab-button" onclick="showTab('kiosk')">Kiosk Settings</button>{% endif %}
            {% if 'view_logs' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}<button class="tab-button" onclick="showTab('logs')">Logs</button>{% endif %}
        </div>

        <div id="printers" class="tab-content active">
            <h2>Manage Printers</h2>
            <table>
                <thead><tr><th>Name</th><th>Type</th><th>Connection Info</th><th>Manual Override</th><th>Actions</th></tr></thead>
                <tbody>
                    {% for printer in printers %}
                    <tr>
                        <td>{{ printer.name }}</td><td>{{ printer.type }}</td>
                        <td>
                            {% if printer.type == 'prusa' %}{{ printer.ip }} / {{ printer.api_key[:4] }}...{% endif %}
                            {% if printer.type == 'klipper' %}{{ printer.url }}{% endif %}
                            {% if printer.type == 'bambulab' %}{{ printer.ip }} / {{ printer.serial[:6] }}...{% endif %}
                        </td>
                        <td>
                            <form action="{{ url_for('manage_overrides') }}" method="POST" style="display:inline-flex;">
                                <input type="hidden" name="name" value="{{ printer.name }}">
                                <select name="status_override">
                                    <option value="">-- Clear --</option>
                                    {% for status in manual_statuses %}<option value="{{ status }}" {% if overrides.get(printer.name, {}).get('status') == status %}selected{% endif %}>{{ status }}</option>{% endfor %}
                                </select><button type="submit">Set</button>
                            </form>
                        </td>
                        <td>
                            {% if 'edit_printer' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
                            <a href="{{ url_for('edit_printer', original_name=printer.name) }}" class="button edit">Edit</a>
                            {% endif %}
                            {% if 'delete_printer' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
                            <form action="{{ url_for('manage_printers') }}" method="POST" onsubmit="return confirm('Delete this printer?');" style="display:inline-flex;">
                                <input type="hidden" name="action" value="delete_printer"><input type="hidden" name="name" value="{{ printer.name }}"><button class="delete" type="submit">Delete</button>
                            </form>
                            {% endif %}
                        </td>
                    </tr>
                    {% else %}<tr><td colspan="5" style="text-align: center;">No printers configured.</td></tr>{% endfor %}
                </tbody>
            </table>
            
            {% if 'add_printer' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <div class="form-section">
                <h3>Add New Printer</h3>
                <form action="{{ url_for('manage_printers') }}" method="POST" id="add-printer-form" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="add_printer">
                    <div class="form-grid">
                        <div><label>Printer Name</label><input type="text" name="name" required></div>
                        <div><label>Type</label>
                            <select name="type" id="add-printer-type">
                                <option value="prusa">Prusa</option>
                                <option value="klipper">Klipper</option>
                                <option value="bambulab">Bambu Lab</option>
                            </select>
                        </div>
                    </div>
                    <div class="type-specific-fields" id="prusa-fields">
                        <div class="form-grid">
                            <div><label>IP Address (Local Network)</label><input type="text" name="ip"></div>
                            <div><label>API Key (From Printer Menu)</label><input type="text" name="api_key"></div>
                        </div>
                    </div>
                    <div class="type-specific-fields" id="klipper-fields">
                        <div class="form-grid">
                            <div><label>Moonraker/Klipper URL</label><input type="text" name="url" placeholder="http://klipper.local"></div>
                        </div>
                    </div>
                    <div class="type-specific-fields" id="bambulab-fields">
                        <div class="form-grid">
                            <div><label>IP Address</label><input type="text" name="ip"></div>
                            <div><label>Access Code</label><input type="text" name="access_code"></div>
                            <div><label>Serial Number</label><input type="text" name="serial"></div>
                        </div>
                    </div>
                    <div class="form-grid" style="margin-top: 1rem;">
                        <div><label>Number of Toolheads</label><input type="number" name="toolheads" min="1" value="1"></div>
                        <div><label>Image URL (Optional)</label><input type="text" name="image_url" placeholder="https://.../image.png"></div>
                        <div>
                            <label>Or Upload Image (Optional)</label>
                            <input type="file" name="image_file" accept="image/*">
                            <small>Overrides Image URL if provided.</small>
                        </div>
                        <div>
                            <label><input type="checkbox" name="show_filename" checked> Display File Name</label>
                        </div>
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Add Printer</button>
                </form>
            </div>
            {% endif %}
        </div>

        <div id="users" class="tab-content">
            {% if 'add_user' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <h2>User Management</h2>
            <table>
                <thead><tr><th>Username</th><th>Role</th><th>Actions</th></tr></thead>
                <tbody>
                    {% for username, data in users.items() %}
                    <tr><td>{{ username }}</td><td>{{ data.role }}</td>
                        <td>
                            {% if roles[data.role].level < roles[session.role].level %}
                            {% if 'change_user_role' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
                            <form action="{{ url_for('manage_users') }}" method="POST" style="display:inline-flex;">
                                <input type="hidden" name="action" value="change_role"><input type="hidden" name="username" value="{{ username }}">
                                <select name="role" onchange="this.form.submit()">
                                    {% for role_name, role_data in roles.items() %}{% if role_data.level < roles[session.role].level %}
                                    <option value="{{ role_name }}" {% if data.role == role_name %}selected{% endif %}>{{ role_name }}</option>
                                    {% endif %}{% endfor %}
                                </select>
                            </form>
                            {% endif %}
                            {% if 'delete_user' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
                            <form action="{{ url_for('manage_users') }}" method="POST" onsubmit="return confirm('Delete this user?');" style="display:inline-flex;">
                                <input type="hidden" name="action" value="delete_user"><input type="hidden" name="username" value="{{ username }}">
                                <button class="delete" type="submit">Delete</button>
                            </form>
                            {% endif %}
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            {% if 'add_user' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <div class="form-section">
                <h3>Add New User</h3>
                <form action="{{ url_for('manage_users') }}" method="POST"><input type="hidden" name="action" value="add_user">
                    <div class="form-grid">
                        <div><label>Username</label><input type="text" name="username" required></div>
                        <div><label>Password</label><input type="password" name="password" required></div>
                        <div><label>Role</label>
                            <select name="role">
                                {% for role_name, role_data in roles.items() %}{% if role_data.level < roles[session.role].level %}
                                <option value="{{ role_name }}">{{ role_name }}</option>
                                {% endif %}{% endfor %}
                            </select>
                        </div>
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Add User</button>
                </form>
            </div>
            {% endif %}
            {% if 'change_user_password' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <div class="form-section">
                <h3>Change User Password</h3>
                <form action="{{ url_for('manage_users') }}" method="POST"><input type="hidden" name="action" value="change_password">
                    <div class="form-grid">
                        <div><label>Username</label>
                            <select name="username">
                                {% for u, d in users.items() %}{% if roles[d.role].level < roles[session.role].level or u == session.username %}
                                <option value="{{ u }}">{{ u }}</option>
                                {% endif %}{% endfor %}
                            </select>
                        </div>
                        <div><label>New Password</label><input type="password" name="new_password" required></div>
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Change Password</button>
                </form>
            </div>
            {% endif %}
            {% endif %}
        </div>

        <div id="roles" class="tab-content">
            {% if 'manage_roles' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <h2>Role Management</h2>
            <table>
                <thead><tr><th>Role Name</th><th>Permissions</th><th>Actions</th></tr></thead>
                <tbody>
                    {% for role_name, role_data in roles.items() %}
                    <tr>
                        <td>{{ role_name }} (Level: {{role_data.level}})</td><td>{{ role_data.permissions|join(', ') }}</td>
                        <td>
                            {% if role_name != 'system' %}
                            <a href="{{ url_for('edit_role', role_name=role_name) }}" class="button edit">Edit</a>
                            {% if role_name not in ['super_user', 'admin', 'intern'] %}
                            <form action="{{ url_for('manage_roles') }}" method="POST" onsubmit="return confirm('Delete this role? This cannot be undone.');" style="display:inline-flex;">
                                <input type="hidden" name="action" value="delete_role"><input type="hidden" name="role_name" value="{{ role_name }}">
                                <button class="delete" type="submit">Delete</button>
                            </form>
                            {% endif %}
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <div class="form-section">
                <h3>Create New Role</h3>
                <form action="{{ url_for('manage_roles') }}" method="POST"><input type="hidden" name="action" value="add_role">
                    <div class="form-grid">
                        <div><label>Role Name</label><input type="text" name="role_name" required></div>
                        <div><label>Permission Level (1-89)</label><input type="number" name="level" min="1" max="89" value="10" required></div>
                    </div>
                    <h4>Permissions:</h4>
                    <div class="permissions-grid">
                        {% for perm in available_permissions %}
                        <div><input type="checkbox" name="permissions" value="{{ perm }}" id="perm_{{ perm }}"> <label for="perm_{{ perm }}">{{ perm }}</label></div>
                        {% endfor %}
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Create Role</button>
                </form>
            </div>
            {% endif %}
        </div>

        <div id="config" class="tab-content">
            {% if 'manage_config' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <h2>Application Configuration</h2>
            <div class="form-section">
                <h3>Dashboard Layout & Appearance</h3>
                <form action="{{ url_for('manage_config') }}" method="POST" id="layout-form">
                    <input type="hidden" name="action" value="update_appearance">
                    <input type="hidden" name="printer_order" id="printer_order_input">
                    <input type="hidden" name="status_order" id="status_order_input">
                    <div class="form-grid">
                        <div><label>Dashboard Title</label><input type="text" name="dashboard_title" value="{{ config.dashboard_title }}"></div>
                        <div><label>Sort Printers By</label>
                            <select name="sort_by">
                                <option value="manual" {% if config.sort_by == 'manual' %}selected{% endif %}>Manual</option>
                                <option value="status" {% if config.sort_by == 'status' %}selected{% endif %}>Status</option>
                            </select>
                        </div>
                        <div><label>Card Size</label>
                            <select name="card_size">
                                <option value="small" {% if config.card_size == 'small' %}selected{% endif %}>Small</option>
                                <option value="medium" {% if config.card_size == 'medium' %}selected{% endif %}>Medium</option>
                                <option value="large" {% if config.card_size == 'large' %}selected{% endif %}>Large</option>
                            </select>
                        </div>
                        <div><label>Font Family</label>
                            <select name="font_family">
                                <option value="sans-serif" {% if config.font_family == 'sans-serif' %}selected{% endif %}>Sans-Serif</option>
                                <option value="serif" {% if config.font_family == 'serif' %}selected{% endif %}>Serif</option>
                                <option value="monospace" {% if config.font_family == 'monospace' %}selected{% endif %}>Monospace</option>
                            </select>
                        </div>
                        <div><label>Refresh Interval (seconds)</label><input type="number" name="refresh_interval_sec" value="{{ config.refresh_interval_sec | default(30) }}" min="5"></div>
                    </div>
                    <div class="form-grid" style="grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); margin-top: 1.5rem;">
                        <div><label>Printer Name Font Size (px)</label><input type="number" name="font_size_printer_name_px" value="{{ config.font_size_printer_name_px | default(20) }}"></div>
                        <div><label>Filename Font Size (px)</label><input type="number" name="font_size_filename_px" value="{{ config.font_size_filename_px | default(14) }}"></div>
                        <div><label>Status Font Size (px)</label><input type="number" name="font_size_status_px" value="{{ config.font_size_status_px | default(12) }}"></div>
                        <div><label>Details Font Size (px)</label><input type="number" name="font_size_details_px" value="{{ config.font_size_details_px | default(14) }}"></div>
                    </div>
                    <div class="form-grid" style="margin-top: 1.5rem;">
                        <div>
                            <label>Manual Printer Order (Drag)</label>
                            <ul id="sortable-printers">
                                {% for printer_name in config.printer_order %}
                                    <li data-name="{{ printer_name }}">{{ printer_name }}</li>
                                {% endfor %}
                                {% for printer in printers %}{% if printer.name not in config.printer_order %}
                                    <li data-name="{{ printer.name }}">{{ printer.name }}</li>
                                {% endif %}{% endfor %}
                            </ul>
                        </div>
                        <div>
                            <label>Status Sort Order (Drag)</label>
                            <ul id="sortable-statuses">
                                {% set aliased_keys = config.status_aliases.keys() %}
                                {% for status_name in config.status_order %}
                                    {% if status_name not in aliased_keys %}
                                    <li data-name="{{ status_name }}">{{ status_name }}</li>
                                    {% endif %}
                                {% endfor %}
                                {% for status_name in all_statuses %}
                                    {% if status_name not in config.status_order and status_name not in aliased_keys %}
                                    <li data-name="{{ status_name }}">{{ status_name }}</li>
                                    {% endif %}
                                {% endfor %}
                            </ul>
                        </div>
                    </div>
                    <div class="form-grid" style="margin-top: 1.5rem;">
                        <div><label>Progress Bar Color</label><input type="color" name="progress_bar_color" value="{{ config.progress_bar_color }}"></div>
                        <div><label>Progress Bar Text Color</label><input type="color" name="progress_bar_text_color" value="{{ config.progress_bar_text_color }}"></div>
                        <div><label>Progress Bar Font Size (px)</label><input type="number" name="progress_bar_font_size_px" value="{{ config.progress_bar_font_size_px }}" min="6"></div>
                        <div><label>Progress Bar Height (px)</label><input type="number" name="progress_bar_height_px" value="{{ config.progress_bar_height_px }}" min="4"></div>
                        <div><label>Progress Bar Text Outline</label>
                            <input type="checkbox" name="progress_bar_text_shadow" value="true" {% if config.progress_bar_text_shadow %}checked{% endif %}>
                        </div>
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Save Layout & Appearance</button>
                </form>
            </div>
            <div class="form-section">
                <h3>Manage Manual Statuses</h3>
                <table>
                    <thead><tr><th>Status Name</th><th>Action</th></tr></thead>
                    <tbody>
                        {% for status in manual_statuses %}
                        <tr><td>{{ status }}</td>
                            <td>
                                <form action="{{ url_for('manage_config') }}" method="POST" onsubmit="return confirm('Delete this status?');" style="display:inline-flex;">
                                    <input type="hidden" name="action" value="delete_status"><input type="hidden" name="status_name" value="{{ status }}">
                                    <button class="delete" type="submit">Delete</button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <form action="{{ url_for('manage_config') }}" method="POST" style="margin-top: 1rem;">
                    <input type="hidden" name="action" value="add_status">
                    <div class="form-grid">
                        <div><label>New Status Name</label><input type="text" name="new_status_name" required></div>
                        <div style="align-self: end;"><button type="submit">Add Status</button></div>
                    </div>
                </form>
            </div>
            <div class="form-section">
                <h3>Manage Status Colors <small>(Appearance may vary by browser)</small></h3>
                <form action="{{ url_for('manage_config') }}" method="POST">
                    <input type="hidden" name="action" value="update_colors">
                    <div class="form-grid">
                        {% for status_name in all_statuses %}
                        {% set status_key = status_name.lower().replace(' ', '_') %}
                        <div>
                            <label for="color_{{ status_key }}">{{ status_name }}</label>
                            <input type="color" id="color_{{ status_key }}" name="{{ status_key }}" value="{{ config.status_colors.get(status_key, '#6c757d') }}">
                        </div>
                        {% endfor %}
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Save Colors</button>
                </form>
            </div>
            <div class="form-section">
                <h3>Status Aliasing</h3>
                <form action="{{ url_for('manage_config') }}" method="POST">
                    <input type="hidden" name="action" value="update_aliases">
                    <table>
                        <thead><tr><th>Original Status</th><th>Display As</th></tr></thead>
                        <tbody>
                            {% for status_name in all_statuses %}
                            <tr>
                                <td>{{ status_name }}</td>
                                <td>
                                    <select name="alias_{{ status_name }}">
                                        <option value="">-- No Alias --</option>
                                        {% for target_status in all_statuses %}
                                            {% if status_name != target_status %}
                                            <option value="{{ target_status }}" {% if config.get('status_aliases', {}).get(status_name) == target_status %}selected{% endif %}>{{ target_status }}</option>
                                            {% endif %}
                                        {% endfor %}
                                    </select>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    <button type="submit" style="margin-top: 1rem;">Save Aliases</button>
                </form>
            </div>
            {% endif %}
        </div>

        <div id="kiosk" class="tab-content">
            {% if 'manage_kiosk' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
            <h2>Kiosk Mode Settings</h2>
            <div class="form-section">
                <form action="{{ url_for('manage_config') }}" method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="update_kiosk">
                    <div class="form-grid">
                        <div><label>Printers per Page</label><input type="number" name="kiosk_printers_per_page" value="{{ kiosk_config.kiosk_printers_per_page }}" min="1"></div>
                        <div><label>Printer Page Time (sec)</label><input type="number" name="kiosk_printer_page_time" value="{{ kiosk_config.kiosk_printer_page_time }}" min="1"></div>
                        <div><label>Default Image Page Time (sec)</label><input type="number" name="kiosk_image_page_time" value="{{ kiosk_config.kiosk_image_page_time }}" min="1"></div>
                        {% if 'manage_kiosk_frequency' in roles[session.role]['permissions'] or 'manage_kiosk' in roles[session.role]['permissions'] or '*' in roles[session.role]['permissions'] %}
                        <div><label>Image Frequency (after # printer pages)</label><input type="number" name="kiosk_image_frequency" value="{{ kiosk_config.kiosk_image_frequency }}" min="1"></div>
                        {% endif %}
                        <div><label>Images Per Slot</label><input type="number" name="kiosk_images_per_slot" value="{{ kiosk_config.kiosk_images_per_slot }}" min="1"></div>
                        <div>
                            <label>Sort Kiosk By</label>
                            <select name="kiosk_sort_by">
                                <option value="manual" {% if kiosk_config.kiosk_sort_by == 'manual' %}selected{% endif %}>Manual</option>
                                <option value="status" {% if kiosk_config.kiosk_sort_by == 'status' %}selected{% endif %}>Status</option>
                            </select>
                        </div>
                        <div><label>Kiosk Background Color</label><input type="color" name="kiosk_background_color" value="{{ kiosk_config.kiosk_background_color }}"></div>
                    </div>
                    <div style="margin-top: 1.5rem;">
                        <label>Kiosk Title</label>
                        <input type="text" name="kiosk_title" value="{{ kiosk_config.kiosk_title }}">
                    </div>
                    <div style="margin-top: 1rem;">
                        <label>Kiosk Header Image</label>
                        <input type="file" name="kiosk_header_image_file" accept="image/*">
                        <small>Current: {{ kiosk_config.kiosk_header_image or 'None' }}</small>
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Save Kiosk Settings</button>
                </form>
            </div>
            <div class="form-section">
                <h3>Manage Kiosk Images</h3>
                <form action="{{ url_for('manage_kiosk_images') }}" method="POST" enctype="multipart/form-data">
                    <div id="kiosk-image-list">
                        {% for image in kiosk_config.kiosk_images %}
                        <div class="kiosk-image-item">
                            <input type="hidden" name="url_{{ loop.index0 }}" value="{{ image.url }}">
                            <input type="text" value="{{ image.url.split('/')[-1] }}" readonly>
                            <input type="number" name="time_{{ loop.index0 }}" value="{{ image.time }}" min="1">
                            <label>sec</label>
                            <button type="submit" name="remove_{{ loop.index0 }}" class="delete">Remove</button>
                        </div>
                        {% endfor %}
                    </div>
                    <div style="margin-top: 1rem;">
                        <label>Upload New Images</label>
                        <input type="file" name="kiosk_image_files" accept="image/*" multiple>
                        <small>You can select multiple images. They will be added to the slideshow with the default time.</small>
                    </div>
                    <button type="submit" style="margin-top: 1rem;">Save Changes & Upload</button>
                </form>
            </div>
            {% endif %}
        </div>
        
        <div id="logs" class="tab-content">
            <h2>Activity Log</h2>
            <pre id="log-viewer">{{ log_content }}</pre>
        </div>
    </div>
    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-button').forEach(button => button.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');
            event.currentTarget.classList.add('active');
        }

        const sortablePrinters = document.getElementById('sortable-printers');
        if (sortablePrinters) {
            new Sortable(sortablePrinters, { animation: 150 });
        }
        
        const sortableStatuses = document.getElementById('sortable-statuses');
        if (sortableStatuses) {
            new Sortable(sortableStatuses, { animation: 150 });
        }
        
        const layoutForm = document.getElementById('layout-form');
        if(layoutForm) {
            layoutForm.addEventListener('submit', function() {
                if(sortablePrinters) {
                    const printerOrder = Array.from(sortablePrinters.children).map(item => item.dataset.name);
                    document.getElementById('printer_order_input').value = printerOrder.join(',');
                }
                if(sortableStatuses) {
                    const statusOrder = Array.from(sortableStatuses.children).map(item => item.dataset.name);
                    document.getElementById('status_order_input').value = statusOrder.join(',');
                }
            });
        }

        function handleAddFormDisplay() {
            const type = document.getElementById('add-printer-type').value;
            document.querySelectorAll('.type-specific-fields').forEach(div => {
                div.style.display = 'none';
                div.querySelectorAll('input').forEach(input => input.disabled = true);
            });
            const fieldsToShow = document.getElementById(type + '-fields');
            if (fieldsToShow) {
                fieldsToShow.style.display = 'block';
                fieldsToShow.querySelectorAll('input').forEach(input => input.disabled = false);
            }
        }
        document.getElementById('add-printer-type').addEventListener('change', handleAddFormDisplay);
        document.addEventListener('DOMContentLoaded', handleAddFormDisplay);
    </script>
</body>
</html>
EOF
echo "    > templates/admin.html created."

# --- 7. Write the Edit Printer & Edit Role HTML templates ---
echo "[*] Writing templates/edit_printer.html..."
cat > templates/edit_printer.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Edit Printer</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; background-color: #f8f9fa; color: #343a40; margin: 0; padding: 2rem; }
        .container { max-width: 800px; margin: auto; background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #0056b3; margin-top: 0; }
        .form-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 1.5rem; }
        label { font-weight: bold; margin-bottom: 5px; display: block; }
        input, select { width: 100%; padding: 10px; border-radius: 4px; border: 1px solid #ced4da; box-sizing: border-box; }
        button { cursor: pointer; background: #28a745; color: white; border: none; padding: 12px 24px; border-radius: 4px; font-size: 1rem; }
        button:hover { background: #218838; }
        a.button { display: inline-block; background: #6c757d; color: white; padding: 12px 24px; border-radius: 4px; text-decoration: none; margin-left: 10px; }
        a.button:hover { background: #5a6268; }
        small { color: #6c757d; font-size: 0.85em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Edit Printer: {{ printer.name }}</h1>
        <form method="POST" enctype="multipart/form-data">
            <div class="form-grid">
                <div><label>Printer Name</label><input type="text" name="name" value="{{ printer.name }}" required></div>
                <div><label>Type</label>
                    <select name="type" id="edit-printer-type">
                        <option value="prusa" {% if printer.type == 'prusa' %}selected{% endif %}>Prusa</option>
                        <option value="klipper" {% if printer.type == 'klipper' %}selected{% endif %}>Klipper</option>
                        <option value="bambulab" {% if printer.type == 'bambulab' %}selected{% endif %}>Bambu Lab</option>
                    </select>
                </div>
            </div>
            <div class="type-specific-fields" id="prusa-fields-edit">
                <div class="form-grid">
                    <div><label>IP Address (Local Network)</label><input type="text" name="ip" value="{{ printer.ip or '' }}"></div>
                    <div><label>API Key (From Printer Menu)</label><input type="text" name="api_key" value="{{ printer.api_key or '' }}"></div>
                </div>
            </div>
            <div class="type-specific-fields" id="klipper-fields-edit">
                <div class="form-grid">
                    <div><label>Moonraker/Klipper URL</label><input type="text" name="url" value="{{ printer.url or '' }}"></div>
                </div>
            </div>
            <div class="type-specific-fields" id="bambulab-fields-edit">
                <div class="form-grid">
                    <div><label>IP Address</label><input type="text" name="ip" value="{{ printer.ip or '' }}"></div>
                    <div><label>Access Code</label><input type="text" name="access_code" value="{{ printer.access_code or '' }}"></div>
                    <div><label>Serial Number</label><input type="text" name="serial" value="{{ printer.serial or '' }}"></div>
                </div>
            </div>
            <div class="form-grid" style="margin-top: 1rem;">
                <div><label>Number of Toolheads</label><input type="number" name="toolheads" min="1" value="{{ printer.toolheads | default(1, true) }}"></div>
                <div><label>Image URL (Optional)</label><input type="text" name="image_url" value="{{ printer.image_url or '' }}" placeholder="https://.../image.png"></div>
                <div>
                    <label>Or Upload New Image (Optional)</label>
                    <input type="file" name="image_file" accept="image/*">
                    <small>Current file: <strong>{{ printer.get('local_image_filename', 'None') }}</strong>. Overrides URL.</small>
                </div>
                <div>
                    <label><input type="checkbox" name="show_filename" {% if printer.show_filename != False %}checked{% endif %}> Display File Name</label>
                </div>
            </div>
            <div style="margin-top: 2rem;">
                <button type="submit">Save Changes</button>
                <a href="{{ url_for('admin') }}" class="button">Cancel</a>
            </div>
        </form>
    </div>
    <script>
        function handleEditFormDisplay() {
            const type = document.getElementById('edit-printer-type').value;
            document.querySelectorAll('.type-specific-fields').forEach(div => {
                div.style.display = 'none';
                div.querySelectorAll('input').forEach(input => input.disabled = true);
            });
            const fieldsToShow = document.getElementById(type + '-fields-edit');
            if (fieldsToShow) {
                fieldsToShow.style.display = 'block';
                fieldsToShow.querySelectorAll('input').forEach(input => input.disabled = false);
            }
        }
        document.getElementById('edit-printer-type').addEventListener('change', handleEditFormDisplay);
        handleEditFormDisplay(); // Initial call
    </script>
</body>
</html>
EOF
echo "    > templates/edit_printer.html created."

echo "[*] Writing templates/edit_role.html..."
cat > templates/edit_role.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Edit Role</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; background-color: #f8f9fa; color: #343a40; margin: 0; padding: 2rem; }
        .container { max-width: 800px; margin: auto; background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { color: #0056b3; margin-top: 0; }
        .form-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; margin-top: 1.5rem; }
        label { font-weight: bold; margin-bottom: 5px; display: block; }
        input, select { width: 100%; padding: 10px; border-radius: 4px; border: 1px solid #ced4da; box-sizing: border-box; }
        button { cursor: pointer; background: #28a745; color: white; border: none; padding: 12px 24px; border-radius: 4px; font-size: 1rem; }
        button:hover { background: #218838; }
        a.button { display: inline-block; background: #6c757d; color: white; padding: 12px 24px; border-radius: 4px; text-decoration: none; margin-left: 10px; }
        a.button:hover { background: #5a6268; }
        .permissions-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Edit Role: {{ role_name }}</h1>
        <form method="POST">
            <div class="form-grid">
                <div><label>Permission Level (1-89)</label><input type="number" name="level" min="1" max="89" value="{{ role_data.level }}" required></div>
            </div>
            <h4>Permissions:</h4>
            <div class="permissions-grid">
                {% for perm in available_permissions %}
                <div>
                    <input type="checkbox" name="permissions" value="{{ perm }}" id="perm_{{ perm }}" {% if perm in role_data.permissions %}checked{% endif %}>
                    <label for="perm_{{ perm }}">{{ perm }}</label>
                </div>
                {% endfor %}
            </div>
            <div style="margin-top: 2rem;">
                <button type="submit">Save Changes</button>
                <a href="{{ url_for('admin') }}" class="button">Cancel</a>
            </div>
        </form>
    </div>
</body>
</html>
EOF
echo "    > templates/edit_role.html created."

# --- 8. Write the Dashboard HTML template ---
echo "[*] Writing templates/dashboard.html..."
cat > templates/dashboard.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ dashboard_title }}</title>
    <style>
        body { background: #f0f2f5; color: #333; padding: 1rem; margin: 0; }
        h1 { text-align: center; color: #444; }
        #dash { display: grid; gap: 1.5rem; max-width: 1600px; margin: auto; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); display: flex; flex-direction: column; transition: transform 0.2s; overflow: hidden; }
        .card:hover { transform: translateY(-5px); }
        .card-img { width: 100%; height: 180px; object-fit: contain; background-color: #e9ecef; }
        .card-content { padding: 1rem 1.5rem; text-align: center; flex-grow: 1; display: flex; flex-direction: column; }
        .card h4 { margin: 0 0 0.5rem 0; font-size: 1.25em; color: #0056b3; }
        .filename { font-size: 0.8em; color: #6c757d; margin-bottom: 0.5rem; word-break: break-all; }
        .status { display: inline-block; padding: .3rem .8rem; margin: .5rem 0; border-radius: 99px; color: #fff; font-size: .8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .override .status { border: 2px dashed #ffc107; box-shadow: 0 0 0 2px #6c757d; }
        .progress-bar { background: #e9ecef; border-radius: 99px; overflow: hidden; position: relative; }
        .progress-bar .progress-fill { height: 100%; transition: width 0.5s ease-in-out; }
        .progress-text { position: absolute; width: 100%; text-align: center; font-weight: bold; }
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; text-align: left; margin-top: 1rem; }
        .stats-grid span { font-size: 0.9em; }
        .temps { display: flex; justify-content: space-around; font-size: 0.9em; margin-top: 1rem; border-top: 1px solid #e9ecef; padding-top: 1rem; flex-wrap: wrap; gap: 8px; }
        .error-message { font-size: 0.8em; color: #dc3545; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <h1>{{ dashboard_title }}</h1>
    <div id="dash"><p>Loading printer statuses...</p></div>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        let refreshTimeout;

        function applyStyles(config) {
            const root = document.documentElement;
            const cardSize = config.card_size || 'medium';
            const fontFamily = config.font_family || 'sans-serif';

            let gridCols = 'minmax(300px, 1fr)';
            if (cardSize === 'small') gridCols = 'minmax(250px, 1fr)';
            if (cardSize === 'large') gridCols = 'minmax(400px, 1fr)';
            document.getElementById('dash').style.gridTemplateColumns = `repeat(auto-fill, ${gridCols})`;
            
            document.body.style.fontFamily = fontFamily;
        }

        function formatTime(s){if(s===null||s<=0)return'—';const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h>0?`${h}h ${m}m`:`${m}m`;}
        
        function render(data){
            const t=$('#dash');
            const config=data.config||{status_colors:{}};
            applyStyles(config);
            const printerData = { ...data };
            delete printerData.config;
            delete printerData.kiosk_config;

            let printerArray = Object.entries(printerData);

            if (config.sort_by === 'status') {
                const statusOrder = config.status_order || [];
                const statusMap = new Map(statusOrder.map((status, index) => [status, index]));
                printerArray.sort(([, a], [, b]) => {
                    const aIndex = statusMap.get(a.state) ?? 999;
                    const bIndex = statusMap.get(b.state) ?? 999;
                    return aIndex - bIndex;
                });
            } else if (config.sort_by === 'manual' || !config.sort_by) {
                const printerOrder = config.printer_order || [];
                const printerMap = new Map(printerOrder.map((name, index) => [name, index]));
                printerArray.sort(([aName], [bName]) => {
                    const aIndex = printerMap.get(aName) ?? 999;
                    const bIndex = printerMap.get(bName) ?? 999;
                    return aIndex - bIndex;
                });
            }

            t.empty();
            if(printerArray.length===0){t.html('<p>No printers found. Please add one in the /admin panel.</p>');return}
            
            printerArray.forEach(([e,n])=>{
                let a=n.state||'unknown';
                let error_msg = n.error || null;
                if (a === 'Config Error') {
                    a = 'Offline'; // Show a generic status to public
                }

                const o=a.toLowerCase().replace(/\s+/g,'-'),s=n.progress!=null?n.progress:0,i=n.time_remaining!=null?formatTime(n.time_remaining):'—',l=n.time_elapsed!=null?formatTime(n.time_elapsed):'—',r=n.override?'card override':'card';let m='—';if(n.nozzle_temp!==null){if(Array.isArray(n.nozzle_temp)){m=n.nozzle_temp.map((t,e)=>`T${e}:${t}°C`).join(' ')}else{m=n.nozzle_temp+'°C'}}const p=n.image_src||`https://via.placeholder.com/400x200/dee2e6/6c757d?text=${e}`;const u=config.status_colors[o]||'#6c757d';let timeHtml='';if(a==='Printing'){let pb_fs=(config.progress_bar_font_size_px||12)+'px';let pb_h=(config.progress_bar_height_px||14)+'px';let pb_shadow=config.progress_bar_text_shadow?'1px 1px 1px rgba(0,0,0,0.5), -1px -1px 0 rgba(0,0,0,0.5), 1px -1px 0 rgba(0,0,0,0.5), -1px 1px 0 rgba(0,0,0,0.5)':'none';timeHtml=`<div class="progress-bar" style="height:${pb_h};margin: 0.75rem 0;"><div class="progress-text" style="color:${config.progress_bar_text_color};font-size:${pb_fs};line-height:${pb_h};text-shadow:${pb_shadow};">${s}%</div><div class="progress-fill" style="width:${s}%;background-color:${config.progress_bar_color};"></div></div><div class="stats-grid" style="font-size:${config.font_size_details_px}px;"><span><strong>Elapsed:</strong> ${l}</span><span><strong>Remaining:</strong> ${i}</span></div>`}let tempsHtml='';const hideTempsFor=['Offline','Under Maintenance','Unsupported','Error','Config Error'];if(!hideTempsFor.includes(n.state)){tempsHtml=`<div class="temps" style="font-size:${config.font_size_details_px}px;"><span><img src="https://api.iconify.design/mdi/heat-bed.svg?color=%23888888" alt="Bed"> ${n.bed_temp!=null?n.bed_temp+'°C':'—'}</span><span><img src="https://api.iconify.design/mdi/nozzle.svg?color=%23888888" alt="Nozzle"> ${m}</span></div>`} let errorHtml = n.state === 'Config Error' ? `<div class="error-message">Error: ${error_msg}</div>` : ''; const c=`<div class="${r}"><img src="${p}" class="card-img" alt="${e}" onerror="this.onerror=null;this.src='https://via.placeholder.com/400x200/dee2e6/6c757d?text=Image+Error';"><div class="card-content"><h4 style="font-size:${config.font_size_printer_name_px}px;">${e}</h4><span class="status" style="background-color:${u}; font-size:${config.font_size_status_px}px;">${a}</span>${errorHtml}${timeHtml}${tempsHtml}</div></div>`;t.append(c)
            });
        }
        
        function fetchAndRender() {
            $.getJSON('/status')
                .done(data => {
                    const refreshInterval = (data.config.refresh_interval_sec || 30) * 1000;
                    render(data);
                    clearTimeout(refreshTimeout);
                    refreshTimeout = setTimeout(fetchAndRender, refreshInterval);
                })
                .fail(() => {
                    clearTimeout(refreshTimeout);
                    refreshTimeout = setTimeout(fetchAndRender, 30000); // Retry after 30s on failure
                });
        }

        $(document).ready(function(){
            fetchAndRender(); // Initial call
        });
    </script>
</body>
</html>
EOF
echo "    > templates/dashboard.html created."

# --- 9. Write the Kiosk HTML template ---
echo "[*] Writing templates/kiosk.html..."
cat > templates/kiosk.html << 'EOF'
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Kiosk View</title>
    <style>
        body, html { margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; cursor: none; }
        .kiosk-header { position: fixed; top: 0; left: 0; width: 100%; padding: 10px 20px; box-sizing: border-box; display: flex; align-items: center; justify-content: center; z-index: 10; color: white; }
        .kiosk-header img { max-height: 50px; margin-right: 20px; }
        .kiosk-header h1 { margin: 0; font-size: 2.5em; text-shadow: 2px 2px 4px rgba(0,0,0,0.7); }
        #kiosk-container { width: 100%; height: 100%; position: relative; }
        .slide { width: 100%; height: 100%; position: absolute; top: 0; left: 0; opacity: 0; transition: opacity 1s ease-in-out; }
        .slide.active { opacity: 1; z-index: 1; }
        .image-slide { background-size: contain; background-position: center; background-repeat: no-repeat; }
        .printer-slide { display: grid; padding: 2rem; box-sizing: border-box; gap: 1.5rem; align-content: center; padding-top: 80px; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); display: flex; flex-direction: column; overflow: hidden; }
        .card-img { width: 100%; height: 180px; object-fit: contain; background-color: #e9ecef; }
        .card-content { padding: 1rem 1.5rem; text-align: center; flex-grow: 1; display: flex; flex-direction: column; }
        .card h4 { margin: 0 0 0.5rem 0; font-size: 1.25em; color: #0056b3; }
        .filename { font-size: 0.8em; color: #6c757d; margin-bottom: 0.5rem; word-break: break-all; }
        .status { display: inline-block; padding: .3rem .8rem; margin: .5rem 0; border-radius: 99px; color: #fff; font-size: .8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .progress-bar { background: #e9ecef; border-radius: 99px; overflow: hidden; position: relative; }
        .progress-bar .progress-fill { height: 100%; }
        .progress-text { position: absolute; width: 100%; text-align: center; font-weight: bold; }
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; text-align: left; margin-top: 1rem; }
        .stats-grid span { font-size: 0.9em; }
        .temps { display: flex; justify-content: space-around; font-size: 0.9em; margin-top: 1rem; border-top: 1px solid #e9ecef; padding-top: 1rem; flex-wrap: wrap; gap: 8px; }
        .error-message { font-size: 0.8em; color: #dc3545; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <div class="kiosk-header"></div>
    <div id="kiosk-container"><h1 style="text-align:center; padding-top: 2rem;">Loading Kiosk...</h1></div>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        const kioskContainer = document.getElementById('kiosk-container');
        const kioskHeader = document.querySelector('.kiosk-header');
        let slides = [];
        let currentSlideIndex = 0;
        let slideTimeout;
        let imageIndex = 0;
        let globalConfig = {};
        let globalKioskConfig = {};

        function formatTime(s) {
            if (s === null || s <= 0) return '—';
            const h = Math.floor(s / 3600),
                m = Math.floor((s % 3600) / 60);
            return h > 0 ? `${h}h ${m}m` : `${m}m`;
        }

        function createPrinterCardHtml(printerName, printerData) {
            const config = globalConfig;
            let state = printerData.state || 'unknown';
            const originalState = printerData.state; 
            if (state === 'Config Error') {
                state = 'Offline';
            }

            const stateKey = state.toLowerCase().replace(/\s+/g, '-');
            const progress = printerData.progress != null ? printerData.progress : 0;
            const timeRemaining = formatTime(printerData.time_remaining);
            const timeElapsed = formatTime(printerData.time_elapsed);
            
            let nozzleTempStr = '—';
            if (printerData.nozzle_temp !== null) {
                if (Array.isArray(printerData.nozzle_temp)) {
                    nozzleTempStr = printerData.nozzle_temp.map((t, i) => `T${i}:${t}°C`).join(' ');
                } else {
                    nozzleTempStr = printerData.nozzle_temp + '°C';
                }
            }

            const imgSrc = printerData.image_src || `https://via.placeholder.com/400x200/dee2e6/6c757d?text=${printerName}`;
            const statusColor = config.status_colors[stateKey] || '#6c757d';
            const showFile = printerData.show_filename !== false;
            const filenameHtml = showFile && printerData.filename ? `<div class="filename" style="font-size:${config.font_size_filename_px}px;">${printerData.filename}</div>` : '';

            let timeHtml = '';
            if (state === 'Printing') {
                const pb_fs = (config.progress_bar_font_size_px || 12) + 'px';
                const pb_h = (config.progress_bar_height_px || 14) + 'px';
                const pb_shadow = config.progress_bar_text_shadow ? '1px 1px 1px rgba(0,0,0,0.5), -1px -1px 0 rgba(0,0,0,0.5), 1px -1px 0 rgba(0,0,0,0.5), -1px 1px 0 rgba(0,0,0,0.5)' : 'none';
                timeHtml = `
                    <div class="progress-bar" style="height:${pb_h}; margin: 0.75rem 0;">
                        <div class="progress-text" style="color:${config.progress_bar_text_color};font-size:${pb_fs};line-height:${pb_h};text-shadow:${pb_shadow};">${progress}%</div>
                        <div class="progress-fill" style="width:${progress}%;background-color:${config.progress_bar_color};"></div>
                    </div>
                    <div class="stats-grid" style="display: grid; font-size:${config.font_size_details_px}px;">
                        <span><strong>Elapsed:</strong> ${timeElapsed}</span>
                        <span><strong>Remaining:</strong> ${timeRemaining}</span>
                    </div>`;
            } else {
                timeHtml = `<div class="progress-bar" style="display: none;"></div><div class="stats-grid" style="display: none;"></div>`;
            }

            let tempsHtml = '';
            const hideTempsFor = ['Offline', 'Under Maintenance', 'Unsupported', 'Error', 'Config Error'];
            if (!hideTempsFor.includes(originalState)) {
                tempsHtml = `
                    <div class="temps" style="display: flex; font-size:${config.font_size_details_px}px;">
                        <span><img src="https://api.iconify.design/mdi/heat-bed.svg?color=%23888888" alt="Bed"> ${printerData.bed_temp != null ? printerData.bed_temp + '°C' : '—'}</span>
                        <span><img src="https://api.iconify.design/mdi/nozzle.svg?color=%23888888" alt="Nozzle"> ${nozzleTempStr}</span>
                    </div>`;
            } else {
                 tempsHtml = `<div class="temps" style="display: none;"></div>`;
            }
            
            let errorHtml = originalState === 'Config Error' ? `<div class="error-message">Error: ${printerData.error}</div>` : '';

            return `
                <div class="card" data-printer-name="${printerName}">
                    <img src="${imgSrc}" class="card-img" alt="${printerName}" onerror="this.onerror=null;this.src='https://via.placeholder.com/400x200/dee2e6/6c757d?text=Image+Error';">
                    <div class="card-content">
                        <h4 style="font-size:${config.font_size_printer_name_px}px;">${printerName}</h4>
                        ${filenameHtml}
                        <span class="status" style="background-color:${statusColor}; font-size:${config.font_size_status_px}px;">${state}</span>
                        ${errorHtml}
                        ${timeHtml}
                        ${tempsHtml}
                    </div>
                </div>`;
        }

        function buildAndRenderSlides(data) {
            globalConfig = data.config || {};
            globalKioskConfig = data.kiosk_config || {};
            document.body.style.backgroundColor = globalKioskConfig.kiosk_background_color || '#000';
            
            kioskHeader.innerHTML = '';
            if (globalKioskConfig.kiosk_header_image) {
                kioskHeader.innerHTML += `<img src="${globalKioskConfig.kiosk_header_image}" alt="Header Image">`;
            }
            if (globalKioskConfig.kiosk_title) {
                kioskHeader.innerHTML += `<h1>${globalKioskConfig.kiosk_title}</h1>`;
            }

            const printerData = { ...data };
            delete printerData.config;
            delete printerData.kiosk_config;

            let printerArray = Object.entries(printerData);
            if (globalKioskConfig.kiosk_sort_by === 'status') {
                const statusOrder = globalConfig.status_order || [];
                const statusMap = new Map(statusOrder.map((status, index) => [status, index]));
                printerArray.sort(([, a], [, b]) => (statusMap.get(a.state) ?? 999) - (statusMap.get(b.state) ?? 999));
            } else if (globalKioskConfig.kiosk_sort_by === 'manual' || !globalKioskConfig.kiosk_sort_by) {
                const printerOrder = globalConfig.printer_order || [];
                const printerMap = new Map(printerOrder.map((name, index) => [name, index]));
                printerArray.sort(([aName], [bName]) => (printerMap.get(aName) ?? 999) - (printerMap.get(bName) ?? 999));
            }

            let printerSlides = [];
            const printersPerPage = globalKioskConfig.kiosk_printers_per_page || 6;
            for (let i = 0; i < printerArray.length; i += printersPerPage) {
                printerSlides.push({ isImage: false, printers: printerArray.slice(i, i + printersPerPage) });
            }

            slides = [];
            const imageFrequency = globalKioskConfig.kiosk_image_frequency || 2;
            const imagesPerSlot = globalKioskConfig.kiosk_images_per_slot || 1;
            const images = globalKioskConfig.kiosk_images || [];
            if (printerSlides.length === 0 && images.length > 0) {
                 images.forEach(image => {
                    slides.push({ isImage: true, url: image.url, time: image.time });
                 });
            } else {
                for (let i = 0; i < printerSlides.length; i++) {
                    slides.push(printerSlides[i]);
                    if (images.length > 0 && (i + 1) % imageFrequency === 0) {
                        for (let j = 0; j < imagesPerSlot; j++) {
                            const image = images[imageIndex % images.length];
                            slides.push({ isImage: true, url: image.url, time: image.time });
                            imageIndex++;
                        }
                    }
                }
            }
            
            kioskContainer.innerHTML = '';
            if (slides.length === 0) {
                kioskContainer.innerHTML = '<h1 style="text-align:center; color: white; padding-top: 2rem;">No printers to display.</h1>';
                return;
            }

            slides.forEach((slideData, index) => {
                const slideDiv = document.createElement('div');
                slideDiv.className = 'slide';
                slideDiv.id = 'slide-' + index;

                if (slideData.isImage) {
                    slideDiv.classList.add('image-slide');
                    slideDiv.style.backgroundImage = `url(${slideData.url})`;
                } else {
                    slideDiv.classList.add('printer-slide');
                    let gridCols = 'repeat(auto-fit, minmax(300px, 1fr))';
                    if (slideData.printers.length <= 3) gridCols = `repeat(${slideData.printers.length}, 1fr)`;
                    else if (slideData.printers.length === 4) gridCols = 'repeat(2, 1fr)';
                    else if (slideData.printers.length > 4 && slideData.printers.length <= 6) gridCols = 'repeat(3, 1fr)';
                    else if (slideData.printers.length > 6) gridCols = 'repeat(4, 1fr)';
                    slideDiv.style.gridTemplateColumns = gridCols;
                    
                    slideData.printers.forEach(([printerName, pData]) => {
                        slideDiv.innerHTML += createPrinterCardHtml(printerName, pData);
                    });
                }
                kioskContainer.appendChild(slideDiv);
            });

            // Restart slideshow at the first slide whenever we rebuild
            currentSlideIndex = 0;
            cycleSlide();
        }
        
        function cycleSlide() {
            clearTimeout(slideTimeout);
            if (slides.length === 0) return;

            document.querySelectorAll('.slide.active').forEach(el => el.classList.remove('active'));

            const current = slides[currentSlideIndex];
            if (!current) {
                currentSlideIndex = 0;
                cycleSlide();
                return;
            }

            kioskHeader.style.display = current.isImage ? 'none' : 'flex';

            let slideEl = document.getElementById('slide-' + currentSlideIndex);
            if (!slideEl) {
                console.warn(`slide-${currentSlideIndex} not found, falling back to slide-0`);
                currentSlideIndex = 0;
                slideEl = document.getElementById('slide-0');
                if (!slideEl) return;
            }

            slideEl.classList.add('active');

            if (slides.length <= 1) return;

            const delaySec = current.isImage
                ? (current.time || globalKioskConfig.kiosk_image_page_time || 5)
                : (globalKioskConfig.kiosk_printer_page_time || 10);
            
            currentSlideIndex = (currentSlideIndex + 1) % slides.length;
            slideTimeout = setTimeout(cycleSlide, delaySec * 1000);
        }

        function initialLoad() {
            $.getJSON('/status')
                .done(data => {
                    const refreshInterval = (data.config.refresh_interval_sec || 30) * 1000;
                    buildAndRenderSlides(data);
                    
                    setInterval(() => {
                        $.getJSON('/status').done(buildAndRenderSlides);
                    }, refreshInterval);
                })
                .fail(() => {
                    kioskContainer.innerHTML = '<h1 style="text-align:center; color: red; padding-top: 2rem;">Error fetching status. Retrying...</h1>';
                    setTimeout(initialLoad, 5000);
                });
        }

        $(document).ready(function(){
            initialLoad();
        });
    </script>
</body>
</html>
EOF
echo "    > templates/kiosk.html created."

# --- 10. Make script executable ---
chmod +x aggregator_with_ui.py

echo ""
echo "--- ✅ Setup Complete ---"
echo ""
echo "Next steps:"
echo "1. Install Python dependencies:"
echo "   sudo apt update && sudo apt install -y python3-flask python3-requests python3-werkzeug"
echo "2. Run the application:      python3 aggregator_with_ui.py"
echo "3. Open your browser to http://<your_ip>:8080/admin and log in."
echo "   > Default SYSTEM login is:  system / changeme"
echo "   > Default ADMIN login is:   admin / changeme"
echo "   > CHANGE THESE PASSWORDS IMMEDIATELY using the system account."
echo""