#!/usr/bin/env python3
"""
aggregator_with_ui.py (v63 - Optional Printerless Kiosks)

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
- Kiosks can now be created without printer slides for image-only displays.
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
KIOSK_DIR = os.path.join(BASE_DIR, 'kiosks')
KIOSK_CONFIG_FILE = os.path.join(KIOSK_DIR, 'default.json')
LOG_FILE = os.path.join(BASE_DIR, 'activity.log')
PRINTER_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/printer_images')
KIOSK_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/kiosk_images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
CACHE_TTL = 5 # Lower TTL for more responsive status discovery
HTTP_PORT = 80

BASE_PERMISSIONS = [
    'view_dashboard', 'set_overrides', 'view_logs',
    'add_printer', 'edit_printer', 'delete_printer',
    'add_user', 'delete_user', 'change_user_password', 'change_user_role',
    'manage_roles', 'manage_config', 'manage_kiosk', 'manage_kiosk_frequency'
]

def get_available_permissions():
    kiosks = []
    if os.path.isdir(KIOSK_DIR):
        kiosks = [f.split('.')[0] for f in os.listdir(KIOSK_DIR) if f.endswith('.json')]
    return BASE_PERMISSIONS + [f'manage_kiosk_{k}' for k in kiosks if k != 'default']

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

DEFAULT_KIOSK_CONFIG = {
    "name": "Main Kiosk",
    "kiosk_printers_per_page": 6,
    "kiosk_printer_page_time": 10,
    "kiosk_image_page_time": 5,
    "kiosk_image_frequency": 2,
    "kiosk_images_per_slot": 1,
    "kiosk_images": [],
    "kiosk_background_color": "#000000",
    "kiosk_sort_by": "manual",
    "kiosk_title": "",
    "kiosk_header_image": "",
    "kiosk_header_height_px": 150,
    "show_printers": True
}

def get_kiosk_config(kiosk_id='default'):
    if not os.path.isdir(KIOSK_DIR):
        os.makedirs(KIOSK_DIR, exist_ok=True)
    config_path = os.path.join(KIOSK_DIR, f"{kiosk_id}.json")
    user_config = load_data(config_path, DEFAULT_KIOSK_CONFIG)

    if user_config.get('kiosk_images') and all(isinstance(img, str) for img in user_config['kiosk_images']):
        default_time = user_config.get('kiosk_image_page_time', 5)
        user_config['kiosk_images'] = [{'url': url, 'time': default_time} for url in user_config['kiosk_images']]

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
def root():
    """Serve the dashboard when no route is specified."""
    return dashboard()

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
    kiosk_id = request.args.get('kiosk', 'default')
    status_data = get_status_data()
    config = get_full_config()
    kiosk_config = get_kiosk_config(kiosk_id)
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
    kiosk_configs = list_kiosk_configs()
    kiosk_config = kiosk_configs.get('default', DEFAULT_KIOSK_CONFIG)
    
    # Always fetch fresh data for the admin page to discover all statuses
    live_statuses = fetch_all(printers)
    
    all_statuses = set(config.get('manual_statuses', []))
    for status_key in config.get('status_colors', {}).keys():
        all_statuses.add(status_key.replace('_', ' ').title())
    
    for printer_data in live_statuses.values():
        if printer_data.get('state'):
            all_statuses.add(printer_data['state'])

    log_content = ""
    user_role = session.get('role')
    user_permissions = roles.get(user_role, {}).get('permissions', [])
    if 'view_logs' in user_permissions or '*' in user_permissions:
        try:
            with open(LOG_FILE, 'r') as f: log_content = f.read()
        except FileNotFoundError: log_content = "Log file not found."
    perms = get_available_permissions()
    can_add_kiosk = (
        '*' in user_permissions
        or 'manage_kiosk' in user_permissions
        or any(p.startswith('manage_kiosk_') for p in user_permissions)
    )
    return render_template(
        'admin.html',
        printers=printers,
        overrides=overrides,
        users=users,
        roles=roles,
        config=config,
        kiosk_config=kiosk_config,
        kiosk_configs=kiosk_configs,
        manual_statuses=config.get('manual_statuses', []),
        all_statuses=sorted(list(all_statuses)),
        available_permissions=perms,
        log_content=log_content,
        can_add_kiosk=can_add_kiosk,
    )

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
    perms = get_available_permissions()
    return render_template('edit_role.html', role_name=role_name, role_data=role_to_edit, available_permissions=perms)

@app.route('/admin/config', methods=['POST'])
def manage_config():
    roles = load_data(ROLES_FILE, {})
    user_perms = roles.get(session.get('role'), {}).get('permissions', [])
    def has_perm(p):
        return p in user_perms or '*' in user_perms
    config = get_full_config()
    action = request.form.get('action')

    if action == 'update_appearance':
        if not has_perm('manage_config'):
            flash('You do not have permission to update appearance.', 'danger')
            return redirect(url_for('admin'))
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
        if not (has_perm('manage_kiosk') or has_perm(f'manage_kiosk_{request.form.get("kiosk_id", "default")}')):
            flash('You do not have permission to update kiosk.', 'danger')
            return redirect(url_for('admin'))
        kiosk_id = request.form.get('kiosk_id', 'default')
        kiosk_config = get_kiosk_config(kiosk_id)
        kiosk_config['kiosk_printers_per_page'] = int(request.form.get('kiosk_printers_per_page', 6))
        kiosk_config['kiosk_printer_page_time'] = int(request.form.get('kiosk_printer_page_time', 10))
        kiosk_config['kiosk_image_page_time'] = int(request.form.get('kiosk_image_page_time', 5))
        kiosk_config['kiosk_image_frequency'] = int(request.form.get('kiosk_image_frequency', 2))
        kiosk_config['kiosk_images_per_slot'] = int(request.form.get('kiosk_images_per_slot', 1))

        kiosk_config['show_printers'] = bool(request.form.get('show_printers'))

        kiosk_config['kiosk_background_color'] = request.form.get('kiosk_background_color', '#000000')
        kiosk_config['kiosk_sort_by'] = request.form.get('kiosk_sort_by', 'manual')
        kiosk_config['kiosk_title'] = request.form.get('kiosk_title', '')
        kiosk_config['kiosk_header_height_px'] = int(request.form.get('kiosk_header_height_px', 150))
        name = request.form.get('kiosk_name')
        if name:
            kiosk_config['name'] = name

        if 'kiosk_header_image_file' in request.files:
            file = request.files['kiosk_header_image_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"header_{file.filename}")
                file.save(os.path.join(app.config['KIOSK_UPLOAD_FOLDER'], filename))
                kiosk_config['kiosk_header_image'] = url_for('static', filename=f"kiosk_images/{filename}")
        save_data(kiosk_config, os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))
        flash('Kiosk settings updated.', 'success')
    elif action == 'update_colors':
        if not has_perm('manage_config'):
            flash('You do not have permission to update colors.', 'danger')
            return redirect(url_for('admin'))
        config['status_colors'] = {key: value for key, value in request.form.items() if key != 'action'}
        save_data(config, CONFIG_FILE)
        flash('Status colors updated.', 'success')
    elif action == 'add_status':
        if not has_perm('manage_config'):
            flash('You do not have permission to add status.', 'danger')
            return redirect(url_for('admin'))
        new_status = request.form.get('new_status_name')
        if new_status and new_status not in config.get('manual_statuses', []):
            config.setdefault('manual_statuses', []).append(new_status)
            config.setdefault('status_colors', {})[new_status.lower().replace(' ', '_')] = '#6c757d'
            save_data(config, CONFIG_FILE)
            flash(f"Status '{new_status}' added.", 'success')
        else:
            flash('Invalid name or status already exists.', 'danger')
    elif action == 'delete_status':
        if not has_perm('manage_config'):
            flash('You do not have permission to delete status.', 'danger')
            return redirect(url_for('admin'))
        status_to_delete = request.form.get('status_name')
        if status_to_delete in config.get('manual_statuses', []):
            config['manual_statuses'].remove(status_to_delete)
            config.get('status_colors', {}).pop(status_to_delete.lower().replace(' ', '_'), None)
            save_data(config, CONFIG_FILE)
            flash(f"Status '{status_to_delete}' deleted.", 'success')
        else:
            flash('Status not found.', 'danger')
    elif action == 'update_aliases':
        if not has_perm('manage_config'):
            flash('You do not have permission to update aliases.', 'danger')
            return redirect(url_for('admin'))
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
    kiosk_id = request.form.get('kiosk_id', 'default')
    kiosk_config = get_kiosk_config(kiosk_id)
    
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

    save_data(kiosk_config, os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))
    flash("Kiosk images updated.", 'success')
    return redirect(url_for('admin'))

@app.route('/admin/kiosks', methods=['POST'])
@require_permission('manage_kiosk')
def manage_kiosks():
    action = request.form.get('action')
    kiosk_id = request.form.get('kiosk_id', '').strip()
    if not kiosk_id:
        flash('Kiosk ID required.', 'danger')
        return redirect(url_for('admin'))
    if action == 'add_kiosk':
        path = os.path.join(KIOSK_DIR, f"{kiosk_id}.json")
        if os.path.exists(path):
            flash('Kiosk already exists.', 'danger')
        else:
            config = DEFAULT_KIOSK_CONFIG.copy()
            config['name'] = request.form.get('kiosk_name', kiosk_id)
            config['show_printers'] = bool(request.form.get('show_printers'))
            save_data(config, path)
            flash('Kiosk added.', 'success')
    elif action == 'delete_kiosk':
        if kiosk_id == 'default':
            flash('Cannot delete default kiosk.', 'danger')
        else:
            try:
                os.remove(os.path.join(KIOSK_DIR, f"{kiosk_id}.json"))
                flash('Kiosk deleted.', 'success')
            except FileNotFoundError:
                flash('Kiosk not found.', 'danger')
    return redirect(url_for('admin'))


@app.route('/dashboard')
def dashboard():
    config = get_full_config()
    dashboard_title = config.get('dashboard_title', 'Printer Dashboard')
    return render_template('dashboard.html', dashboard_title=dashboard_title)

@app.route('/kiosk')
@app.route('/kiosk/<kiosk_id>')
def kiosk(kiosk_id='default'):
    return render_template('kiosk.html', kiosk_id=kiosk_id)

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
    if not os.path.exists(KIOSK_DIR):
        os.makedirs(KIOSK_DIR, exist_ok=True)
    if not os.path.exists(KIOSK_CONFIG_FILE):
        print("First run: Creating default kiosk configuration.")
        get_kiosk_config()  # This will create and save the default kiosk config
    
    app.run(host='0.0.0.0', port=HTTP_PORT, debug=True)
