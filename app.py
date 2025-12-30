import os
import subprocess
import threading
import time
import signal
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, make_response
from werkzeug.utils import secure_filename
import json
import psutil
import uuid
from datetime import datetime, timedelta
import secrets
import sqlite3
import hashlib
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configuration
UPLOAD_FOLDER = 'uploads'
HOSTED_FILES_FOLDER = 'hosted_files'
DATABASE = 'database.db'
ALLOWED_EXTENSIONS = {'py'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['HOSTED_FILES_FOLDER'] = HOSTED_FILES_FOLDER
app.config['DATABASE'] = DATABASE

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(HOSTED_FILES_FOLDER, exist_ok=True)

# Global dictionary to track running processes
running_processes = {}

# ==================== DATABASE FUNCTIONS ====================

def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')
    
    # Files table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            file_id TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'uploaded',
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            pid INTEGER,
            last_output TEXT,
            last_error TEXT,
            detected_imports TEXT,
            installed_modules TEXT,
            failed_modules TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # User sessions table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, email, password):
    conn = get_db_connection()
    hashed_password = hash_password(password)
    
    try:
        conn.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            (username, email, hashed_password)
        )
        conn.commit()
        user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        conn.close()
        return None

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    conn.close()
    return user

def get_user_by_email(email):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE email = ?',
        (email,)
    ).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()
    return user

def verify_password(username, password):
    user = get_user_by_username(username)
    if user and user['password'] == hash_password(password):
        return user
    return None

def create_session(user_id, token, expires_hours=24):
    conn = get_db_connection()
    expires_at = datetime.now().timestamp() + (expires_hours * 3600)
    
    conn.execute(
        'INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)',
        (user_id, token, expires_at)
    )
    conn.commit()
    conn.close()

def get_session(token):
    conn = get_db_connection()
    session = conn.execute(
        '''SELECT s.*, u.username, u.is_admin 
           FROM sessions s 
           JOIN users u ON s.user_id = u.id 
           WHERE s.session_token = ? AND s.expires_at > ?''',
        (token, datetime.now().timestamp())
    ).fetchone()
    conn.close()
    return session

def delete_session(token):
    conn = get_db_connection()
    conn.execute('DELETE FROM sessions WHERE session_token = ?', (token,))
    conn.commit()
    conn.close()

def cleanup_expired_sessions():
    conn = get_db_connection()
    conn.execute('DELETE FROM sessions WHERE expires_at <= ?', (datetime.now().timestamp(),))
    conn.commit()
    conn.close()

def save_file_metadata(user_id, file_data):
    conn = get_db_connection()
    
    conn.execute('''
        INSERT INTO files 
        (user_id, filename, original_filename, filepath, file_id, status, 
         upload_time, detected_imports)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        file_data['filename'],
        file_data['original_filename'],
        file_data['filepath'],
        file_data['file_id'],
        file_data['status'],
        file_data['upload_time'],
        ','.join(file_data['detected_imports']) if file_data['detected_imports'] else ''
    ))
    
    conn.commit()
    conn.close()

def update_file_status(file_id, status_data):
    conn = get_db_connection()
    
    update_fields = []
    values = []
    
    for field in ['status', 'pid', 'start_time', 'end_time', 'last_output', 
                  'last_error', 'installed_modules', 'failed_modules']:
        if field in status_data and status_data[field] is not None:
            update_fields.append(f"{field} = ?")
            if isinstance(status_data[field], list):
                values.append(','.join(status_data[field]))
            else:
                values.append(status_data[field])
    
    values.append(file_id)
    
    if update_fields:
        query = f"UPDATE files SET {', '.join(update_fields)} WHERE file_id = ?"
        conn.execute(query, values)
        conn.commit()
    
    conn.close()

def get_user_files(user_id):
    conn = get_db_connection()
    files = conn.execute(
        '''SELECT * FROM files 
           WHERE user_id = ? 
           ORDER BY upload_time DESC''',
        (user_id,)
    ).fetchall()
    conn.close()
    return files

def get_file_by_id(file_id, user_id=None):
    conn = get_db_connection()
    if user_id:
        file = conn.execute(
            'SELECT * FROM files WHERE file_id = ? AND user_id = ?',
            (file_id, user_id)
        ).fetchone()
    else:
        file = conn.execute(
            'SELECT * FROM files WHERE file_id = ?',
            (file_id,)
        ).fetchone()
    conn.close()
    return file

def delete_file_db(file_id, user_id):
    conn = get_db_connection()
    
    # Get file info first
    file = get_file_by_id(file_id, user_id)
    
    if file:
        # Delete from database
        conn.execute('DELETE FROM files WHERE file_id = ? AND user_id = ?', (file_id, user_id))
        conn.commit()
    
    conn.close()
    return file

def get_file_count_by_user(user_id):
    conn = get_db_connection()
    count = conn.execute(
        'SELECT COUNT(*) FROM files WHERE user_id = ?',
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return count

def get_total_file_count():
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) FROM files').fetchone()[0]
    conn.close()
    return count

def get_all_files():
    conn = get_db_connection()
    files = conn.execute(
        '''SELECT f.*, u.username 
           FROM files f 
           JOIN users u ON f.user_id = u.id 
           ORDER BY f.upload_time DESC'''
    ).fetchall()
    conn.close()
    return files

# ==================== HELPER FUNCTIONS ====================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_imports(filepath):
    """Extract imports from Python file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        imports = set()
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if line.startswith('#') or not line:
                continue
                
            if line.startswith('import '):
                parts = line.split('import ')[1].split()
                if parts:
                    module = parts[0].split('.')[0]
                    # Skip relative imports
                    if not module.startswith('.'):
                        imports.add(module)
            elif line.startswith('from '):
                parts = line.split('from ')[1].split(' import')[0]
                module = parts.strip().split('.')[0]
                # Skip relative imports
                if not module.startswith('.'):
                    imports.add(module)
        
        return imports
    except Exception as e:
        print(f"Error extracting imports: {e}")
        return set()

def install_requirements(imports):
    """Install required modules"""
    # Common built-in modules that don't need installation
    builtin_modules = {
        'os', 'sys', 'json', 'time', 'datetime', 'math', 'random',
        're', 'collections', 'itertools', 'functools', 'threading',
        'subprocess', 'hashlib', 'base64', 'uuid', 'pathlib', 'typing',
        'flask', 'werkzeug', 'psutil', 'sqlite3', 'hashlib', 'secrets'
    }
    
    # Filter out built-in modules
    imports_to_install = imports - builtin_modules
    
    installed_modules = []
    failed_modules = []
    
    if imports_to_install:
        print(f"Installing requirements: {imports_to_install}")
        for module in imports_to_install:
            try:
                # Check if module is already installed
                subprocess.check_call([sys.executable, '-c', f"import {module}"])
                print(f"{module} is already installed")
                installed_modules.append(f"{module} (already installed)")
            except:
                try:
                    # Try to install the module
                    result = subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', module],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    if result.returncode == 0:
                        print(f"Successfully installed {module}")
                        installed_modules.append(module)
                    else:
                        print(f"Failed to install {module}: {result.stderr}")
                        failed_modules.append(module)
                except subprocess.TimeoutExpired:
                    print(f"Timeout installing {module}")
                    failed_modules.append(module)
                except Exception as e:
                    print(f"Error installing {module}: {e}")
                    failed_modules.append(module)
    
    return installed_modules, failed_modules

def run_python_file(file_id, filepath, user_id):
    """Run the Python file in a separate process"""
    try:
        # Get file metadata
        file_data = get_file_by_id(file_id, user_id)
        if not file_data:
            print(f"File {file_id} not found for user {user_id}")
            return False
        
        # Extract and install requirements
        imports = extract_imports(filepath)
        installed, failed = install_requirements(imports)
        
        # Run the file with output capture
        process = subprocess.Popen(
            [sys.executable, '-u', filepath],  # -u for unbuffered output
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            encoding='utf-8'
        )
        
        running_processes[file_id] = {
            'process': process,
            'filepath': filepath,
            'user_id': user_id,
            'start_time': time.time()
        }
        
        # Update database
        update_file_status(file_id, {
            'status': 'running',
            'pid': process.pid,
            'start_time': time.time(),
            'installed_modules': installed,
            'failed_modules': failed
        })
        
        # Function to capture output in real-time
        def capture_output():
            output_lines = []
            error_lines = []
            
            try:
                # Read stdout and stderr
                while True:
                    # Check if process is still running
                    if process.poll() is not None:
                        # Process ended, read remaining output
                        stdout, stderr = process.communicate()
                        if stdout:
                            output_lines.append(stdout)
                        if stderr:
                            error_lines.append(stderr)
                        break
                    
                    # Try to read from stdout
                    try:
                        stdout_line = process.stdout.readline()
                        if stdout_line:
                            output_lines.append(stdout_line)
                            # Update output in database every 10 lines
                            if len(output_lines) % 10 == 0:
                                update_file_status(file_id, {
                                    'last_output': ''.join(output_lines[-1000:]),
                                    'last_error': ''.join(error_lines[-1000:])
                                })
                    except:
                        pass
                    
                    # Try to read from stderr
                    try:
                        stderr_line = process.stderr.readline()
                        if stderr_line:
                            error_lines.append(stderr_line)
                            # Update error in database
                            update_file_status(file_id, {
                                'last_output': ''.join(output_lines[-1000:]),
                                'last_error': ''.join(error_lines[-1000:])
                            })
                    except:
                        pass
                    
                    time.sleep(0.1)
            except Exception as e:
                print(f"Error capturing output: {e}")
            
            # Final update after process ends
            update_file_status(file_id, {
                'status': 'stopped',
                'end_time': time.time(),
                'last_output': ''.join(output_lines[-2000:]),
                'last_error': ''.join(error_lines[-2000:])
            })
            
            # Remove from running processes
            if file_id in running_processes:
                del running_processes[file_id]
        
        # Start output capture in a separate thread
        capture_thread = threading.Thread(target=capture_output)
        capture_thread.daemon = True
        capture_thread.start()
        
        return True
    except Exception as e:
        print(f"Error running Python file: {e}")
        # Update database with error
        update_file_status(file_id, {
            'status': 'error',
            'last_error': str(e)
        })
        return False

def stop_process(file_id, user_id):
    """Stop a running process"""
    if file_id in running_processes and running_processes[file_id]['user_id'] == user_id:
        process = running_processes[file_id]['process']
        
        # Try to terminate gracefully
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force kill if not terminated
            process.kill()
            process.wait()
        
        # Update database
        update_file_status(file_id, {
            'status': 'stopped',
            'end_time': time.time()
        })
        
        # Remove from running processes
        del running_processes[file_id]
        return True
    return False

# ==================== AUTHENTICATION DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        if not session_token or not get_session(session_token):
            flash('Please login to access this page')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        session = get_session(session_token)
        if not session or not session['is_admin']:
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== TEMPLATE FILTERS ====================

@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(timestamp):
    if timestamp:
        try:
            dt = datetime.fromtimestamp(float(timestamp))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid timestamp"
    return "N/A"

@app.template_filter('format_time')
def format_time_filter(timestamp):
    if timestamp:
        try:
            dt = datetime.fromtimestamp(float(timestamp))
            return dt.strftime('%b %d, %Y %I:%M %p')
        except:
            return "Invalid timestamp"
    return "N/A"

@app.template_filter('file_exists')
def file_exists_filter(filepath):
    return os.path.exists(filepath) if filepath else False

@app.template_filter('file_size')
def file_size_filter(filepath):
    try:
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            if size < 1024:
                return f"{size} B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
    except:
        pass
    return "0 B"

@app.template_filter('time_ago')
def time_ago_filter(timestamp):
    if not timestamp:
        return "Never"
    
    try:
        dt = datetime.fromtimestamp(float(timestamp))
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 365:
            return f"{diff.days // 365} years ago"
        elif diff.days > 30:
            return f"{diff.days // 30} months ago"
        elif diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600} hours ago"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60} minutes ago"
        else:
            return "Just now"
    except:
        return "Invalid time"

# ==================== CONTEXT PROCESSOR ====================

@app.context_processor
def inject_user():
    def get_current_user():
        session_token = request.cookies.get('session_token')
        if session_token:
            session = get_session(session_token)
            if session:
                return get_user_by_id(session['user_id'])
        return None
    
    return dict(current_user=get_current_user())

# ==================== ROUTES ====================

@app.route('/')
def index():
    user = get_current_user()
    if user:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password')
            return render_template('login.html')
        
        user = verify_password(username, password)
        
        if user:
            # Create session
            session_token = secrets.token_hex(32)
            create_session(user['id'], session_token)
            
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('session_token', session_token, httponly=True, max_age=24*3600)
            flash('Login successful!')
            return response
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
        
        # Check if user already exists
        if get_user_by_username(username):
            flash('Username already exists')
            return render_template('register.html')
        
        if get_user_by_email(email):
            flash('Email already registered')
            return render_template('register.html')
        
        # Create user
        user_id = create_user(username, email, password)
        
        if user_id:
            # Auto login after registration
            session_token = secrets.token_hex(32)
            create_session(user_id, session_token)
            
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('session_token', session_token, httponly=True, max_age=24*3600)
            flash('Registration successful! Welcome to Python File Hosting')
            return response
        else:
            flash('Registration failed. Please try again.')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token:
        delete_session(session_token)
    
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('session_token')
    flash('Logged out successfully')
    return response

@app.route('/dashboard')
@login_required
def dashboard():
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    files = get_user_files(user['id'])
    file_count = get_file_count_by_user(user['id'])
    
    # Get running files count
    running_count = sum(1 for file in files if file['status'] == 'running')
    
    return render_template('dashboard.html', 
                         user=user, 
                         files=files[:5],  # Show only recent 5 files
                         file_count=file_count,
                         running_count=running_count)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())[:8]
        
        # Save uploaded file with user folder structure
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user['id']))
        os.makedirs(user_folder, exist_ok=True)
        
        filepath = os.path.join(user_folder, f"{file_id}_{filename}")
        file.save(filepath)
        
        # Extract imports
        imports = extract_imports(filepath)
        
        # Create file metadata
        file_data = {
            'filename': filename,
            'original_filename': file.filename,
            'filepath': filepath,
            'file_id': file_id,
            'status': 'uploaded',
            'upload_time': time.time(),
            'detected_imports': list(imports)
        }
        
        # Save to database
        save_file_metadata(user['id'], file_data)
        
        flash(f'File uploaded successfully! File ID: {file_id}')
        return redirect(url_for('file_detail', file_id=file_id))
    
    flash('Invalid file type. Only .py files are allowed.')
    return redirect(url_for('dashboard'))

@app.route('/files')
@login_required
def list_files():
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    files = get_user_files(user['id'])
    return render_template('files.html', user=user, files=files)

@app.route('/file/<file_id>')
@login_required
def file_detail(file_id):
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    file_data = get_file_by_id(file_id, user['id'])
    
    if not file_data:
        flash('File not found or access denied')
        return redirect(url_for('list_files'))
    
    # Check if file still exists
    if not os.path.exists(file_data['filepath']):
        flash('File not found on disk')
        return redirect(url_for('list_files'))
    
    # Check if process is actually running
    if file_data['status'] == 'running' and file_data['pid']:
        try:
            process = psutil.Process(file_data['pid'])
            if not process.is_running():
                update_file_status(file_id, {'status': 'stopped'})
                file_data = get_file_by_id(file_id, user['id'])
        except psutil.NoSuchProcess:
            update_file_status(file_id, {'status': 'stopped'})
            file_data = get_file_by_id(file_id, user['id'])
        except:
            pass
    
    # Read file content for preview
    file_content = ""
    if os.path.exists(file_data['filepath']):
        try:
            with open(file_data['filepath'], 'r', encoding='utf-8') as f:
                file_content = f.read()
        except:
            file_content = "Unable to read file content"
    
    # Parse stored lists
    detected_imports = file_data['detected_imports'].split(',') if file_data['detected_imports'] else []
    installed_modules = file_data['installed_modules'].split(',') if file_data['installed_modules'] else []
    failed_modules = file_data['failed_modules'].split(',') if file_data['failed_modules'] else []
    
    return render_template('file_detail.html', 
                         user=user, 
                         file=file_data,
                         file_content=file_content,
                         detected_imports=detected_imports,
                         installed_modules=installed_modules,
                         failed_modules=failed_modules)

@app.route('/start/<file_id>')
@login_required
def start_file(file_id):
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    file_data = get_file_by_id(file_id, user['id'])
    
    if not file_data:
        flash('File not found or access denied')
        return redirect(url_for('list_files'))
    
    if not os.path.exists(file_data['filepath']):
        flash('File not found on disk')
        return redirect(url_for('file_detail', file_id=file_id))
    
    if file_data['status'] == 'running':
        flash('File is already running')
    else:
        success = run_python_file(file_id, file_data['filepath'], user['id'])
        if success:
            flash('File started successfully. Modules are being installed automatically.')
        else:
            flash('Failed to start file')
    
    return redirect(url_for('file_detail', file_id=file_id))

@app.route('/stop/<file_id>')
@login_required
def stop_file(file_id):
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    if stop_process(file_id, user['id']):
        flash('File stopped successfully')
    else:
        flash('File was not running or could not be stopped')
    
    return redirect(url_for('file_detail', file_id=file_id))

@app.route('/delete/<file_id>')
@login_required
def delete_file(file_id):
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    file_data = delete_file_db(file_id, user['id'])
    
    if file_data:
        # Stop if running
        if file_data['status'] == 'running':
            stop_process(file_id, user['id'])
        
        # Delete uploaded file
        if os.path.exists(file_data['filepath']):
            try:
                os.remove(file_data['filepath'])
            except:
                pass
        
        flash('File deleted successfully')
    else:
        flash('File not found or access denied')
    
    return redirect(url_for('list_files'))

@app.route('/download/<file_id>')
@login_required
def download_file(file_id):
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    file_data = get_file_by_id(file_id, user['id'])
    
    if not file_data:
        flash('File not found or access denied')
        return redirect(url_for('list_files'))
    
    if os.path.exists(file_data['filepath']):
        return send_file(
            file_data['filepath'],
            as_attachment=True,
            download_name=file_data['original_filename']
        )
    
    flash('File not found on disk')
    return redirect(url_for('list_files'))

@app.route('/view_output/<file_id>')
@login_required
def view_output(file_id):
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    file_data = get_file_by_id(file_id, user['id'])
    
    if not file_data:
        return "File not found or access denied", 404
    
    output = file_data['last_output'] or 'No output available'
    error = file_data['last_error'] or ''
    
    result = f"=== Output for {file_data['original_filename']} ===\n\n"
    result += f"Status: {file_data['status']}\n"
    
    if file_data['start_time']:
        result += f"Started: {datetime.fromtimestamp(file_data['start_time']).strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    if file_data['end_time']:
        result += f"Ended: {datetime.fromtimestamp(file_data['end_time']).strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    result += f"\n{'='*50}\nOUTPUT:\n{'='*50}\n{output}\n"
    
    if error:
        result += f"\n{'='*50}\nERRORS:\n{'='*50}\n{error}\n"
    
    installed = file_data['installed_modules'].split(',') if file_data['installed_modules'] else []
    failed = file_data['failed_modules'].split(',') if file_data['failed_modules'] else []
    
    if installed:
        result += f"\n{'='*50}\nINSTALLED MODULES:\n{'='*50}\n"
        for module in installed:
            result += f"- {module}\n"
    
    if failed:
        result += f"\n{'='*50}\nFAILED TO INSTALL:\n{'='*50}\n"
        for module in failed:
            result += f"- {module}\n"
    
    return f"<pre style='padding: 20px; background: #f5f5f5; border-radius: 5px; font-family: monospace;'>{result}</pre>"

@app.route('/profile')
@login_required
def profile():
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    files = get_user_files(user['id'])
    file_count = get_file_count_by_user(user['id'])
    
    # Get running files count
    running_count = sum(1 for file in files if file['status'] == 'running')
    
    # Calculate total storage used
    total_size = 0
    for file in files:
        if os.path.exists(file['filepath']):
            total_size += os.path.getsize(file['filepath'])
    
    return render_template('profile.html', 
                         user=user, 
                         file_count=file_count,
                         running_count=running_count,
                         total_size=total_size)

@app.route('/admin/files')
@admin_required
def admin_files():
    session_token = request.cookies.get('session_token')
    session = get_session(session_token)
    user = get_user_by_id(session['user_id'])
    
    files = get_all_files()
    total_count = get_total_file_count()
    
    return render_template('admin_files.html', 
                         user=user, 
                         files=files,
                         total_count=total_count)

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'running_processes': len(running_processes)
    }), 200

@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Cleanup expired sessions and orphaned files"""
    try:
        cleanup_expired_sessions()
        
        # Clean orphaned files
        conn = get_db_connection()
        all_files = conn.execute('SELECT * FROM files').fetchall()
        
        deleted_count = 0
        for file in all_files:
            if not os.path.exists(file['filepath']):
                conn.execute('DELETE FROM files WHERE id = ?', (file['id'],))
                deleted_count += 1
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'deleted_files': deleted_count,
            'message': f'Cleanup completed. Deleted {deleted_count} orphaned files.'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(413)
def too_large(e):
    flash('File is too large. Maximum size is 16MB.')
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error="Internal server error"), 500

# ==================== HELPER FUNCTIONS ====================

def get_current_user():
    """Helper function to get current user from session"""
    session_token = request.cookies.get('session_token')
    if session_token:
        session = get_session(session_token)
        if session:
            return get_user_by_id(session['user_id'])
    return None

# ==================== INITIALIZATION ====================

# Initialize database on startup
init_db()

# Start cleanup thread for expired sessions
def cleanup_thread_func():
    while True:
        try:
            cleanup_expired_sessions()
            time.sleep(3600)  # Run every hour
        except Exception as e:
            print(f"Cleanup thread error: {e}")
            time.sleep(300)

cleanup_thread = threading.Thread(target=cleanup_thread_func, daemon=True)
cleanup_thread.start()

# ==================== MAIN ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)