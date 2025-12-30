import sqlite3
import hashlib
import os
from datetime import datetime

def get_db_connection():
    conn = sqlite3.connect('database.db')
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

def delete_file(file_id, user_id):
    conn = get_db_connection()
    
    # Get file info first
    file = get_file_by_id(file_id, user_id)
    
    if file:
        # Delete from database
        conn.execute('DELETE FROM files WHERE file_id = ? AND user_id = ?', (file_id, user_id))
        conn.commit()
    
    conn.close()
    return file

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

# Initialize database on import
init_db()