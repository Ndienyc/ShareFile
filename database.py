import sqlite3
import os
import secrets

DB_FILE = 'files.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            pin_code TEXT NOT NULL,
            download_limit INTEGER NOT NULL,
            download_count INTEGER DEFAULT 0,
            auto_delete INTEGER DEFAULT 0,
            uploader TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", "admin"))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

def register_user(username, password):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password))
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(username, password):
    with sqlite3.connect(DB_FILE) as conn:
        return conn.execute('SELECT 1 FROM users WHERE username = ? AND password_hash = ?',
                            (username, password)).fetchone() is not None

def get_all_users():
    with sqlite3.connect(DB_FILE) as conn:
        return [r[0] for r in conn.execute('SELECT username FROM users').fetchall()]

def save_file_info(uploader, filename, storage_path, pin_code, download_limit, auto_delete=False):
    token = secrets.token_urlsafe(12)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT INTO files (uploader, filename, storage_path, token, pin_code, download_limit, auto_delete)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (uploader, filename, storage_path, token, pin_code, download_limit, int(auto_delete)))
    return token

def get_file_by_token(token):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute('''
            SELECT filename, storage_path, pin_code, download_limit, download_count, uploader, auto_delete
            FROM files WHERE token = ?
        ''', (token,)).fetchone()
    if row:
        return {
            'filename': row[0], 'storage_path': row[1], 'pin_code': row[2],
            'download_limit': row[3], 'download_count': row[4],
            'uploader': row[5], 'auto_delete': bool(row[6])
        }
    return None

def increment_download_count_and_delete_if_needed(token):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            'SELECT download_count, download_limit, auto_delete, storage_path FROM files WHERE token = ?',
            (token,)).fetchone()
        if not row: return None, False, False

        new_count = row[0] + 1
        should_delete = (new_count >= row[1]) and bool(row[2])

        if should_delete:
            conn.execute('DELETE FROM files WHERE token = ?', (token,))
        else:
            conn.execute('UPDATE files SET download_count = ? WHERE token = ?', (new_count, token))

        return row[3], should_delete, bool(row[2])

def get_user_files(username):
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute('''
            SELECT token, filename, download_limit, download_count, auto_delete, created_at
            FROM files WHERE uploader = ? ORDER BY created_at DESC
        ''', (username,)).fetchall()
    return [{
        'token': r[0], 'filename': r[1], 'download_limit': r[2], 'download_count': r[3],
        'auto_delete': bool(r[4]), 'created_at': r[5], 'download_url': f"/f/{r[0]}", 'storage_path': ''
    } for r in rows]

def delete_file_by_token(token, uploader):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute('SELECT storage_path FROM files WHERE token = ? AND uploader = ?',
                           (token, uploader)).fetchone()
        if not row: return None
        conn.execute('DELETE FROM files WHERE token = ? AND uploader = ?', (token, uploader))
        return row[0]

def get_system_stats():
    with sqlite3.connect(DB_FILE) as conn:
        users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        files = conn.execute('SELECT COUNT(*) FROM files').fetchone()[0]
        downloads = conn.execute('SELECT SUM(download_count) FROM files').fetchone()[0] or 0
    return {'users': users, 'files': files, 'downloads': downloads}

def get_all_files_admin():
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            'SELECT token, filename, download_count, download_limit, uploader, created_at FROM files ORDER BY created_at DESC').fetchall()
    return [{
        'token': r[0], 'filename': r[1], 'download_count': r[2], 'download_limit': r[3],
        'uploader': r[4], 'created_at': r[5], 'download_url': f"/f/{r[0]}"
    } for r in rows]

def delete_user_full(username):
    if username == 'admin': return False
    with sqlite3.connect(DB_FILE) as conn:
        paths = conn.execute('SELECT storage_path FROM files WHERE uploader = ?', (username,)).fetchall()
        file_paths = [p[0] for p in paths]
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.execute('DELETE FROM files WHERE uploader = ?', (username,))
    return file_paths
