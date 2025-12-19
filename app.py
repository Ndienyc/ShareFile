import os
import re
import secrets
import base64
from io import BytesIO
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file
)
from functools import wraps
import qrcode
from database import (
    init_db, register_user, verify_user,
    save_file_info, get_file_by_token,
    increment_download_count_and_delete_if_needed,
    get_user_files, get_all_users, delete_file_by_token,
    get_system_stats, get_all_files_admin, delete_user_full
)

RU_EN = {'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e', 'ё': 'e', 'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y',
         'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u', 'ф': 'f',
         'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 'ы': 'y', 'э': 'e', 'ю': 'yu', 'я': 'ya'}

def safe_filename(filename):
    name, ext = os.path.splitext(filename)
    name = ''.join(RU_EN.get(c, c) for c in name.lower())
    name = re.sub(r'[^a-z0-9_. \-()\[\]]', '', name)
    name = re.sub(r'\s+', ' ', name).strip()
    return (name or "file") + ext

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ADMIN_USERNAME = 'admin'

# === Лимиты для обычных пользователей ===
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_DOWNLOADS = 5
MAX_FILES_PER_USER = 5

init_db()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('Войдите в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session or session['username'] != ADMIN_USERNAME:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    return redirect(url_for('dashboard' if 'username' in session else 'login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        if register_user(username, password):
            flash('Регистрация успешна!', 'success')
            return redirect(url_for('login'))
        flash('Пользователь уже существует', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if verify_user(request.form.get('username'), request.form.get('password')):
            session['username'] = request.form.get('username')
            return redirect(url_for('dashboard'))
        flash('Неверные данные', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    new_link = session.pop('new_link', None)
    qr_code_data = session.pop('qr_code_data', None)

    if request.method == 'POST':
        file = request.files.get('file')
        pin = request.form.get('pin_code')

        if not file or not pin:
            flash('Выберите файл и укажите PIN', 'danger')
            return redirect(url_for('dashboard'))

        # Проверка лимитов ТОЛЬКО для не-админов
        if session['username'] != ADMIN_USERNAME:
            if len(get_user_files(session['username'])) >= MAX_FILES_PER_USER:
                flash(f'Free-аккаунт: максимум {MAX_FILES_PER_USER} файлов', 'danger')
                return redirect(url_for('dashboard'))

            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            if file_size > MAX_FILE_SIZE:
                flash('Free-аккаунт: макс. размер файла 5 МБ', 'danger')
                return redirect(url_for('dashboard'))

        fname = safe_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        counter = 1
        while os.path.exists(path):
            path = os.path.join(app.config['UPLOAD_FOLDER'], f"{counter}_{fname}")
            counter += 1

        file.save(path)

        # Параметры загрузки
        if session['username'] == ADMIN_USERNAME:
            download_limit = int(request.form.get('download_limit', 5))
            auto_delete = 'auto_delete' in request.form
        else:
            download_limit = MAX_DOWNLOADS
            auto_delete = False

        token = save_file_info(
            session['username'], 
            fname, 
            path, 
            pin,
            download_limit,
            auto_delete
        )
        full_url = f"{request.url_root}f/{token}"

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(full_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_code_data_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

        session['new_link'] = full_url
        session['qr_code_data'] = qr_code_data_b64
        return redirect(url_for('dashboard'))

    files = get_user_files(session['username'])
    return render_template('dashboard.html', username=session['username'], files=files, new_link=new_link, qr_code_data=qr_code_data)

@app.route('/f/<token>', methods=['GET', 'POST'])
def download_file(token):
    info = get_file_by_token(token)
    if not info or info['download_count'] >= info['download_limit']:
        flash('Файл недоступен (удален или лимит исчерпан)', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if request.form.get('pin_code') == info['pin_code']:
            path, delete, _ = increment_download_count_and_delete_if_needed(token)
            if path and os.path.exists(path):
                with open(path, 'rb') as f:
                    data = BytesIO(f.read())
                if delete:
                    os.remove(path)
                return send_file(data, as_attachment=True, download_name=info['filename'])
        flash('Неверный PIN', 'danger')
    return render_template('enter_pin.html', token=token)

@app.route('/delete/<token>', methods=['POST'])
@login_required
def delete_file(token):
    info = get_file_by_token(token)
    if info and (info['uploader'] == session['username'] or session['username'] == ADMIN_USERNAME):
        path = delete_file_by_token(token, info['uploader'])
        if path and os.path.exists(path):
            os.remove(path)
        flash('Файл удален', 'success')

    if session['username'] == ADMIN_USERNAME and 'admin' in request.referrer:
        return redirect(url_for('admin_panel'))
    return redirect(url_for('dashboard'))

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html',
                           stats=get_system_stats(),
                           files=get_all_files_admin(),
                           users=get_all_users(),
                           username=session['username'])

@app.route('/admin/delete_user/<username>', methods=['POST'])
@admin_required
def delete_user_route(username):
    file_paths = delete_user_full(username)
    if file_paths is not False:
        for path in file_paths:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass
        flash(f'Пользователь {username} удален', 'success')
    else:
        flash('Нельзя удалить админа', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/qr/<token>')
@login_required
def generate_qr(token):
    info = get_file_by_token(token)
    if not info:
        return "File not found", 404

    if session['username'] != ADMIN_USERNAME and info['uploader'] != session['username']:
        return "Access denied", 403

    full_url = f"{request.url_root}f/{token}"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=8, border=2)
    qr.add_data(full_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    buffered.seek(0)
    return send_file(buffered, mimetype='image/png')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5051, debug=True)
