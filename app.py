import os
import re
import secrets
import mimetypes
from io import BytesIO
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file
)
from functools import wraps
from werkzeug.utils import secure_filename

from database import (
    init_db, register_user, verify_user,
    save_file_info, get_file_by_token,
    increment_download_count_and_delete_if_needed,
    get_user_files, get_all_users, delete_file_by_token
)

RU_EN = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd',
    'е': 'e', 'ё': 'e', 'ж': 'zh', 'з': 'z', 'и': 'i',
    'й': 'y', 'к': 'k', 'л': 'l', 'м': 'm', 'н': 'n',
    'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't',
    'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch',
    'ш': 'sh', 'щ': 'shch', 'ы': 'y', 'э': 'e', 'ю': 'yu', 'я': 'ya',
    'А': 'A', 'Б': 'B', 'В': 'V', 'Г': 'G', 'Д': 'D',
    'Е': 'E', 'Ё': 'E', 'Ж': 'Zh', 'З': 'Z', 'И': 'I',
    'Й': 'Y', 'К': 'K', 'Л': 'L', 'М': 'M', 'Н': 'N',
    'О': 'O', 'П': 'P', 'Р': 'R', 'С': 'S', 'Т': 'T',
    'У': 'U', 'Ф': 'F', 'Х': 'Kh', 'Ц': 'Ts', 'Ч': 'Ch',
    'Ш': 'Sh', 'Щ': 'Shch', 'Ы': 'Y', 'Э': 'E', 'Ю': 'Yu', 'Я': 'Ya'
}

def safe_filename(filename):
    name, ext = os.path.splitext(filename)
    for ru, en in RU_EN.items():
        name = name.replace(ru, en)
    name = re.sub(r'[^a-zA-Z0-9_. -]', '', name)
    name = re.sub(r'\s+', '_', name.strip())
    name = re.sub(r'_+', '_', name)
    if not name:
        name = "file"
    ext = re.sub(r'[^a-zA-Z0-9.]', '', ext)
    if ext and not ext.startswith('.'):
        ext = '.' + ext
    return name + ext

# === Flask app ===
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ADMIN_USERNAME = 'admin'

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
        if 'username' not in session:
            flash('Войдите в систему', 'warning')
            return redirect(url_for('login'))
        if session['username'] != ADMIN_USERNAME:
            flash('Только для администраторов', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    return redirect(url_for('dashboard' if 'username' in session else 'login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        if not username or not password:
            flash('Заполните все поля', 'danger')
        elif password != request.form.get('confirm_password'):
            flash('Пароли не совпадают', 'danger')
        elif register_user(username, password):
            flash('Регистрация успешна!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Пользователь уже существует', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        if verify_user(username, password):
            session['username'] = username
            flash('Вход выполнен!', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы вышли', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        file = request.files.get('file')
        pin_code = request.form.get('pin_code', '').strip()
        try:
            download_limit = int(request.form.get('download_limit', 1))
        except (ValueError, TypeError):
            download_limit = 1
        auto_delete = 'auto_delete' in request.form

        if not file or not file.filename:
            flash('Выберите файл', 'danger')
        elif not pin_code or len(pin_code) < 4:
            flash('PIN-код должен быть минимум 4 символа', 'danger')
        elif download_limit < 1 or download_limit > 100:
            flash('Лимит: от 1 до 100 скачиваний', 'danger')
        else:
            filename = safe_filename(file.filename)
            storage_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            counter = 1
            while os.path.exists(storage_path):
                name, ext = os.path.splitext(filename)
                storage_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{name}_{counter}{ext}")
                counter += 1

            file.save(storage_path)
            if not os.path.isfile(storage_path):
                flash('Ошибка: файл не сохранён на диск!', 'danger')
                return redirect(url_for('dashboard'))

            token = save_file_info(
                uploader=session['username'],
                filename=filename,
                storage_path=storage_path,
                pin_code=pin_code,
                download_limit=download_limit,
                auto_delete=auto_delete
            )
            full_url = request.url_root + 'f/' + token
            flash(f'Файл загружен! Ссылка: {full_url}', 'success')
            return redirect(url_for('dashboard'))

    files = get_user_files(session['username'])
    return render_template('dashboard.html', username=session['username'], files=files)

@app.route('/f/<token>', methods=['GET', 'POST'])
def download_file(token):
    file_info = get_file_by_token(token)
    if not file_info:
        flash('Ссылка недействительна', 'danger')
        return redirect(url_for('login'))
    if file_info['download_count'] >= file_info['download_limit']:
        flash('Лимит скачиваний исчерпан', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form.get('pin_code', '').strip() == file_info['pin_code']:
            storage_path, should_delete, auto_delete = increment_download_count_and_delete_if_needed(token)

            if not storage_path or not os.path.isfile(storage_path):
                flash('Файл был удалён или повреждён', 'danger')
                return redirect(url_for('dashboard'))

            try:
                with open(storage_path, 'rb') as f:
                    file_data = BytesIO(f.read())
            except Exception as e:
                flash('Ошибка чтения файла', 'danger')
                return redirect(url_for('dashboard'))

            if should_delete:
                try:
                    os.remove(storage_path)
                    print(f"✅ Файл удалён с диска: {storage_path}")
                except Exception as e:
                    print(f"❌ Ошибка удаления файла: {e}")

            mimetype = mimetypes.guess_type(file_info['filename'])[0] or 'application/octet-stream'

            return send_file(
                file_data,
                as_attachment=True,
                download_name=file_info['filename'],
                mimetype=mimetype
            )

        flash('Неверный PIN-код', 'danger')
    return render_template('enter_pin.html', token=token)

@app.route('/delete/<token>', methods=['POST'])
@login_required
def delete_file(token):
    storage_path = delete_file_by_token(token, session['username'])
    if storage_path:
        try:
            if os.path.isfile(storage_path):
                os.remove(storage_path)
                print(f"✅ Файл удалён пользователем: {storage_path}")
        except Exception as e:
            print(f"❌ Ошибка удаления: {e}")
        flash('Файл удалён', 'info')
    else:
        flash('Файл не найден или у вас нет прав', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', username=session['username'], users=get_all_users())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)