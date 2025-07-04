import zipfile
import uuid
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, flash, g, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from opentele.exception import OpenTeleException
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PasswordHashInvalidError, FloodWaitError
import re
import os
import asyncio
import tempfile
from opentele.td import TDesktop
from opentele.api import UseCurrentSession
import logging
import threading
from datetime import datetime
from functools import wraps
import phonenumbers
from phonenumbers import geocoder
import pytz
import urllib.parse
import random

# --- Basic Setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
logging.basicConfig(level=logging.INFO)

# --- Constants ---
SESSION_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sessions')
os.makedirs(SESSION_DIR, exist_ok=True)
API_ID = '19842526'
API_HASH = '1ddb30b32ff81188a4356450ffff3035'
DATABASE = 'database.db'
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')


# --- Database Setup ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        # Use the schema from the file to initialize
        with open('schema.sql', 'r') as f:
            schema = f.read()
        db = get_db()
        db.cursor().executescript(schema)
        db.commit()


# --- Helper Functions & Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('此页面需要登录才能访问', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def parse_proxy_url(proxy_url):
    if not proxy_url: return None
    try:
        parsed = urllib.parse.urlparse(proxy_url)
        return (parsed.scheme, parsed.hostname, parsed.port, True, parsed.username, parsed.password)
    except Exception:
        return None


def get_user_proxy(user_id):
    db = get_db()
    proxy_rows = db.execute('SELECT proxy_string FROM proxies WHERE user_id = ?', (user_id,)).fetchall()
    if not proxy_rows: return None
    return parse_proxy_url(random.choice(proxy_rows)['proxy_string'])


def beijing_time_filter(utc_dt):
    if not isinstance(utc_dt, datetime):
        try:
            utc_dt = datetime.strptime(str(utc_dt).split('.')[0], '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return utc_dt
    return utc_dt.strftime('%Y-%m-%d %H:%M:%S')


app.jinja_env.filters['beijing_time'] = beijing_time_filter


def run_async_in_thread(async_func):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(async_func)
    finally:
        loop.close()


# --- Core Telegram Logic ---
async def fetch_telegram_data(session_string, proxy=None):
    # This function remains largely the same, retrieves codes.
    async with TelegramClient(StringSession(session_string), API_ID, API_HASH, proxy=proxy) as client:
        me = await client.get_me()
        codes = []
        entity = await client.get_entity(777000)
        async for message in client.iter_messages(entity, limit=20):
            message_text = message.raw_text or ""
            if "Login code" in message_text or "登录代码" in message_text:
                if code_match := re.search(r'\b\d{5}\b', message_text):
                    codes.append({'code': code_match.group(0),
                                  'time': message.date.astimezone(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')})
        return {'codes': codes, 'phone': f"+{me.phone}" if me.phone else "N/A", 'chat_id': me.id, 'error': None}


async def get_session_details(client):
    me = await client.get_me()
    if not me: return None
    phone = f"+{me.phone}" if me.phone else None
    try:
        country = geocoder.country_name_for_number(phonenumbers.parse(phone), 'en') if phone else "Unknown"
    except Exception:
        country = "Unknown"
    return {"session_string": StringSession.save(client.session), "chat_id": str(me.id), "phone": phone,
            "country": country}


def store_session_in_db(details, user_id):
    db = get_db()
    new_uuid = str(uuid.uuid4())
    db.execute(
        'INSERT INTO sessions (user_id, uuid, name, session_string, chat_id, phone, country, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (user_id, new_uuid, f"Account {details['phone']}", details['session_string'], details['chat_id'],
         details['phone'], details['country'], datetime.now(SHANGHAI_TZ))
    )
    db.commit()


# --- Background Processing ---
def background_task_wrapper(app_context, func, user_id, *args):
    with app_context:
        try:
            details = run_async_in_thread(func(user_id, *args))
            if details:
                store_session_in_db(details, user_id)
        except Exception as e:
            logging.error(f"Error in background task {func.__name__}: {e}")
        finally:
            for arg in args:
                if isinstance(arg, str) and os.path.exists(arg) and ('.session' in arg or '.zip' in arg):
                    os.remove(arg)


async def process_session_file(user_id, file_path):
    proxy = get_user_proxy(user_id)
    client = TelegramClient(file_path, API_ID, API_HASH, proxy=proxy)
    await client.connect()
    if not await client.is_user_authorized(): raise Exception("Session file invalid/expired.")
    return await get_session_details(client)


async def process_tdata_zip(user_id, zip_path):
    proxy = get_user_proxy(user_id)
    temp_extract_dir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(temp_extract_dir)
        tdata_path = os.path.join(temp_extract_dir, 'tdata')
        if not os.path.isdir(tdata_path): raise Exception("ZIP must contain a 'tdata' folder.")
        session_name = f"tdata_{uuid.uuid4()}.session"
        client = await TDesktop(tdata_path, api_id=API_ID).ToTelethon(session=session_name, flag=UseCurrentSession,
                                                                      proxy=proxy)
        await client.connect()
        details = await get_session_details(client)
        await client.disconnect()
        if os.path.exists(session_name): os.remove(session_name)
        return details
    finally:
        import shutil
        shutil.rmtree(temp_extract_dir)


# --- Routes ---

# Guest-accessible routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('manage_sessions'))
    return render_template('index.html')


@app.route('/get_code', methods=['GET', 'POST'])
def get_code():
    result = None
    if request.method == 'POST':
        user_uuid = request.form.get('uuid')
        if not user_uuid:
            flash('请输入有效的 UUID', 'error')
            return render_template('index.html')
        db = get_db()
        session_data = db.execute('SELECT * FROM sessions WHERE uuid = ?', (user_uuid,)).fetchone()
        if session_data:
            proxy = get_user_proxy(session_data['user_id']) if session_data['user_id'] else None
            try:
                result = run_async_in_thread(fetch_telegram_data(session_data['session_string'], proxy))
            except Exception as e:
                result = {'error': f'运行时错误: {e}'}
        else:
            result = {'error': '未找到具有此UUID的会话'}
    return render_template('index.html', result=result, uuid=request.form.get('uuid', ''))


# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True
            flash('登录成功！', 'success')
            return redirect(url_for('manage_sessions'))
        else:
            flash('无效的用户名或密码', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Standard registration logic
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('用户名已存在', 'error')
        else:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                       (username, generate_password_hash(password)))
            db.commit()
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功登出', 'success')
    return redirect(url_for('login'))


# --- User-only routes (login required) ---
@app.route('/manage_sessions')
@login_required
def manage_sessions():
    db = get_db()
    user_sessions = db.execute('SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC',
                               (session['user_id'],)).fetchall()
    return render_template('manage_sessions.html', sessions=user_sessions)


@app.route('/edit_session/<int:session_id>', methods=['GET', 'POST'])
@login_required
def edit_session(session_id):
    # Standard session editing logic
    db = get_db()
    s = db.execute('SELECT * FROM sessions WHERE id = ? AND user_id = ?', (session_id, session['user_id'])).fetchone()
    if not s:
        flash('未找到会话或无权操作', 'error')
        return redirect(url_for('manage_sessions'))
    if request.method == 'POST':
        new_name = request.form.get('name')
        db.execute('UPDATE sessions SET name = ? WHERE id = ?', (new_name, session_id))
        db.commit()
        flash('会话名称已更新', 'success')
        return redirect(url_for('manage_sessions'))
    return render_template('edit_session.html', session=s)


@app.route('/bulk_actions', methods=['POST'])
@login_required
def bulk_actions():
    # Standard bulk deletion logic
    db = get_db()
    session_ids = request.form.getlist('session_ids')
    action = request.form.get('action')
    if not session_ids:
        flash('请至少选择一个会话', 'warning')
        return redirect(url_for('manage_sessions'))
    if action == 'delete':
        placeholders = ','.join('?' for _ in session_ids)
        query = f'DELETE FROM sessions WHERE id IN ({placeholders}) AND user_id = ?'
        params = session_ids + [session['user_id']]
        db.execute(query, params)
        db.commit()
        flash(f'{len(session_ids)} 个会话已删除', 'success')
    return redirect(url_for('manage_sessions'))


@app.route('/telegram_login', methods=['GET'])
@login_required
def telegram_login():
    return render_template('telegram_login.html')


@app.route('/api/telegram/send_code', methods=['POST'])
@login_required
def api_telegram_send_code():
    proxy = get_user_proxy(session['user_id'])

    async def task():
        phone = request.form.get('phone')
        session_path = os.path.join(SESSION_DIR, f"{phone}_{uuid.uuid4()}.session")
        session['login_session_path'] = session_path
        client = TelegramClient(session_path, API_ID, API_HASH, proxy=proxy)
        try:
            await client.connect()
            await client.send_code_request(phone)
            await client.disconnect()
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": f"发送验证码失败: {e}"})

    return run_async_in_thread(task())


@app.route('/api/telegram/login', methods=['POST'])
@login_required
def api_telegram_login():
    proxy = get_user_proxy(session['user_id'])

    async def task():
        session_path = session.get('login_session_path')
        code, password = request.form.get('code'), request.form.get('password')
        client = TelegramClient(session_path, API_ID, API_HASH, proxy=proxy)
        try:
            await client.connect()
            try:
                await client.sign_in(code=code)
            except SessionPasswordNeededError:
                if not password: return jsonify({"success": False, "error": "password_needed"})
                await client.sign_in(password=password)
            details = await get_session_details(client)
            if details:
                store_session_in_db(details, session['user_id'])
                return jsonify({"success": True, "redirect": url_for('manage_sessions')})
            return jsonify({"success": False, "error": "无法获取账号信息"})
        except Exception as e:
            return jsonify({"success": False, "error": f"登录时发生未知错误: {e}"})
        finally:
            if client.is_connected(): await client.disconnect()
            if os.path.exists(session_path): os.remove(session_path)
            session.pop('login_session_path', None)

    return run_async_in_thread(task())


# File Conversion Routes
@app.route('/session_to_string', methods=['GET', 'POST'])
@login_required
def session_to_string():
    if request.method == 'POST':
        files = request.files.getlist('files')
        if not any(f.filename for f in files):
            flash('请选择文件', 'error')
            return redirect(request.url)
        for f in files:
            if f.filename:
                temp_f_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}.session")
                f.save(temp_f_path)
                threading.Thread(target=background_task_wrapper, args=(
                app.app_context(), process_session_file, session['user_id'], temp_f_path)).start()
        flash('文件上传成功，正在后台处理中...', 'success')
        return redirect(url_for('manage_sessions'))
    return render_template('convert_form.html', title='转换 .session 文件', form_url=url_for('session_to_string'),
                           accept_type='.session')


@app.route('/upload_tdata', methods=['GET', 'POST'])
@login_required
def upload_tdata():
    if request.method == 'POST':
        files = request.files.getlist('files')
        if not any(f.filename for f in files):
            flash('请选择文件', 'error')
            return redirect(request.url)
        for f in files:
            if f.filename:
                temp_f_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}.zip")
                f.save(temp_f_path)
                threading.Thread(target=background_task_wrapper,
                                 args=(app.app_context(), process_tdata_zip, session['user_id'], temp_f_path)).start()
        flash('文件上传成功，正在后台处理中...', 'success')
        return redirect(url_for('manage_sessions'))
    return render_template('convert_form.html', title='转换 TData 文件夹', form_url=url_for('upload_tdata'),
                           accept_type='.zip')


# Proxy Management Routes
@app.route('/manage_proxy', methods=['GET'])
@login_required
def manage_proxy():
    db = get_db()
    proxies = db.execute('SELECT id, proxy_string FROM proxies WHERE user_id = ? ORDER BY id DESC',
                         (session['user_id'],)).fetchall()
    return render_template('manage_proxy.html', proxies=proxies)


@app.route('/add_proxy', methods=['POST'])
@login_required
def add_proxy():
    proxy_string = request.form.get('proxy', '').strip()
    if proxy_string:
        db = get_db()
        db.execute('INSERT INTO proxies (user_id, proxy_string) VALUES (?, ?)', (session['user_id'], proxy_string))
        db.commit()
        flash('代理已成功添加', 'success')
    else:
        flash('代理地址不能为空', 'error')
    return redirect(url_for('manage_proxy'))


@app.route('/delete_proxy/<int:proxy_id>', methods=['POST'])
@login_required
def delete_proxy(proxy_id):
    db = get_db()
    proxy = db.execute('SELECT id FROM proxies WHERE id = ? AND user_id = ?', (proxy_id, session['user_id'])).fetchone()
    if proxy:
        db.execute('DELETE FROM proxies WHERE id = ?', (proxy_id,))
        db.commit()
        flash('代理已删除', 'success')
    else:
        flash('未找到代理或无权操作', 'error')
    return redirect(url_for('manage_proxy'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5555)
