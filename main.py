import os
import sqlite3
import json
import datetime
import tempfile
import time
import io
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
from PIL import Image

try:
    with open('api_key.txt', 'r', encoding='utf-8') as f:
        API_KEY = f.read().strip()
except:
    API_KEY = ""

genai.configure(api_key=API_KEY)

app = Flask(__name__)
app.secret_key = 'ht_pro_ai_secret_key_2025'
DB_NAME = "chat.db"
ADMIN_USER = "admin"
ADMIN_PASS = "hoathangg"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    fullname TEXT,
                    email TEXT,
                    ai_settings TEXT DEFAULT "{}", 
                    learned_style TEXT DEFAULT "",
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER,
                    role TEXT,
                    content TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
                )''')
    conn.commit()
    conn.close()

init_db()

def get_system_prompt(user_id):
    base_prompt = "Bạn là trợ lý AI."
    try:
        if os.path.exists('prompt.txt'):
            with open('prompt.txt', 'r', encoding='utf-8') as f:
                content = f.read()
                if 'SYSTEM_INSTRUCTION=' in content:
                    base_prompt = content.split('SYSTEM_INSTRUCTION=', 1)[1].split('\n[', 1)[0].strip()
    except: pass

    settings = {}
    learned = ""
    conn = get_db_connection()
    user = conn.execute('SELECT ai_settings, learned_style FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        try: settings = json.loads(user['ai_settings']) if user['ai_settings'] else {}
        except: settings = {}
        learned = user['learned_style'] if user['learned_style'] else ""

    custom_instruction = settings.get('custom_instruction', '')
    
    full_prompt = f"""
    {base_prompt}
    [GHI NHỚ VỀ USER]: {learned}
    [YÊU CẦU CỦA USER]: {custom_instruction}
    """
    return full_prompt

@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('chat_interface'))
    return render_template('welcome.html')

@app.route('/auth')
def auth():
    if 'user_id' in session: return redirect(url_for('chat_interface'))
    return render_template('auth.html')

@app.route('/app')
def chat_interface():
    if 'user_id' not in session: return redirect(url_for('auth'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    if not user:
        session.clear()
        return redirect(url_for('auth'))
    try: ai_settings = json.loads(user['ai_settings']) if user['ai_settings'] else {}
    except: ai_settings = {}
    return render_template('index.html', user=user, settings=ai_settings)

@app.route('/admin')
def admin_login_page():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/auth', methods=['POST'])
def admin_auth():
    data = request.json
    if data['username'] == ADMIN_USER and data['password'] == ADMIN_PASS:
        session['is_admin'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Sai thông tin quản trị viên'})

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('admin_login_page'))
    conn = get_db_connection()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_convs = conn.execute('SELECT COUNT(*) FROM conversations').fetchone()[0]
    total_msgs = conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
    users = conn.execute('SELECT id, username, fullname, email, created_at FROM users ORDER BY id DESC').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', stats={'users': total_users, 'convs': total_convs, 'msgs': total_msgs}, users=users)

@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if not session.get('is_admin'): return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    user_id = request.json.get('user_id')
    conn = get_db_connection()
    conn.execute('DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id = ?)', (user_id,))
    conn.execute('DELETE FROM conversations WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/logout')
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login_page'))

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], data['password']):
        session['user_id'] = user['id']
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Sai tài khoản hoặc mật khẩu'})

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    if data['password'] != data['confirm_password']:
        return jsonify({'success': False, 'message': 'Mật khẩu xác nhận không khớp'})
    hashed = generate_password_hash(data['password'])
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, fullname, email) VALUES (?, ?, ?, ?)', 
                     (data['username'], hashed, data['fullname'], data['email']))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Tên đăng nhập đã tồn tại'})
    finally: conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    data = request.json
    conn = get_db_connection()
    conn.execute('UPDATE users SET fullname = ?, email = ? WHERE id = ?', (data['fullname'], data['email'], session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/change_password', methods=['POST'])
def change_password():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    data = request.json
    conn = get_db_connection()
    user = conn.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not check_password_hash(user['password'], data['current_password']): pass 
    new_hashed = generate_password_hash(data['new_password'])
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (new_hashed, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/save_ai_settings', methods=['POST'])
def save_ai_settings():
    if 'user_id' not in session: return jsonify({'success': False}), 401
    settings_json = json.dumps({'custom_instruction': request.json.get('custom_instruction')})
    conn = get_db_connection()
    conn.execute('UPDATE users SET ai_settings = ? WHERE id = ?', (settings_json, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/conversations')
def get_conversations():
    if 'user_id' not in session: return jsonify([])
    conn = get_db_connection()
    convs = conn.execute('SELECT * FROM conversations WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(ix) for ix in convs])

@app.route('/api/messages/<int:conv_id>')
def get_messages(conv_id):
    if 'user_id' not in session: return jsonify([])
    conn = get_db_connection()
    msgs = conn.execute('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id ASC', (conv_id,)).fetchall()
    conn.close()
    return jsonify([dict(m) for m in msgs])

@app.route('/api/chat_stream', methods=['POST'])
def chat_stream():
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    
    user_input = request.form.get('message')
    conv_id = request.form.get('conversation_id')
    model_type = request.form.get('model', 'fast')
    model_name = 'gemini-2.5-pro' if model_type == 'super' else 'gemini-2.5-flash'
    file_obj = request.files.get('image')
    
    media_content = None
    if file_obj:
        mime = file_obj.mimetype
        if mime.startswith('image/'):
            try: 
                file_data = file_obj.read()
                image_stream = io.BytesIO(file_data)
                media_content = Image.open(image_stream)
            except: pass
        else:
            try:
                suffix = "." + file_obj.filename.split('.')[-1] if '.' in file_obj.filename else ""
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    file_obj.save(tmp.name)
                    tmp_path = tmp.name
                uploaded_file = genai.upload_file(tmp_path, mime_type=mime)
                while uploaded_file.state.name == "PROCESSING":
                    time.sleep(1)
                    uploaded_file = genai.get_file(uploaded_file.name)
                media_content = uploaded_file
                os.remove(tmp_path)
            except: pass

    conn = get_db_connection()
    if not conv_id or conv_id == 'null' or conv_id == 'undefined':
        title = user_input[:30] if user_input else ("Tài liệu mới" if media_content else "Hội thoại mới")
        cursor = conn.execute('INSERT INTO conversations (user_id, title) VALUES (?, ?)', (session['user_id'], title))
        conv_id = cursor.lastrowid
        conn.commit()
    
    old_messages = conn.execute('SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id ASC', (conv_id,)).fetchall()
    gemini_history = [{'role': ('user' if m['role']=='user' else 'model'), 'parts': [m['content']]} for m in old_messages]
    
    current_parts = []
    if user_input: current_parts.append(user_input)
    if media_content: current_parts.append(media_content)
    
    if not current_parts: return jsonify({'error': 'Empty'}), 400

    gemini_history.append({'role': 'user', 'parts': current_parts})
    
    save_content = user_input if user_input else ""
    if media_content:
        if isinstance(media_content, Image.Image): save_content += " [Đã gửi 1 hình ảnh]"
        else: save_content += f" [Đã gửi tài liệu: {file_obj.filename}]"
            
    conn.execute('INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)', (conv_id, 'user', save_content))
    conn.commit()
    conn.close()

    system_instruction = get_system_prompt(session['user_id'])
    if model_type == 'super':
        system_instruction += """\nBạn đang ở chế độ Siêu Trí Tuệ. Hãy suy nghĩ kỹ trong thẻ <think>Nội dung suy nghĩ...</think> trước khi đưa ra câu trả lời cuối cùng."""

    def generate():
        model = genai.GenerativeModel(model_name=model_name, system_instruction=system_instruction)
        try:
            response = model.generate_content(gemini_history, stream=True)
            for chunk in response:
                if chunk.text: yield chunk.text
            
            final_conn = get_db_connection()
            full_text = response.text if hasattr(response, 'text') else "".join([c.text for c in response])
            final_conn.execute('INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)', (conv_id, 'model', full_text))
            final_conn.commit()
            final_conn.close()
        except Exception as e: yield f"Lỗi: {str(e)}"

    return Response(stream_with_context(generate()), mimetype='text/plain', headers={'X-Conversation-ID': str(conv_id)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)