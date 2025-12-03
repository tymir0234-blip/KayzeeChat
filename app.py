"""
AI Chat Backend for PythonAnywhere
Flask + SQLite
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import uuid
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'

DB_PATH = os.path.join(os.path.dirname(__file__), 'aichat.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT,
        avatar_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Auth tokens
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Friends
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        friend_id TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (friend_id) REFERENCES users(id),
        UNIQUE(user_id, friend_id)
    )''')
    
    # Groups
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        owner_id TEXT NOT NULL,
        ai_model TEXT DEFAULT 'openai/gpt-4o-mini',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )''')
    
    # Group members
    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(group_id, user_id)
    )''')
    
    # Messages
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        group_id TEXT NOT NULL,
        user_id TEXT,
        content TEXT NOT NULL,
        is_ai BOOLEAN DEFAULT 0,
        ai_model TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (group_id) REFERENCES groups(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

init_db()


# Auth decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        conn = get_db()
        user = conn.execute(
            'SELECT u.* FROM users u JOIN tokens t ON u.id = t.user_id WHERE t.token = ?',
            (token,)
        ).fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid token'}), 401
        
        request.user = dict(user)
        return f(*args, **kwargs)
    return decorated

# ============ AUTH ENDPOINTS ============

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip().lower()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    display_name = data.get('display_name', username)
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    conn = get_db()
    
    # Check if exists
    existing = conn.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'error': 'Username or email already exists'}), 400
    
    user_id = str(uuid.uuid4())
    password_hash = generate_password_hash(password)
    token = str(uuid.uuid4())
    
    conn.execute(
        'INSERT INTO users (id, username, email, password_hash, display_name) VALUES (?, ?, ?, ?, ?)',
        (user_id, username, email, password_hash, display_name)
    )
    conn.execute('INSERT INTO tokens (token, user_id) VALUES (?, ?)', (token, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({
        'token': token,
        'user': {
            'id': user_id,
            'username': username,
            'email': email,
            'display_name': display_name
        }
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    login_id = data.get('login', '').strip().lower()  # username or email
    password = data.get('password', '')
    
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        (login_id, login_id)
    ).fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = str(uuid.uuid4())
    conn.execute('INSERT INTO tokens (token, user_id) VALUES (?, ?)', (token, user['id']))
    conn.execute('UPDATE users SET last_seen = ? WHERE id = ?', (datetime.now(), user['id']))
    conn.commit()
    conn.close()
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'display_name': user['display_name']
        }
    })

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    conn = get_db()
    conn.execute('DELETE FROM tokens WHERE token = ?', (token,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/me', methods=['GET'])
@require_auth
def get_me():
    user = request.user
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'display_name': user['display_name'],
        'avatar_url': user['avatar_url']
    })


# ============ FRIENDS ENDPOINTS ============

@app.route('/api/users/search', methods=['GET'])
@require_auth
def search_users():
    query = request.args.get('q', '').strip().lower()
    if len(query) < 2:
        return jsonify([])
    
    conn = get_db()
    users = conn.execute(
        '''SELECT id, username, display_name, avatar_url FROM users 
           WHERE (username LIKE ? OR display_name LIKE ?) AND id != ?
           LIMIT 20''',
        (f'%{query}%', f'%{query}%', request.user['id'])
    ).fetchall()
    conn.close()
    
    return jsonify([dict(u) for u in users])

@app.route('/api/friends', methods=['GET'])
@require_auth
def get_friends():
    conn = get_db()
    friends = conn.execute(
        '''SELECT u.id, u.username, u.display_name, u.avatar_url, u.last_seen, f.status
           FROM friends f
           JOIN users u ON (f.friend_id = u.id AND f.user_id = ?) 
                        OR (f.user_id = u.id AND f.friend_id = ? AND f.status = 'accepted')
           WHERE f.user_id = ? OR (f.friend_id = ? AND f.status = 'accepted')''',
        (request.user['id'], request.user['id'], request.user['id'], request.user['id'])
    ).fetchall()
    conn.close()
    
    return jsonify([dict(f) for f in friends])

@app.route('/api/friends/requests', methods=['GET'])
@require_auth
def get_friend_requests():
    conn = get_db()
    requests_list = conn.execute(
        '''SELECT u.id, u.username, u.display_name, u.avatar_url, f.created_at
           FROM friends f
           JOIN users u ON f.user_id = u.id
           WHERE f.friend_id = ? AND f.status = 'pending' ''',
        (request.user['id'],)
    ).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in requests_list])

@app.route('/api/friends/add', methods=['POST'])
@require_auth
def add_friend():
    data = request.json
    friend_id = data.get('user_id')
    
    if not friend_id or friend_id == request.user['id']:
        return jsonify({'error': 'Invalid user'}), 400
    
    conn = get_db()
    
    # Check if already friends or pending
    existing = conn.execute(
        '''SELECT * FROM friends 
           WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)''',
        (request.user['id'], friend_id, friend_id, request.user['id'])
    ).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'error': 'Friend request already exists'}), 400
    
    conn.execute(
        'INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)',
        (request.user['id'], friend_id, 'pending')
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'status': 'pending'})

@app.route('/api/friends/accept', methods=['POST'])
@require_auth
def accept_friend():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    conn.execute(
        '''UPDATE friends SET status = 'accepted' 
           WHERE user_id = ? AND friend_id = ? AND status = 'pending' ''',
        (user_id, request.user['id'])
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/friends/reject', methods=['POST'])
@require_auth
def reject_friend():
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    conn.execute(
        'DELETE FROM friends WHERE user_id = ? AND friend_id = ? AND status = ?',
        (user_id, request.user['id'], 'pending')
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/friends/remove', methods=['POST'])
@require_auth
def remove_friend():
    data = request.json
    friend_id = data.get('user_id')
    
    conn = get_db()
    conn.execute(
        '''DELETE FROM friends 
           WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)''',
        (request.user['id'], friend_id, friend_id, request.user['id'])
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


# ============ GROUPS ENDPOINTS ============

@app.route('/api/groups', methods=['GET'])
@require_auth
def get_groups():
    conn = get_db()
    groups = conn.execute(
        '''SELECT g.*, 
           (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count,
           (SELECT content FROM messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message
           FROM groups g
           JOIN group_members gm ON g.id = gm.group_id
           WHERE gm.user_id = ?
           ORDER BY g.created_at DESC''',
        (request.user['id'],)
    ).fetchall()
    conn.close()
    
    return jsonify([dict(g) for g in groups])

@app.route('/api/groups', methods=['POST'])
@require_auth
def create_group():
    data = request.json
    name = data.get('name', '').strip()
    description = data.get('description', '')
    ai_model = data.get('ai_model', 'openai/gpt-4o-mini')
    member_ids = data.get('members', [])
    
    if not name:
        return jsonify({'error': 'Group name is required'}), 400
    
    group_id = str(uuid.uuid4())
    conn = get_db()
    
    conn.execute(
        'INSERT INTO groups (id, name, description, owner_id, ai_model) VALUES (?, ?, ?, ?, ?)',
        (group_id, name, description, request.user['id'], ai_model)
    )
    
    # Add owner as admin
    conn.execute(
        'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
        (group_id, request.user['id'], 'admin')
    )
    
    # Add other members
    for member_id in member_ids:
        if member_id != request.user['id']:
            conn.execute(
                'INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                (group_id, member_id, 'member')
            )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'id': group_id,
        'name': name,
        'description': description,
        'ai_model': ai_model
    })

@app.route('/api/groups/<group_id>', methods=['GET'])
@require_auth
def get_group(group_id):
    conn = get_db()
    
    # Check membership
    member = conn.execute(
        'SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    ).fetchone()
    
    if not member:
        conn.close()
        return jsonify({'error': 'Not a member of this group'}), 403
    
    group = conn.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    members = conn.execute(
        '''SELECT u.id, u.username, u.display_name, u.avatar_url, gm.role
           FROM group_members gm
           JOIN users u ON gm.user_id = u.id
           WHERE gm.group_id = ?''',
        (group_id,)
    ).fetchall()
    
    conn.close()
    
    return jsonify({
        **dict(group),
        'members': [dict(m) for m in members]
    })

@app.route('/api/groups/<group_id>', methods=['PUT'])
@require_auth
def update_group(group_id):
    data = request.json
    conn = get_db()
    
    # Check if admin
    member = conn.execute(
        'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    ).fetchone()
    
    if not member or member['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403
    
    updates = []
    params = []
    
    if 'name' in data:
        updates.append('name = ?')
        params.append(data['name'])
    if 'description' in data:
        updates.append('description = ?')
        params.append(data['description'])
    if 'ai_model' in data:
        updates.append('ai_model = ?')
        params.append(data['ai_model'])
    
    if updates:
        params.append(group_id)
        conn.execute(f'UPDATE groups SET {", ".join(updates)} WHERE id = ?', params)
        conn.commit()
    
    conn.close()
    return jsonify({'success': True})

@app.route('/api/groups/<group_id>/members', methods=['POST'])
@require_auth
def add_group_member(group_id):
    data = request.json
    user_id = data.get('user_id')
    
    conn = get_db()
    
    # Check if admin
    member = conn.execute(
        'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    ).fetchone()
    
    if not member or member['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not authorized'}), 403
    
    conn.execute(
        'INSERT OR IGNORE INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
        (group_id, user_id, 'member')
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/groups/<group_id>/leave', methods=['POST'])
@require_auth
def leave_group(group_id):
    conn = get_db()
    conn.execute(
        'DELETE FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})


# ============ MESSAGES ENDPOINTS ============

@app.route('/api/groups/<group_id>/messages', methods=['GET'])
@require_auth
def get_messages(group_id):
    conn = get_db()
    
    # Check membership
    member = conn.execute(
        'SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    ).fetchone()
    
    if not member:
        conn.close()
        return jsonify({'error': 'Not a member'}), 403
    
    limit = request.args.get('limit', 50, type=int)
    before = request.args.get('before')
    
    if before:
        messages = conn.execute(
            '''SELECT m.*, u.username, u.display_name, u.avatar_url
               FROM messages m
               LEFT JOIN users u ON m.user_id = u.id
               WHERE m.group_id = ? AND m.created_at < ?
               ORDER BY m.created_at DESC
               LIMIT ?''',
            (group_id, before, limit)
        ).fetchall()
    else:
        messages = conn.execute(
            '''SELECT m.*, u.username, u.display_name, u.avatar_url
               FROM messages m
               LEFT JOIN users u ON m.user_id = u.id
               WHERE m.group_id = ?
               ORDER BY m.created_at DESC
               LIMIT ?''',
            (group_id, limit)
        ).fetchall()
    
    conn.close()
    
    return jsonify([dict(m) for m in reversed(messages)])

@app.route('/api/groups/<group_id>/messages', methods=['POST'])
@require_auth
def send_message(group_id):
    data = request.json
    content = data.get('content', '').strip()
    
    if not content:
        return jsonify({'error': 'Message content is required'}), 400
    
    conn = get_db()
    
    # Check membership
    member = conn.execute(
        'SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    ).fetchone()
    
    if not member:
        conn.close()
        return jsonify({'error': 'Not a member'}), 403
    
    message_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    
    conn.execute(
        'INSERT INTO messages (id, group_id, user_id, content, is_ai, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (message_id, group_id, request.user['id'], content, False, now)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'id': message_id,
        'group_id': group_id,
        'user_id': request.user['id'],
        'username': request.user['username'],
        'display_name': request.user['display_name'],
        'content': content,
        'is_ai': False,
        'created_at': now
    })

@app.route('/api/groups/<group_id>/ai', methods=['POST'])
@require_auth
def send_ai_message(group_id):
    """Save AI response to group chat"""
    data = request.json
    content = data.get('content', '').strip()
    ai_model = data.get('ai_model', '')
    
    if not content:
        return jsonify({'error': 'Message content is required'}), 400
    
    conn = get_db()
    
    # Check membership
    member = conn.execute(
        'SELECT * FROM group_members WHERE group_id = ? AND user_id = ?',
        (group_id, request.user['id'])
    ).fetchone()
    
    if not member:
        conn.close()
        return jsonify({'error': 'Not a member'}), 403
    
    message_id = str(uuid.uuid4())
    now = datetime.now().isoformat()
    
    conn.execute(
        'INSERT INTO messages (id, group_id, user_id, content, is_ai, ai_model, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (message_id, group_id, None, content, True, ai_model, now)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'id': message_id,
        'group_id': group_id,
        'content': content,
        'is_ai': True,
        'ai_model': ai_model,
        'created_at': now
    })

# ============ HEALTH CHECK ============

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'})

@app.route('/')
def index():
    return jsonify({
        'name': 'AI Chat API',
        'version': '1.0.0',
        'endpoints': [
            'POST /api/register',
            'POST /api/login',
            'GET /api/me',
            'GET /api/users/search?q=',
            'GET /api/friends',
            'GET /api/friends/requests',
            'POST /api/friends/add',
            'POST /api/friends/accept',
            'POST /api/friends/reject',
            'GET /api/groups',
            'POST /api/groups',
            'GET /api/groups/<id>',
            'GET /api/groups/<id>/messages',
            'POST /api/groups/<id>/messages',
            'POST /api/groups/<id>/ai'
        ]
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
