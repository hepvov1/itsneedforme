from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3, os
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DB_PATH = 'forum.db'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Ensure DB exists
def init_db():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            tag TEXT,
            content TEXT,
            created_at TEXT,
            username TEXT
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS chat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT,
            created_at TEXT,
            username TEXT
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            body TEXT,
            created_at TEXT,
            username TEXT
        )''')
        con.commit()


init_db()


# Helper functions
def get_user(username):
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if row:
            return dict(id=row[0], username=row[1], email=row[2], password=row[3], role=row[4])
        return None


def get_all_users():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute("SELECT username, role FROM users")
        return [dict(username=r[0], role=r[1]) for r in cur.fetchall()]


@app.route('/')
def home():
    if 'username' not in session:
        return redirect('/auth/login')
    users = get_all_users()
    return render_template('index.html', page='home', users=users)


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'username' not in session:
        return redirect('/auth/login')
    if request.method == 'POST':
        content = request.form['content']
        with sqlite3.connect(DB_PATH) as con:
            con.execute("INSERT INTO chat (content, created_at, username) VALUES (?, ?, ?)",
                        (content, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['username']))
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute("SELECT id, content, created_at, username FROM chat ORDER BY id DESC LIMIT 50")
        chat = [dict(id=r[0], content=r[1], created_at=r[2], username=r[3]) for r in cur.fetchall()]
    users = get_all_users()
    return render_template('index.html', page='chat', chat=chat, users=users)


@app.route('/data', methods=['GET', 'POST'])
def data():
    if 'username' not in session:
        return redirect('/auth/login')
    if request.method == 'POST':
        title = request.form['title']
        tag = request.form['tag']
        content = request.form['content']
        with sqlite3.connect(DB_PATH) as con:
            con.execute("INSERT INTO posts (title, tag, content, created_at, username) VALUES (?, ?, ?, ?, ?)",
                        (title, tag, content, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['username']))
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute("SELECT title, tag, content, created_at FROM posts ORDER BY id DESC")
        data = [dict(title=r[0], tag=r[1], content=r[2], created_at=r[3]) for r in cur.fetchall()]
    users = get_all_users()
    return render_template('index.html', page='data', data=data, users=users)


@app.route('/news', methods=['GET', 'POST'])
def news():
    if 'username' not in session:
        return redirect('/auth/login')
    # Re-validate role from database to handle session inconsistencies
    user = get_user(session['username'])
    if user:
        session['role'] = user['role']
        logger.debug(f"Re-validated user: {session['username']}, Role: {session['role']}")
    else:
        logger.error(f"User {session['username']} not found in database")
        session.clear()
        return redirect('/auth/login')

    logger.debug(f"User: {session.get('username')}, Role: {session.get('role')}")
    if request.method == 'POST' and session.get('role') == 'owner':
        title = request.form['title']
        body = request.form['body']
        logger.debug(f"Posting news: {title} by {session['username']}")
        with sqlite3.connect(DB_PATH) as con:
            con.execute("INSERT INTO news (title, body, created_at, username) VALUES (?, ?, ?, ?)",
                        (title, body, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), session['username']))
        return redirect('/news')
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute("SELECT title, body, created_at, username FROM news ORDER BY id DESC")
        news = [dict(title=r[0], body=r[1], created_at=r[2], username=r[3]) for r in cur.fetchall()]
    users = get_all_users()
    return render_template('index.html', page='news', news=news, users=users, role=session.get('role'))


@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and user['password'] == password:
            session.clear()  # Clear existing session to avoid stale data
            session['username'] = user['username']
            session['role'] = user['role']
            session['is_admin'] = user['role'] in ['owner', 'moder']
            logger.debug(f"Login successful: {username}, Role: {user['role']}, Session Role: {session['role']}")
            return redirect('/')
        logger.debug(f"Login failed: {username}")
    return render_template('index.html', page='login')


@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            cur.execute("INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                        (username, email, password, 'user'))
        return redirect('/auth/login')
    return render_template('index.html', page='register')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/profile/<username>')
def profile(username):
    if 'username' not in session:
        return redirect('/auth/login')
    profile = get_user(username)
    users = get_all_users()
    return render_template('index.html', page='profile', profile=profile, users=users)


@app.route('/grant/<username>', methods=['POST'])
def grant(username):
    if 'username' not in session or session.get('role') != 'owner':
        return redirect('/')
    role = request.args.get('role')
    if role not in ['moder', 'owner']:
        return redirect('/')
    with sqlite3.connect(DB_PATH) as con:
        con.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    return redirect(f'/profile/{username}')


@app.route('/revoke/<username>', methods=['POST'])
def revoke(username):
    if 'username' not in session or session.get('role') != 'owner':
        return redirect('/')
    with sqlite3.connect(DB_PATH) as con:
        con.execute("UPDATE users SET role='user' WHERE username=?", (username,))
    return redirect(f'/profile/{username}')


@app.route('/ban/<username>', methods=['POST'])
def ban(username):
    if 'username' not in session or session.get('role') != 'owner':
        return redirect('/')
    with sqlite3.connect(DB_PATH) as con:
        con.execute("DELETE FROM users WHERE username=?", (username,))
    return redirect('/')


@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role') != 'owner':
        return redirect('/')
    users = get_all_users()
    return render_template('index.html', page='admin', users=users)


if __name__ == '__main__':
    app.run(debug=True)
