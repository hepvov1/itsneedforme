from flask import Flask, render_template, request, redirect, session, g, abort
import sqlite3, os

app = Flask(__name__)
app.secret_key = 'secret'
DB_NAME = 'deadclouds.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_NAME)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def home():
    return render_template('index.html', page='home', users=get_users())

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    db = get_db()
    if request.method == 'POST':
        db.execute('INSERT INTO chat (username, content) VALUES (?, ?)', (session['username'], request.form['content']))
        db.commit()
    chat = db.execute('SELECT username, content, created_at FROM chat ORDER BY id DESC').fetchall()
    return render_template('index.html', page='chat', chat=chat, users=get_users())

@app.route('/data', methods=['GET', 'POST'])
def data():
    db = get_db()
    if request.method == 'POST':
        db.execute('INSERT INTO data (title, tag, content, username) VALUES (?, ?, ?, ?)', (request.form['title'], request.form['tag'], request.form['content'], session['username']))
        db.commit()
    data = db.execute('SELECT id, title, tag, content, created_at, username FROM data ORDER BY id DESC').fetchall()
    return render_template('index.html', page='data', data=data, users=get_users())

@app.route('/news', methods=['GET', 'POST'])
def news():
    db = get_db()
    if request.method == 'POST' and session.get('role') == 'owner':
        db.execute('INSERT INTO news (title, body, username) VALUES (?, ?, ?)', (request.form['title'], request.form['body'], session['username']))
        db.commit()
    news = db.execute('SELECT title, body, username, created_at FROM news ORDER BY id DESC').fetchall()
    return render_template('index.html', page='news', news=news, users=get_users())

@app.route('/admin')
def admin():
    if session.get('role') != 'owner': return redirect('/')
    return render_template('index.html', page='admin', users=get_users())

@app.route('/grant/<username>', methods=['POST'])
def grant(username):
    if session.get('role') != 'owner': return redirect('/')
    role = request.args.get('role')
    db = get_db()
    db.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    db.commit()
    return redirect('/admin')

@app.route('/revoke/<username>', methods=['POST'])
def revoke(username):
    if session.get('role') != 'owner': return redirect('/')
    db = get_db()
    db.execute('UPDATE users SET role = "user" WHERE username = ?', (username,))
    db.commit()
    return redirect('/admin')

@app.route('/ban/<username>', methods=['POST'])
def ban(username):
    if session.get('role') != 'owner': return redirect('/')
    db = get_db()
    db.execute('DELETE FROM users WHERE username = ?', (username,))
    db.commit()
    return redirect('/admin')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?', (request.form['username'], request.form['password'])).fetchone()
        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect('/')
        return render_template('index.html', page='login', error='Неверный логин', users=get_users())
    return render_template('index.html', page='login', users=get_users())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = get_db()
        exists = db.execute('SELECT * FROM users WHERE username = ?', (request.form['username'],)).fetchone()
        if exists:
            return render_template('index.html', page='register', error='Пользователь уже есть', users=get_users())
        db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (request.form['username'], request.form['password'], 'user'))
        db.commit()
        return redirect('/login')
    return render_template('index.html', page='register', users=get_users())

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/profile/<username>')
def profile(username):
    db = get_db()
    profile = db.execute('SELECT username, role FROM users WHERE username = ?', (username,)).fetchone()
    return render_template('index.html', page='profile', profile=profile, users=get_users())

@app.route('/pastes')
def pastes():
    db = get_db()
    pastes = db.execute('SELECT * FROM pastes ORDER BY id DESC').fetchall()
    return render_template('index.html', page='pastes', pastes=pastes, users=get_users())

@app.route('/paste/<int:paste_id>')
def paste_view(paste_id):
    db = get_db()
    paste = db.execute('SELECT * FROM pastes WHERE id = ?', (paste_id,)).fetchone()
    if not paste:
        abort(404)
    return render_template('index.html', page='paste', paste=paste, users=get_users())

@app.route('/create_paste', methods=['GET', 'POST'])
def create_paste():
    if request.method == 'POST':
        db = get_db()
        db.execute('INSERT INTO pastes (title, content, username) VALUES (?, ?, ?)', (request.form['title'], request.form['content'], session['username']))
        db.commit()
        return redirect('/pastes')
    return render_template('index.html', page='create_paste', users=get_users())

@app.route('/edit_paste/<int:paste_id>', methods=['GET', 'POST'])
def edit_paste(paste_id):
    db = get_db()
    paste = db.execute('SELECT * FROM pastes WHERE id = ?', (paste_id,)).fetchone()
    if not paste:
        abort(404)
    if paste['username'] != session['username'] and session.get('role') != 'owner':
        abort(403)
    if request.method == 'POST':
        db.execute('UPDATE pastes SET title = ?, content = ? WHERE id = ?', (request.form['title'], request.form['content'], paste_id))
        db.commit()
        return redirect(f'/paste/{paste_id}')
    return render_template('index.html', page='edit_paste', paste=paste, users=get_users())

@app.route('/delete_paste/<int:paste_id>', methods=['POST'])
def delete_paste(paste_id):
    db = get_db()
    paste = db.execute('SELECT * FROM pastes WHERE id = ?', (paste_id,)).fetchone()
    if not paste:
        abort(404)
    if paste['username'] != session['username'] and session.get('role') != 'owner':
        abort(403)
    db.execute('DELETE FROM pastes WHERE id = ?', (paste_id,))
    db.commit()
    return redirect('/pastes')

def get_users():
    return get_db().execute('SELECT username, role FROM users').fetchall()

if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT "user")')
        conn.execute('CREATE TABLE chat (id INTEGER PRIMARY KEY, username TEXT, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.execute('CREATE TABLE data (id INTEGER PRIMARY KEY, title TEXT, tag TEXT, content TEXT, username TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.execute('CREATE TABLE news (id INTEGER PRIMARY KEY, title TEXT, body TEXT, username TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.execute('CREATE TABLE pastes (id INTEGER PRIMARY KEY, title TEXT, content TEXT, username TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        conn.execute('INSERT INTO users (username, password, role) VALUES ("hepvov", "123", "owner")')
        conn.commit()
        conn.close()
    app.run(debug=True)
