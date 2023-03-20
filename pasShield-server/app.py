from flask import Flask, render_template, request, session, redirect, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'secret'
cwd = os.getcwd()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password == confirm_password:
            try:
                with sqlite3.connect(os.path.join(cwd, 'users.db')) as conn:
                    cur = conn.cursor()
                    cur.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
                    cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                    conn.commit()
                    session['username'] = username
                    return redirect(url_for('profile'))
            except:
                return render_template('signup.html', error='An error occurred. Please try again.')
        else:
            return render_template('signup.html', error='Passwords do not match.')
    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            with sqlite3.connect(os.path.join(cwd, 'users.db')) as conn:
                cur = conn.cursor()
                cur.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
                user = cur.fetchone()
                if user is not None:
                    session['username'] = user[1]
                    return redirect(url_for('profile'))
                else:
                    return render_template('login.html', error='Invalid username or password.')
        except:
            return render_template('login.html', error='An error occurred. Please try again.')
    else:
        return render_template('login.html')

@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template('profile.html', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
