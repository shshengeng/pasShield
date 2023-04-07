from flask import Blueprint, url_for, render_template, redirect, session, request

from flask_login import LoginManager, login_user
from werkzeug.security import check_password_hash

from models import db, Users
import sqlite3

login = Blueprint('login', __name__, template_folder='../frontend')
login_manager = LoginManager()
login_manager.init_app(login)

@login.route('/login', methods=['GET', 'POST'])
def show():
    if request.method == 'POST':
        #username = request.form['username']
        #password = request.form['password']
        username =  request.form.get('username')
        token = request.form.get('token')
        print(username)
        print(token)
        try: 
            with sqlite3.connect('/home/azureuser/Desktop/pasShield-Ego-Server/data/password.db') as conn:
                cur = conn.cursor()
                cur.execute('SELECT * FROM Token WHERE username = ? AND Token = ?', (username, token))
                user = cur.fetchone()
                if user is not None:
                    session['username'] = username
                    return redirect(url_for('home.show') + '?success=login')
                else: 
                    return redirect(url_for('login.show') + '?error=user-not-found')
        except: 
            return redirect(url_for('login.show') + '?error=unknown')
    else:
        return render_template('login.html')
