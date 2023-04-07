from flask import Blueprint, render_template, session
from flask_login import LoginManager, login_required, current_user

from models import db, Users

home = Blueprint('home', __name__, template_folder='../frontend')
login_manager = LoginManager()
login_manager.init_app(home)

@home.route('/home', methods=['GET'])
#@login_required
def show():
    if 'username' in session:
        return render_template('home.html'), 200, [("Ego-Enclave-Attestation", "true")]
    else:
        return redirect(url_for('login.show')), 200, [("Ego-Enclave-Attestation", "true")]
azureuser@Ubuntu20:/var/www/Flask-Login-Register/backend$ cat app.py 
from flask import Flask
import sqlalchemy
from flask_login import LoginManager
import os

from models import db, Users

from index import index
from login import login
from logout import logout
from register import register
from home import home
from favicon import favicon


app = Flask(__name__, static_folder='../frontend/static')

app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database.db'
app.secret_key = os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)
app.app_context().push()

app.register_blueprint(index)
app.register_blueprint(login)
app.register_blueprint(logout)
app.register_blueprint(register)
app.register_blueprint(home)
app.register_blueprint(favicon)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
