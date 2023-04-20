from flask import Blueprint, render_template, session
from flask_login import LoginManager, login_required, current_user

from models import db, Users

home = Blueprint('home', __name__, template_folder='../frontend/templates')
login_manager = LoginManager()
login_manager.init_app(home)

@home.route('/home/<username>', methods=['GET'])
#@login_required
def show(username):
    if 'username' in session:
        return render_template('home.html', username=username), 200, [("Ego-Enclave-Attestation", "true")]
    else:
        return render_template('home.html', username=username), 200, [("Ego-Enclave-Attestation", "true")]