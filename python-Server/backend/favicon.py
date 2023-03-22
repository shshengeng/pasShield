from flask import Blueprint, url_for, render_template, redirect, request
from flask_login import LoginManager

favicon = Blueprint('favicon', __name__, template_folder='../backend')
login_manager = LoginManager()
login_manager.init_app(favicon)



@favicon.route('/favicon.ico', methods=['GET', 'POST'])
def show():
    return "", 204
    
