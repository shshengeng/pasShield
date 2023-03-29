from multiprocessing import process
import os
import subprocess
from flask import Blueprint, render_template, redirect
from flask_login import LoginManager

server_start = Blueprint('server_start', __name__, template_folder='../frontend')
login_manager = LoginManager()
login_manager.init_app(server_start)

@server_start.route('/server_start', methods=['GET', 'POST'])
def server():
    try:
        os.chdir('/Users/rinkolite/Downloads/pasShield-main/pasShield-enclave')
        subprocess.popen(['ego', 'run', 'main.go'], stdout=subprocess.PIPE)
        output, error = process.communicate()
        print(output.decode('utf-8'))
    except OSError as e:
        error_message = "Failed to start the server: {e}"
        return error_message, 500   

    
