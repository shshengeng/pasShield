import os
from flask import Blueprint, render_template, redirect
from flask_login import LoginManager

attestation = Blueprint('attestation', __name__, template_folder='../frontend')
login_manager = LoginManager()
login_manager.init_app(attestation)



@attestation.route('/attestation', methods=['GET', 'POST'])
def attest():

    r = os.popen("cd ~/Desktop/ego/samples/azure_attestation/ && chmod u+x public.pem && ./client -s `ego signerid public.pem`")
    info = r.readlines()
    for line in info:  
        line = line.strip('\r\n')
        if line == "✅ Azure Attestation Token verified.":
            print("got it")
            return redirect('http://baidu.com')
    return redirect("http://www.google.com")

    
