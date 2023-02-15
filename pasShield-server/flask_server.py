from flask import Flask, request,render_template
import socket

app = Flask(__name__)

def init():
    response_state = False
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.connect(("localhost", 8080))
    
    tcp_client.sendall(b"Hello, server!")
    
    response = tcp_client.recv(1024)
    print("Server says:", response.decode())
    response_state = True

    return 


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}

if __name__ == "__main__":
    init()
    app.run(host="0.0.0.0", port=5000)
