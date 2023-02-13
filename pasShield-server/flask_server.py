from flask import Flask, request,render_template
import socket

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")
@app.route("/")
def req_Credentials_from_ego():
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.connect(("localhost", 8080))
    tcp_client.send("{}:{}".format(username, password).encode("utf-8"))

    # wait go application's response
    response = tcp_client.recv(1024).decode("utf-8")
    return response

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
