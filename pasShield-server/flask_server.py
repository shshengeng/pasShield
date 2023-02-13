from flask import Flask, request,render_template
import socket


app = Flask(__name__)


@app.route("/")
def index():
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.connect(("localhost", 8080))
    tcp_client.send("hello".encode("utf-8"))

    # 等待 TCP 客户端响应并返回结果
    #response = tcp_client.recv(1024).decode("utf-8")
    return render_template("index.html")
    

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
