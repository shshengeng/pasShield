from flask import Flask, request,render_template
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 8080))
server_socket.listen(5)
client_socket, client_address = server_socket.accept()
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")
@app.route("/")
def req_Credentials_from_ego():
    request = client_socket.recv(1024).decode("utf-8")
    tcp_client.send("{}:{}".format(username, password).encode("utf-8"))
    print(request)
    return request

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
