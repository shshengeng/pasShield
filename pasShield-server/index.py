from flask import  Flask,render_template,request,session,redirect,url_for
import socket
app=Flask(__name__)
app.secret_key='2'    #set up a secret key for session

try:
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.connect(('localhost', 8080))       #connect to tcp server
    tcp_sock.send("tcp connect".encode("utf-8"))      #test message sending
    tcp_recv = tcp_sock.recv(1024)
    print(tcp_recv.decode())     #test message receiving
    tcp_sock.close()
except ConnectionRefusedError:
    print("tcp connect failed")

http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    http_sock.connect(('localhost', 8000))      #connect to http server
    http_sock.send('http connect'.encode('utf-8'))
    http_recv = http_sock.recv(1024)
    print(http_recv.decode())
    http_sock.close()
except ConnectionRefusedError:
    print("http connect failed")

@app.route('/')
def index():
    msg="Password Shield Test Form"
    return render_template("index.html",data=msg)

@app.route('/login')
def loginpage():
    return render_template("login.html")

@app.route('/news')   
def newspage():
    return render_template("news.html")

@app.route('/loginProcess',methods=['POST','GET'])
def loginProcesspage():
    if request.method=='POST':
        nm=request.form['nm']
        pwd=request.form['pwd']
        if nm=='karl' and pwd=='123':
            session['username']=nm             #use session to store data，set a key and a value for testing session          
            return redirect(url_for('index'))  #jump back to index page
        else:
            return 'the username or userpwd does not match!'

@app.route('/log_out')
def logOut():
    session.clear()
    return redirect(url_for('index'))                         

if __name__=="__main__":
    app.run(port=8080,host="0.0.0.0",debug=True)