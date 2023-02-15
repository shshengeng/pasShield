import socket
import sys
import getFileContent

server_address = ('localhost', 8000)
class WebServer():
	def run(self):
		print (sys.stderr, 'starting up on %s port %s' % server_address)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(server_address)
		sock.listen(1)
		while True:
			connection, client_address = sock.accept()
			print (sys.stderr, 'waiting for a connection')
			try:
				data = connection.recv(1024)
				print(data)
				if data:
					connection.sendall(getFileContent.getHtmlFile(data).encode("utf-8"))
			finally:
				connection.close()

if __name__ == '__main__':
	server = WebServer()
	server.run()
