import socket
import time

class socket_server:
    def __init__(self, host_ip, host_port):
        self.host_ip = str(host_ip)
        self.host_port = int(host_port)
        self.message = b""

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host_ip, self.host_port))
        server_socket.listen()
        client_socket, addr = server_socket.accept()

        start = time.time()
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            if data.decode() == "Authentication Request":
                client_socket.sendall(self.message)
            # Timeout
            if time.time() - start > 10: 
                break

        client_socket.close()
        server_socket.close()