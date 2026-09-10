import socket

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")

client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)

data = client_socket.recv(1024)

message = data.decode()

print("Client says:", message)

reply = "You have been authenticated as " + message

client_socket.send(reply.encode())

client_socket.close()
server_socket.close()