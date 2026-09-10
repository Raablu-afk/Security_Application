import socket

HOST = "127.0.0.1"
PORT = 12345

client_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client_socket.connect((HOST, PORT))

message = "Raphael"

client_socket.send(message.encode())

response = client_socket.recv(1024)

print("Server replied:", response.decode())

client_socket.close()