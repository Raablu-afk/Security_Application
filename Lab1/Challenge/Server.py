import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

def handle_client(client_socket, client_address):
    """This function runs in a separate thread for every connected client."""
    print("Connected by:", client_address)
    
    username = None
    connected = True

    while connected:
        try:
            data = client_socket.recv(1024)

            if not data:
                print(f"Client {client_address} disconnected unexpectedly")
                break

            message = data.decode()
            print(f"Received from {client_address}: {message}")

            if "|" not in message:
                client_socket.send("ERROR|Invalid command format".encode())
                continue

            command, content = message.split("|", 1)

            if command == "HELLO":
                if content == "":
                    client_socket.send("ERROR|Username required".encode())
                else:
                    username = content
                    print(f"Username for {client_address}: {username}")
                    client_socket.send(("OK|Hello " + username).encode())

            elif command == "MSG":
                if username is None:
                    client_socket.send("ERROR|HELLO required first".encode())
                elif content == "":
                    client_socket.send("ERROR|Message cannot be empty".encode())
                elif len(content) > 200:
                    client_socket.send("ERROR|Message too long".encode())
                else:
                    print(username + " says:", content)
                    client_socket.send(("OK|Message received from " + username).encode())

            elif command == "EXIT":
                client_socket.send("OK|Goodbye".encode())
                connected = False

            else:
                client_socket.send("ERROR|Unknown command".encode())

        except ConnectionResetError:
            print(f"Connection reset by client {client_address}")
            break

    client_socket.close()
    print(f"Connection closed for {client_address}")

# --- Main Server Setup ---
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))

# Listen without a strict limit to allow a queue of multiple incoming clients
server_socket.listen() 

print("Server is waiting for connections...")

try:
    while True:
        # The main thread blocks here until a new client connects
        client_socket, client_address = server_socket.accept()
        
        # Create and start a new thread strictly for this client
        client_thread = threading.Thread(
            target=handle_client, 
            args=(client_socket, client_address)
        )
        
        # Daemon threads automatically shut down when the main server script exits
        client_thread.daemon = True 
        client_thread.start()
        
        # Subtract 1 to exclude the main listening thread
        print(f"Active client threads: {threading.active_count() - 1}")

except KeyboardInterrupt:
    print("\nServer shutting down.")
finally:
    server_socket.close()