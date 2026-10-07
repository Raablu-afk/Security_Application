import socket
import sys
from getpass import getpass

HOST = "127.0.0.1"
PORT = 5050
BUFFER_SIZE = 1024


class Connection:
    """Small wrapper that sends/receives newline-delimited messages."""

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.buffer = ""

    def send(self, message):
        self.sock.sendall((message + "\n").encode())

    def recv(self):
        while "\n" not in self.buffer:
            data = self.sock.recv(BUFFER_SIZE)
            if not data:
                raise ConnectionError("Server closed the connection")
            self.buffer += data.decode(errors="replace")
        line, self.buffer = self.buffer.split("\n", 1)
        return line.strip()

    def close(self):
        self.sock.close()


def login_flow(conn):
    while True:
        username = input("Username: ").strip()
        password = getpass("Password: ")       # not echoed on screen

        if "|" in username or "|" in password:
            print("The '|' character is not allowed.")
            continue

        conn.send(f"AUTH|{username}|{password}")
        response = conn.recv()

        if response == "OTP_REQUIRED":
            otp = input("OTP (6 digits): ").strip()
            conn.send(f"OTP|{otp}")
            response = conn.recv()

        if response == "ACCESS_GRANTED":
            print("[+] ACCESS GRANTED")
            conn.send("QUIT")
            conn.recv()
            return
        elif response == "ACCESS_DENIED":
            print("[-] ACCESS DENIED")
        elif response.startswith("ERROR|"):
            print("[!] Server error:", response.split("|", 1)[1])
            if "blocked" in response.lower():
                return                          # server is closing the connection
        else:
            print("[?] Unexpected response:", response)

        if input("Try again? (y/n): ").strip().lower() != "y":
            conn.send("QUIT")
            conn.recv()
            return


def raw_mode(conn):
    print("Raw protocol mode. Type messages exactly, e.g. OTP|123456 or AUTH|alice")
    print("Type QUIT to exit.")
    while True:
        message = input("> ").strip()
        if not message:
            continue
        conn.send(message)
        response = conn.recv()
        print("Server:", response)
        if response == "BYE" or "blocked" in response.lower():
            return


def main():
    try:
        conn = Connection(HOST, PORT)
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {HOST}:{PORT}. Is auth_server.py running?")
        return

    print(f"[*] Connected to {HOST}:{PORT}")
    try:
        if "--raw" in sys.argv:
            raw_mode(conn)
        else:
            login_flow(conn)
    except (ConnectionError, ConnectionResetError, BrokenPipeError) as e:
        print("[!] Connection lost:", e)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
    finally:
        conn.close()
        print("[*] Connection closed")


if __name__ == "__main__":
    main()