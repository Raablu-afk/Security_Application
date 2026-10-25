# analyst client
# Based on Lab 3 Auth_Client.py (Connection class, login flow).
import json
import socket
from getpass import getpass

import http_checker
import scanner

HOST = "127.0.0.1"
PORT = 5050
BUFFER_SIZE = 1024


class Connection:
    """Small wrapper that sends/receives newline-delimited messages (from Lab 3)."""

    def __init__(self, host=HOST, port=PORT):
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

    def request(self, message):
        self.send(message)
        return self.recv()

    def close(self):
        self.sock.close()


def login(conn):
    username = input("Username: ").strip()
    password = getpass("Password: ")           # not echoed on screen
    response = conn.request(f"AUTH|{username}|{password}")
    if response == "OTP_REQUIRED":
        otp = input("OTP (6 digits): ").strip()
        response = conn.request(f"OTP|{otp}")
    if response.startswith("ACCESS_GRANTED"):
        print("[+] ACCESS GRANTED, role:", response.split("|")[1])
    else:
        print("[-]", response)


def port_scan():
    target = input("Target [127.0.0.1]: ").strip() or "127.0.0.1"
    start = int(input("Start port [5000]: ").strip() or 5000)
    end = int(input("End port [6000]: ").strip() or 6000)
    open_ports = scanner.scan(target, start, end)
    print(f"\nPORT      STATE  SERVICE")
    for port in open_ports:
        print(f"{port:<10}open   {scanner.get_service(port)}")
    print(f"{len(open_ports)} open, {end - start + 1 - len(open_ports)} closed")
    print("(open = reachable, not necessarily vulnerable)")


def http_check():
    url = input(f"Website [{http_checker.BASE_URL}]: ").strip() or http_checker.BASE_URL
    responses, findings = http_checker.check_website(url)
    for path, status in responses:
        print(f"  GET {path:<10} -> {status}")
    print("Findings (observations, not proof of a vulnerability):")
    for f in findings:
        print("  -", f)


def analyze_pcap(conn):
    response = conn.request("LIST")
    if not response.startswith("OK|"):
        print("[-]", response)
        return
    print("Available:", response[3:])
    name = input("File: ").strip()
    response = conn.request(f"PCAP|{name}")
    if not response.startswith("OK|"):
        print("[-]", response)
        return
    result = json.loads(response[3:])
    print("\nSUMMARY")
    for key, value in result["summary"].items():
        print(f"  {key}: {value}")
    print(f"ALERTS ({len(result['alerts'])})")
    for alert in result["alerts"]:
        print("  -", alert)


MENU = """
1) Login            4) Analyze PCAP (server)
2) Port scan        5) Server status (admin)
3) HTTP check       6) Logout
0) Quit"""


def main():
    try:
        conn = Connection()
    except ConnectionRefusedError:
        print(f"[!] Could not connect to {HOST}:{PORT}. Is server.py running?")
        return
    print("Server:", conn.recv())

    try:
        while True:
            print(MENU)
            choice = input("> ").strip()
            try:
                if choice == "1":
                    login(conn)
                elif choice == "2":
                    port_scan()
                elif choice == "3":
                    http_check()
                elif choice == "4":
                    analyze_pcap(conn)
                elif choice == "5":
                    print(conn.request("STATUS"))
                elif choice == "6":
                    print(conn.request("LOGOUT"))
                elif choice == "0":
                    print(conn.request("QUIT"))
                    break
                else:
                    print("[!] Invalid choice")
            except ValueError as e:               # bad numbers or unauthorized targets
                print("[!] Invalid input:", e)
    except (ConnectionError, ConnectionResetError, BrokenPipeError) as e:
        print("[!] Connection lost:", e)
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Interrupted")
    finally:
        conn.close()
        print("[*] Connection closed")


if __name__ == "__main__":
    main()
