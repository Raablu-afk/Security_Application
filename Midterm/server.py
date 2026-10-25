# server
# Based on Lab 1 Challenge/Server.py (threads) and Lab 3 Auth_Server.py (password + OTP state machine)

import json
import logging
import os
import re
import socket
import threading
import time

import auth
from pcap_analyzer import analyze_pcap

HOST = "127.0.0.1"           # localhost only: the service is not exposed to the network
PORT = 5050
BUFFER_SIZE = 1024
MAX_LINE = 4096              # longer messages are rejected (memory / DoS protection)
MAX_FAILED_ATTEMPTS = 3      # per connection, then the connection is closed
IDLE_TIMEOUT = 120           # seconds without a message before disconnecting
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LOG_FILE = os.environ.get("SENTINEL_LOG", "security.log")

LOGIN_REQUIRED = {"LIST", "PCAP", "STATUS", "LOGOUT"}
ADMIN_ONLY = {"STATUS"}

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(message)s")
start_time = time.time()
stats = {"connections": 0, "logins": 0, "failed_logins": 0, "denied": 0}


def log(addr, event):
    # Never pass passwords or OTP codes to this function
    message = f"{addr[0]}:{addr[1]} {event}"
    logging.info(message)
    print("[LOG]", message)


def send_line(conn, message):
    conn.sendall((message + "\n").encode())


def recv_lines(conn):
    """Generator yielding complete newline-terminated messages (from Lab 3)."""
    buffer = ""
    while True:
        data = conn.recv(BUFFER_SIZE)
        if not data:
            return                      # client closed the connection
        buffer += data.decode(errors="replace")
        if len(buffer) > MAX_LINE and "\n" not in buffer:
            raise ValueError("message too long")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if line:
                yield line


def handle_client(conn, addr):
    users = auth.load_users()
    pending_user = None          # password OK, waiting for OTP
    user = None                  # fully logged in (password + OTP)
    role = None
    failed_attempts = 0

    send_line(conn, "OK|Welcome to Operation Sentinel. Send AUTH|username|password")

    for message in recv_lines(conn):
        parts = message.split("|")
        command = parts[0].upper()
        log(addr, f"command {command}")      # only the command name, never its content

        # ---------------- AUTH|username|password ----------------
        if command == "AUTH":
            parts = message.split("|", 2)      # password may contain "|"
            if len(parts) != 3 or not parts[1] or not parts[2]:
                send_line(conn, "ERROR|Malformed AUTH. Use AUTH|username|password")
                continue
            username, password = parts[1], parts[2]

            if auth.is_locked(username):
                log(addr, f"LOGIN_LOCKED user={username}")
                send_line(conn, "ERROR|Account locked")
                continue

            account = users.get(username, auth.DUMMY_USER)
            password_ok = auth.verify_password(password, account)   # always hash, even for unknown users
            if username in users and password_ok:
                pending_user = username
                user = None
                log(addr, f"PASSWORD_OK user={username}")
                send_line(conn, "OTP_REQUIRED")
                continue
            reason = "password"

        # ---------------- OTP|123456 ----------------
        elif command == "OTP":
            if pending_user is None:
                # OTP before password = bypass attempt
                log(addr, "OTP_BEFORE_PASSWORD")
                send_line(conn, "ERROR|Password verification required before OTP")
                continue
            if len(parts) != 2 or not parts[1].isdigit() or len(parts[1]) != 6:
                send_line(conn, "ERROR|Malformed OTP. Use OTP|123456")
                continue

            username = pending_user
            pending_user = None
            if auth.verify_otp(username, users[username]["totp_secret"], parts[1]):
                user, role = username, users[username]["role"]
                auth.reset_failures(username)
                failed_attempts = 0
                stats["logins"] += 1
                log(addr, f"LOGIN_SUCCESS user={user} role={role}")
                send_line(conn, f"ACCESS_GRANTED|{role}")
                continue
            reason = "otp"

        # ---------------- QUIT ----------------
        elif command == "QUIT":
            send_line(conn, "BYE")
            break

        # ---------------- protected commands ----------------
        elif command in LOGIN_REQUIRED:
            if user is None:
                stats["denied"] += 1
                log(addr, f"DENIED_NOT_LOGGED_IN command={command}")
                send_line(conn, "ERROR|Authentication required")
            elif command in ADMIN_ONLY and role != "admin":
                stats["denied"] += 1
                log(addr, f"DENIED_ROLE user={user} role={role} command={command}")
                send_line(conn, "ERROR|Not authorized")
            else:
                send_line(conn, run_command(addr, user, command, parts))
                if command == "LOGOUT":
                    user = role = None
            continue

        else:
            log(addr, "UNKNOWN_COMMAND")
            send_line(conn, f"ERROR|Unknown command '{parts[0][:20]}'")
            continue

        # ---------------- failed AUTH or OTP ends up here ----------------
        failed_attempts += 1
        stats["failed_logins"] += 1
        if username in users:
            auth.record_failure(username)
        log(addr, f"LOGIN_FAILED user={username} stage={reason} attempts={failed_attempts}")
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            send_line(conn, "ERROR|Too many failed attempts. Connection closed.")
            break
        send_line(conn, "ACCESS_DENIED")


def run_command(addr, user, command, parts):
    if command == "LIST":
        files = sorted(f for f in os.listdir(DATA_DIR) if f.endswith(".pcap"))
        return "OK|" + ",".join(files)

    if command == "PCAP":
        name = parts[1] if len(parts) == 2 else ""
        # Only a plain file name: blocks "../users.json" style path traversal
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.pcap", name):
            log(addr, f"PCAP_BAD_NAME user={user}")
            return "ERROR|Invalid file name. Use PCAP|name.pcap"
        path = os.path.join(DATA_DIR, name)
        if not os.path.isfile(path):
            return "ERROR|File not found"
        try:
            result = analyze_pcap(path)
        except Exception as e:
            log(addr, f"PCAP_ERROR user={user} error={type(e).__name__}")
            return "ERROR|Could not read capture file"
        log(addr, f"PCAP_ANALYZED user={user} file={name} alerts={len(result['alerts'])}")
        return "OK|" + json.dumps(result)          # json.dumps keeps it on one line

    if command == "STATUS":
        info = dict(stats, uptime_s=round(time.time() - start_time), threads=threading.active_count() - 1)
        return "OK|" + json.dumps(info)

    if command == "LOGOUT":
        log(addr, f"LOGOUT user={user}")
        return "OK|Logged out"


def client_thread(conn, addr):
    stats["connections"] += 1
    log(addr, "CONNECTED")
    conn.settimeout(IDLE_TIMEOUT)
    try:
        handle_client(conn, addr)
    except socket.timeout:
        log(addr, "IDLE_TIMEOUT")
    except ValueError:
        log(addr, "MESSAGE_TOO_LONG")
        send_line(conn, "ERROR|Message too long. Connection closed.")
    except (ConnectionResetError, BrokenPipeError):
        log(addr, "CONNECTION_RESET")
    except Exception as e:                     # never let one client crash the server
        log(addr, f"ERROR {type(e).__name__}")
    finally:
        conn.close()
        log(addr, "DISCONNECTED")


def main():
    if not auth.load_users():
        print("[!] No users found. Run: python create_user.py <username> <analyst|admin>")
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] Sentinel server listening on {HOST}:{PORT} (Ctrl+C to stop)")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=client_thread, args=(conn, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
