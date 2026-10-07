import hashlib
import hmac
import os
import socket

import pyotp

HOST = "127.0.0.1"
PORT = 5050
BUFFER_SIZE = 1024
MAX_FAILED_ATTEMPTS = 3      # Challenge: lock after 3 consecutive failures
OTP_VALID_WINDOW = 1         # accept current 30 s step +/- 1 step (clock tolerance)
SECRET_FILE = "alice_totp.secret"


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------
def hash_password(password):
    """Return the SHA-256 hex digest of a password."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    """True if the password hashes to stored_hash (constant-time compare)."""
    return hmac.compare_digest(hash_password(password), stored_hash)


def verify_otp(secret, otp):
    """True if otp is a valid TOTP for secret within the allowed window."""
    return pyotp.TOTP(secret).verify(otp, valid_window=OTP_VALID_WINDOW)


def load_or_create_secret(path):
    """
    Keep the SAME TOTP secret across server restarts so the authenticator
    app keeps working. Generated once, then reused.
    """
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    secret = pyotp.random_base32()
    with open(path, "w") as f:
        f.write(secret)
    return secret


# ---------------------------------------------------------------------------
# User database (no plaintext passwords stored)
# ---------------------------------------------------------------------------
alice_secret = load_or_create_secret(SECRET_FILE)

users = {
    "alice": {
        "password_hash": hash_password("Cyber123!"),
        "totp_secret": alice_secret,
    }
}

DUMMY_HASH = hash_password("dummy-value-for-unknown-users")


# ---------------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------------
def send_line(conn, message):
    conn.sendall((message + "\n").encode())


def recv_lines(conn):
    """Generator yielding complete newline-terminated messages."""
    buffer = ""
    while True:
        data = conn.recv(BUFFER_SIZE)
        if not data:
            return                      # client closed the connection
        buffer += data.decode(errors="replace")
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if line:
                yield line


# ---------------------------------------------------------------------------
# Per-client authentication session (the state machine)
# ---------------------------------------------------------------------------
def handle_client(conn, addr):
    # --- authentication state for THIS connection ---
    password_verified = False
    pending_user = None
    failed_attempts = 0

    def register_failure(reason):
        nonlocal failed_attempts, password_verified, pending_user
        failed_attempts += 1
        password_verified = False       # any failure restarts at the password stage
        pending_user = None
        print(f"[!] {addr} {reason} (failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS})")
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            send_line(conn, "ERROR|Too many failed attempts. Authentication blocked.")
            print(f"[X] {addr} blocked after {failed_attempts} consecutive failures")
            return True                 # caller should close the connection
        send_line(conn, "ACCESS_DENIED")
        return False

    for message in recv_lines(conn):
        # Never log full AUTH messages: they contain the password
        log_msg = message.split("|")[0] if message.startswith("AUTH") else message
        print(f"[<] {addr} {log_msg}")

        parts = message.split("|")
        command = parts[0].upper()

        # ---------------- AUTH|username|password ----------------
        if command == "AUTH":
            if len(parts) != 3 or not parts[1] or not parts[2]:
                send_line(conn, "ERROR|Malformed AUTH. Use AUTH|username|password")
                continue

            username, password = parts[1], parts[2]
            user = users.get(username)
            stored = user["password_hash"] if user else DUMMY_HASH
            password_ok = verify_password(password, stored)

            if user and password_ok:
                password_verified = True
                pending_user = username
                print(f"[+] {addr} password OK for '{username}', OTP required")
                send_line(conn, "OTP_REQUIRED")
            else:
                reason = "unknown username" if not user else "wrong password"
                if register_failure(f"AUTH failed: {reason}"):
                    break

        # ---------------- OTP|123456 ----------------
        elif command == "OTP":
            if not password_verified or pending_user is None:
                # Bypass attempt: OTP before password. Rejected, not counted.
                send_line(conn, "ERROR|Password verification required before OTP")
                continue
            if len(parts) != 2 or not parts[1].isdigit() or len(parts[1]) != 6:
                send_line(conn, "ERROR|Malformed OTP. Use OTP|123456")
                continue

            secret = users[pending_user]["totp_secret"]
            if verify_otp(secret, parts[1]):
                print(f"[+] {addr} ACCESS GRANTED for '{pending_user}'")
                failed_attempts = 0         # success resets the counter
                password_verified = False
                pending_user = None
                send_line(conn, "ACCESS_GRANTED")
            else:
                if register_failure("OTP failed (wrong or expired)"):
                    break

        # ---------------- QUIT ----------------
        elif command == "QUIT":
            send_line(conn, "BYE")
            break

        else:
            send_line(conn, f"ERROR|Unknown command '{parts[0]}'")


def main():
    print("=== FSCT 8561 Lab 3 - Authentication Server ===")
    print(f"Alice's TOTP secret: {alice_secret}")
    print("Provisioning URI (add to an authenticator app for testing):")
    print(pyotp.TOTP(alice_secret).provisioning_uri(name="alice", issuer_name="FSCT8561-Lab3"))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[*] Listening on {HOST}:{PORT} (Ctrl+C to stop)")

    try:
        while True:                      # one client at a time, forever
            conn, addr = server.accept()
            print(f"[*] Connection from {addr}")
            try:
                handle_client(conn, addr)
            except (ConnectionResetError, BrokenPipeError) as e:
                print(f"[!] {addr} connection error: {e}")
            except Exception as e:       # never let one client crash the server
                print(f"[!] {addr} unexpected error: {e}")
            finally:
                conn.close()
                print(f"[*] Connection with {addr} closed")
    except KeyboardInterrupt:
        print("\n[*] Server shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()