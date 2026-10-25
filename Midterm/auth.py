# Authentication helpers (based on Lab 3 Auth_Server.py)
import hashlib
import hmac
import json
import os

import pyotp

USERS_FILE = os.environ.get("SENTINEL_USERS", os.path.join(os.path.dirname(__file__), "users.json"))
ITERATIONS = 200_000         # PBKDF2 makes each password guess slow (Lab 3 used plain SHA-256, which is too fast)
OTP_VALID_WINDOW = 1         # accept current 30 s step +/- 1 step (clock tolerance)
MAX_USER_FAILURES = 5        # lock the account after 5 failures (until server restart)

# Used for unknown usernames so the response time is the same as for real users
DUMMY_USER = {"salt": "00" * 16, "password_hash": "0" * 64}

failures = {}                # username -> number of failed logins
last_otp = {}                # username -> last accepted OTP (blocks replay)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS).hex()


def verify_password(password, user):
    """True if the password matches the stored salted hash (constant-time compare)."""
    salt = bytes.fromhex(user["salt"])
    return hmac.compare_digest(hash_password(password, salt), user["password_hash"])


def verify_otp(username, secret, otp):
    """True if otp is valid for this user and was not already used."""
    if last_otp.get(username) == otp:
        return False             # same code used again = replay
    if pyotp.TOTP(secret).verify(otp, valid_window=OTP_VALID_WINDOW):
        last_otp[username] = otp
        return True
    return False


def is_locked(username):
    return failures.get(username, 0) >= MAX_USER_FAILURES


def record_failure(username):
    failures[username] = failures.get(username, 0) + 1


def reset_failures(username):
    failures.pop(username, None)


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)


def add_user(username, password, role):
    """Create or replace a user. Returns the new TOTP secret."""
    users = load_users()
    salt = os.urandom(16)
    secret = pyotp.random_base32()
    users[username] = {
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt),
        "totp_secret": secret,
        "role": role,
    }
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    return secret
