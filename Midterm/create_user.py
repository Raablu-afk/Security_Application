# Create a user in users.json and print the TOTP secret
# Usage: python create_user.py alice analyst
import sys
from getpass import getpass

import pyotp

import auth

if len(sys.argv) != 3 or sys.argv[2] not in ("analyst", "admin"):
    print("Usage: python create_user.py <username> <analyst|admin>")
    sys.exit(1)

username, role = sys.argv[1], sys.argv[2]
password = getpass("Password (min 8 chars): ")
if len(password) < 8 or password != getpass("Repeat password: "):
    print("[!] Passwords must match and be at least 8 characters.")
    sys.exit(1)

secret = auth.add_user(username, password, role)
print(f"User '{username}' ({role}) saved.")
print("TOTP secret:", secret)
print("Provisioning URI:", pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Sentinel"))
