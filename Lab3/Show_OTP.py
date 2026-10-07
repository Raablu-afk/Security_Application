"""
prints alice's current OTp.
"""
import time
import pyotp

with open("alice_totp.secret") as f:
    totp = pyotp.TOTP(f.read().strip())

remaining = totp.interval - int(time.time()) % totp.interval
print(f"Current OTP: {totp.now()}  (changes in {remaining}s)")