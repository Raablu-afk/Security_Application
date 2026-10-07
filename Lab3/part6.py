import hashlib, time, pyotp

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()
def verify_password(p, h): return hash_password(p) == h
def verify_otp(secret, otp): return pyotp.TOTP(secret).verify(otp)

print("Part 2 - hashing")
for p in ["Cyber123!", "Cyber123!", "Cyber124!"]:
    h = hash_password(p); print(f"  {p:<10} -> {h}  ({len(h)} hex chars)")
stored = hash_password("Cyber123!")
print("  verify_password('Cyber123!') ->", verify_password("Cyber123!", stored))
print("  verify_password('cyber123!') ->", verify_password("cyber123!", stored))

print("Part 5 - secrets")
for _ in range(3): print("  random_base32():", pyotp.random_base32())

print("Part 6 - TOTP")
secret = pyotp.random_base32(); totp = pyotp.TOTP(secret)
code = totp.now()
print("  current OTP        :", code, "->", verify_otp(secret, code))
wrong = f"{(int(code) + 1) % 1000000:06d}"
print("  incorrect OTP      :", wrong, "->", verify_otp(secret, wrong))
old = totp.at(time.time() - 60)
print("  OTP from 60 s ago  :", old, "->", verify_otp(secret, old))