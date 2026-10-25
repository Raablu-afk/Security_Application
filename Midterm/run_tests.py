# Run command is this: python run_tests.py > docs/test_output.txt
import json
import os
import subprocess
import sys
import time

import pyotp

import auth
import http_checker
import scanner
from client import Connection

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_USERS = os.path.join(HERE, "test_users.json")
TEST_LOG = os.path.join(HERE, "test_security.log")
PCAP = "FSCT8561_Operation_Sentinel_Traffic.pcap"
results = []


def check(name, expected, actual, passed):
    results.append(passed)
    print(f"\nTest {len(results)}: {name}")
    print(f"  Expected: {expected}")
    print(f"  Actual:   {actual}")
    print(f"  Result:   {'PASS' if passed else 'FAIL'}")


def connect():
    conn = Connection()
    conn.recv()                      # welcome message
    return conn


def login(username, password, secret):
    conn = connect()
    conn.request(f"AUTH|{username}|{password}")
    response = conn.request(f"OTP|{pyotp.TOTP(secret).now()}")
    return conn, response


# --- setup: test users, then start website + server ---------------------------
for f in (TEST_USERS, TEST_LOG):
    if os.path.exists(f):
        os.remove(f)
auth.USERS_FILE = TEST_USERS
alice = auth.add_user("alice", "Analyst-Pass-1", "analyst")
bob = auth.add_user("bob", "Analyst-Pass-2", "analyst")
admin = auth.add_user("admin", "Admin-Pass-3", "admin")
mallory = auth.add_user("mallory", "Mallory-Pass-4", "analyst")

env = dict(os.environ, SENTINEL_USERS=TEST_USERS, SENTINEL_LOG=TEST_LOG)
website = subprocess.Popen([sys.executable, "test_website.py"], cwd=HERE,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
server = subprocess.Popen([sys.executable, "server.py"], cwd=HERE, env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)

try:
    # 1. Unauthenticated request
    conn = connect()
    r = conn.request(f"PCAP|{PCAP}")
    check("Protected command without login", "ERROR|Authentication required", r,
          r == "ERROR|Authentication required")

    # 2. OTP before password
    r = conn.request("OTP|123456")
    check("OTP sent before password", "ERROR|Password verification required before OTP", r,
          r.startswith("ERROR|Password verification required"))

    # 3. Wrong password
    r = conn.request("AUTH|alice|wrong-password")
    check("Failed authentication (wrong password)", "ACCESS_DENIED", r, r == "ACCESS_DENIED")

    # 4. Correct password, wrong OTP
    conn.request("AUTH|alice|Analyst-Pass-1")
    r = conn.request("OTP|000000")
    check("Correct password, wrong OTP", "ACCESS_DENIED", r, r == "ACCESS_DENIED")
    conn.close()

    # 5. Successful login
    conn, r = login("alice", "Analyst-Pass-1", alice)
    check("Successful authentication (password + TOTP)", "ACCESS_GRANTED|analyst", r,
          r == "ACCESS_GRANTED|analyst")
    used_code = pyotp.TOTP(alice).now()
    conn.close()

    # 6. OTP replay
    conn = connect()
    conn.request("AUTH|alice|Analyst-Pass-1")
    r = conn.request(f"OTP|{used_code}")
    check("Replay of an already-used OTP", "ACCESS_DENIED", r, r == "ACCESS_DENIED")
    conn.close()

    # 7. Analyst tries admin command
    conn, _ = login("bob", "Analyst-Pass-2", bob)
    r = conn.request("STATUS")
    check("Analyst runs admin-only STATUS", "ERROR|Not authorized", r, r == "ERROR|Not authorized")

    # 8. PCAP summary
    r = conn.request(f"PCAP|{PCAP}")
    data = json.loads(r[3:]) if r.startswith("OK|") else {}
    summary = data.get("summary", {})
    check("PCAP summary sent to client", "123 packets (113 TCP, 10 UDP)",
          f"{summary.get('total_packets')} packets ({summary.get('tcp_packets')} TCP, "
          f"{summary.get('udp_packets')} UDP), {summary.get('duration_s')} s",
          summary.get("total_packets") == 123)

    # 9. PCAP detection
    alerts = data.get("alerts", [])
    check("PCAP suspicious-pattern detection", "port scan, SYN flood/brute force, non-DNS on port 53",
          "\n            ".join(alerts), len(alerts) == 3)

    # 10. Invalid input: path traversal
    r = conn.request("PCAP|../users.json")
    check("Invalid file name (path traversal)", "ERROR|Invalid file name...", r,
          r.startswith("ERROR|Invalid file name"))

    # 11. Unknown command
    r = conn.request("DELETE_EVERYTHING")
    check("Unknown command", "ERROR|Unknown command", r, r.startswith("ERROR|Unknown command"))
    conn.close()

    # 12. Admin STATUS
    conn, _ = login("admin", "Admin-Pass-3", admin)
    r = conn.request("STATUS")
    check("Admin runs STATUS", "OK|{...diagnostics...}", r, r.startswith("OK|"))
    conn.close()

    # 13. Account lockout
    for i in range(5):
        c = connect()
        c.request(f"AUTH|mallory|bad-guess-{i}")
        c.close()
    c = connect()
    r = c.request("AUTH|mallory|Mallory-Pass-4")
    check("Account locked after 5 failures", "ERROR|Account locked", r, r == "ERROR|Account locked")
    c.close()

    # 14-15. Port scan: open and closed ports
    open_ports = scanner.scan("127.0.0.1", 5000, 6000) + scanner.scan("127.0.0.1", 8700, 8800)
    check("Port scan finds open ports", "5050 (server) and 8765 (website) open", open_ports,
          5050 in open_ports and 8765 in open_ports)
    check("Port scan reports a closed port", "5051 closed", "5051 closed" if 5051 not in open_ports else "5051 open", 5051 not in open_ports)

    # 16. Scanner rejects outside target
    try:
        scanner.scan("8.8.8.8", 1, 100)
        r = "scan allowed"
    except ValueError as e:
        r = str(e)
    check("Scanner rejects unauthorized target", "ValueError (not authorized)", r, "not authorized" in r)

    # 17. HTTP findings
    responses, findings = http_checker.check_website()
    check("HTTP security findings", "plain HTTP, missing headers, weak cookie, server banner",
          f"{responses}\n            " + "\n            ".join(findings), len(findings) >= 5)

    # 18. HTTP connection failure
    responses, findings = http_checker.check_website("http://127.0.0.1:8799")
    check("HTTP connection failure", "Could not connect...", findings[-1], "Could not connect" in findings[-1])

    # 19. Server disconnection
    conn = connect()
    server.terminate()
    server.wait()
    try:
        conn.request("LIST")
        r = "no error"
    except (ConnectionError, OSError) as e:
        r = f"{type(e).__name__}: {e}"
    check("Server disconnects while client connected", "ConnectionError handled", r, r != "no error")

    # 20. Log has no secrets
    log_text = open(TEST_LOG).read()
    leaked = [p for p in ("Analyst-Pass-1", "wrong-password", used_code, alice) if p in log_text]
    check("Security log contains no passwords or OTPs", "nothing leaked",
          f"{len(log_text.splitlines())} log lines, leaked={leaked}", not leaked)

finally:
    for p in (server, website):
        p.terminate()
    for f in (TEST_USERS,):
        if os.path.exists(f):
            os.remove(f)

print(f"\n{sum(results)}/{len(results)} tests passed")