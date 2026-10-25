# HTTP security checks (based on Lab 5 http_scanner.py and vulnerability_detector.py)
from urllib.parse import urlparse

import requests

BASE_URL = "http://127.0.0.1:8765"
TIMEOUT = 5
PATHS = ["/", "/health", "/redirect", "/missing"]
ALLOWED_HOSTS = ("127.0.0.1", "localhost")       # only test our local website

SECURITY_HEADERS = ["Content-Security-Policy", "X-Frame-Options",
                    "X-Content-Type-Options", "Referrer-Policy"]


def get(url):
    """GET request that returns None instead of crashing when the server is unreachable."""
    try:
        # allow_redirects=False so we can see the redirect itself
        return requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None


def check_website(base_url=BASE_URL):
    """Return (responses, findings). Raises ValueError for a non-local target."""
    if urlparse(base_url).hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Target '{base_url}' is not authorized (localhost only)")

    responses = []
    findings = []

    if base_url.startswith("http://"):
        findings.append("Plain HTTP: traffic and cookies are not encrypted")

    for path in PATHS:
        r = get(base_url + path)
        if r is None:
            findings.append(f"Could not connect to {base_url}{path} - is test_website.py running?")
            return responses, findings
        responses.append((path, r.status_code))

        if path == "/":
            for name in SECURITY_HEADERS:
                if name not in r.headers:
                    findings.append(f"Missing header {name} on /")

            cookie = r.headers.get("Set-Cookie")
            if cookie:
                for flag in ("HttpOnly", "Secure", "SameSite"):
                    if flag.lower() not in cookie.lower():
                        findings.append(f"Cookie '{cookie.split('=')[0]}' has no {flag} flag")

            server = r.headers.get("Server")
            if server:
                findings.append(f"Server banner disclosed: {server}")

        if r.status_code in (301, 302):
            findings.append(f"{path} redirects to {r.headers.get('Location')} (same site, not an open redirect)")

    return responses, findings
