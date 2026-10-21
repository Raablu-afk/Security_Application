# FSCT 8561 - Lab 5 - Task 1
# http_scanner.py
# Collects HTTP observations from known Juice Shop endpoints and saves them to CSV.
# This script only OBSERVES - it does not decide if anything is vulnerable.
# Target: my own local OWASP Juice Shop instance only.

import csv
import requests

BASE_URL = "http://localhost:3000"
TIMEOUT = 5
OUTPUT_FILE = "http_scan_results.csv"

FIELDS = ["endpoint", "method", "input", "status_code",
          "response_length", "content_type", "server", "error"]

# Each test case: (method, endpoint, input sent)
test_cases = [
    ("GET", "/", ""),
    ("GET", "/rest/products/search", "apple"),
    ("GET", "/rest/products/search", "banana"),
    ("GET", "/rest/products/search", "orange"),
    # POST to a path that is normally GET-only, just to record how the server reacts
    ("POST", "/rest/products/search", "apple"),
]


def send_request(method, endpoint, value):
    """Send one request and return a dictionary describing what happened."""
    url = BASE_URL + endpoint
    record = {
        "endpoint": endpoint,
        "method": method,
        "input": value if value else "(none)",
        "status_code": "",
        "response_length": "",
        "content_type": "",
        "server": "",
        "error": "",
    }

    try:
        if method == "GET":
            if value:
                response = requests.get(url, params={"q": value}, timeout=TIMEOUT)
            else:
                response = requests.get(url, timeout=TIMEOUT)
        else:
            response = requests.post(url, data={"q": value}, timeout=TIMEOUT)

        record["status_code"] = response.status_code
        record["response_length"] = len(response.content)
        record["content_type"] = response.headers.get("Content-Type", "(not set)")
        record["server"] = response.headers.get("Server", "(not set)")

    except requests.RequestException as error:
        # No HTTP response exists - log it and keep going
        record["error"] = type(error).__name__ + ": " + str(error)[:120]

    return record


def print_record(number, record):
    print("-" * 60)
    print(f"Request #{number}")
    print(f"  Method         : {record['method']}")
    print(f"  Endpoint       : {record['endpoint']}")
    print(f"  Input/payload  : {record['input']}")
    if record["error"]:
        print(f"  ERROR          : {record['error']}")
    else:
        print(f"  Status code    : {record['status_code']}")
        print(f"  Response length: {record['response_length']} bytes")
        print(f"  Content-Type   : {record['content_type']}")
        print(f"  Server header  : {record['server']}")


def save_csv(records):
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)


def main():
    print(f"HTTP scanner - target {BASE_URL} (timeout {TIMEOUT}s)")
    results = []

    for number, (method, endpoint, value) in enumerate(test_cases, start=1):
        record = send_request(method, endpoint, value)
        results.append(record)
        print_record(number, record)

    save_csv(results)

    failed = sum(1 for r in results if r["error"])
    print("=" * 60)
    print(f"{len(results)} requests sent, {failed} failed to connect.")
    print(f"Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
