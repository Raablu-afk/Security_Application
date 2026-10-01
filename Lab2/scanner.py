
import socket
import time

TIMEOUT = 0.5          # seconds per connection attempt
MAX_PORTS = 1000       # maximum (end - start) allowed in one run


def scan_port(target, port):
    """Attempt one TCP connection. Return True if the port accepted it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        result = sock.connect_ex((target, port))
    except (socket.timeout, OSError):
        # Timeout or other socket error -> no successful connection
        result = -1
    finally:
        sock.close()  # every socket is closed, success or failure

    return result == 0


def get_service(port):
    """Return the likely service name for a TCP port, or 'unknown'."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def resolve_target(target):
    """Resolve a hostname / IPv4 address. Return the IP or None."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def read_port(prompt):
    """Read an integer port number. Return the int or None if not numeric."""
    value = input(prompt).strip()
    try:
        return int(value)
    except ValueError:
        print(f"[!] '{value}' is not a valid number.")
        return None


def validate_range(start_port, end_port):
    """Return an error message if the range is invalid, else None."""
    if not 1 <= start_port <= 65535:
        return "Start port must be between 1 and 65535."
    if not 1 <= end_port <= 65535:
        return "End port must be between 1 and 65535."
    if start_port > end_port:
        return "Start port must be less than or equal to end port."
    if end_port - start_port > MAX_PORTS:
        return f"Range too large: maximum of {MAX_PORTS} ports per scan."
    return None


def main():
    print("=" * 45)
    print(" FSCT 8561 - TCP Connect Port Scanner")
    print("=" * 45)

    # 1-2. Target + resolution
    target = input("Target host: ").strip()
    if not target:
        print("[!] No target entered. Scan aborted.")
        return

    target_ip = resolve_target(target)
    if target_ip is None:
        print(f"[!] Unable to resolve '{target}'. Invalid hostname or IP address.")
        return

    # 3-4. Port range + validation
    start_port = read_port("Start port: ")
    if start_port is None:
        return
    end_port = read_port("End port: ")
    if end_port is None:
        return

    error = validate_range(start_port, end_port)
    if error:
        print(f"[!] {error} Scan aborted.")
        return

    # 5-7. Scan
    print(f"\nTarget: {target} ({target_ip})")
    print(f"Scanning TCP ports {start_port}-{end_port}...\n")

    open_ports = []
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        if scan_port(target_ip, port):
            open_ports.append(port)

    elapsed = time.time() - start_time

    # 8. Report
    if open_ports:
        print(f"{'PORT':<10}{'STATE':<11}SERVICE")
        for port in open_ports:
            print(f"{port:<10}{'open':<11}{get_service(port)}")
    else:
        print("No open ports found in the selected range.")

    not_open = (end_port - start_port + 1) - len(open_ports)
    print(f"\nScan complete in {elapsed:.2f} s.")
    print(f"{len(open_ports)} open port(s) found. "
          f"{not_open} port(s) gave no successful connection.")
    print(f"Open ports: {open_ports}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
