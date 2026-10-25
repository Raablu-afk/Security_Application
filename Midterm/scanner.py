# TCP port scanner (based on Lab 2 scanner.py and nmap_scanner.py)
import socket

TIMEOUT = 0.5                            # seconds per connection attempt
MAX_PORTS = 1000                         # maximum (end - start) allowed in one run
ALLOWED_TARGETS = ("127.0.0.1", "localhost")   # only scan our own machine


def scan_port(target, port):
    """Attempt one TCP connection. Return True if the port accepted it."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        result = sock.connect_ex((target, port))
    except (socket.timeout, OSError):
        result = -1
    finally:
        sock.close()
    return result == 0


def get_service(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


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


def check_target(target, start_port, end_port):
    if target not in ALLOWED_TARGETS:
        return f"Target '{target}' is not authorized. Allowed: {', '.join(ALLOWED_TARGETS)}"
    return validate_range(start_port, end_port)


def scan(target, start_port, end_port):
    """Return the list of open ports. Raises ValueError for bad input."""
    error = check_target(target, start_port, end_port)
    if error:
        raise ValueError(error)
    ip = socket.gethostbyname(target)
    return [port for port in range(start_port, end_port + 1) if scan_port(ip, port)]


def nmap_scan(target, start_port, end_port):
    """Same scan with python-nmap (-sT = TCP connect). Needs nmap installed."""
    error = check_target(target, start_port, end_port)
    if error:
        raise ValueError(error)
    import nmap
    ip = socket.gethostbyname(target)
    scanner = nmap.PortScanner()
    scanner.scan(ip, f"{start_port}-{end_port}", arguments="-sT -Pn")
    if ip not in scanner.all_hosts():
        return []
    ports = scanner[ip].get("tcp", {})
    return sorted(p for p, info in ports.items() if info["state"] == "open")
