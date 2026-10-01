
import socket
import sys

try:
    import nmap
except ImportError:
    print("[!] python-nmap is not installed. Run: pip install python-nmap")
    sys.exit(1)

MAX_PORTS = 1000

# -sT : TCP Connect scan (same technique as scanner.py, no root needed)
# -sV : service / version detection
# -Pn : skip host discovery (localhost is always up)
NMAP_ARGS = "-sT -sV -Pn --reason"


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def read_port(prompt):
    value = input(prompt).strip()
    try:
        return int(value)
    except ValueError:
        print(f"[!] '{value}' is not a valid number.")
        return None


def validate_range(start_port, end_port):
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
    print(" FSCT 8561 - python-nmap Port Scanner")
    print("=" * 45)

    # 1. Target
    target = input("Target host: ").strip()
    if not target:
        print("[!] No target entered. Scan aborted.")
        return
    target_ip = resolve_target(target)
    if target_ip is None:
        print(f"[!] Unable to resolve '{target}'. Invalid hostname or IP address.")
        return

    # 2-3. Ports + validation
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

    # 4. Scan
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError:
        print("[!] Nmap executable not found. Install Nmap first.")
        return

    port_range = f"{start_port}-{end_port}"
    print(f"\nTarget: {target} ({target_ip})")
    print(f"Running: nmap {NMAP_ARGS} -p {port_range} {target_ip}\n")

    try:
        scanner.scan(target_ip, port_range, arguments=NMAP_ARGS)
    except nmap.PortScannerError as exc:
        print(f"[!] Nmap error: {exc}")
        return

    # 5-7. Results
    if target_ip not in scanner.all_hosts():
        print("[!] Host did not respond / no results returned.")
        return

    host = scanner[target_ip]
    print(f"Host state: {host.state()}")

    if "tcp" not in host.all_protocols() or not host["tcp"]:
        print("No interesting ports reported in the selected range.")
    else:
        print(f"\n{'PORT':<10}{'STATE':<12}{'SERVICE':<14}{'REASON':<12}VERSION")
        for port in sorted(host["tcp"].keys()):
            info = host["tcp"][port]
            version = " ".join(
                part for part in (info.get("product", ""),
                                  info.get("version", ""),
                                  info.get("extrainfo", "")) if part
            ) or "-"
            print(f"{port:<10}{info['state']:<12}{info['name'] or 'unknown':<14}"
                  f"{info.get('reason', ''):<12}{version}")

    stats = scanner.scanstats()
    open_count = sum(
        1 for p in host.get("tcp", {}).values() if p["state"] == "open"
    )
    print(f"\nScan complete in {stats.get('elapsed', '?')} s.")
    print(f"{open_count} open port(s) found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
