"""
port_scanner.py
Scans a target (IP/hostname) for open TCP ports.
Uses threading for speed, and a "common" port list as default.

USAGE: only against systems you own or have written permission for.
"""

import socket
import concurrent.futures
from datetime import datetime

# Most common ports associated with critical services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def scan_port(host: str, port: int, timeout: float = 0.8):
    """Tries to connect to a single port. Returns True/False whether it's open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {host}")
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 1.0):
    """Attempts to grab the service 'banner' (version, type) if it sends one on its own."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            try:
                # some services send a banner automatically after connecting
                sock.settimeout(0.8)
                banner = sock.recv(256).decode(errors="ignore").strip()
                return banner if banner else None
            except socket.timeout:
                return None
    except Exception:
        return None


def scan_target(host: str, ports: dict = None, max_workers: int = 50, timeout: float = 0.8):
    """
    Scans a host for the given ports (default: COMMON_PORTS).
    Returns a list of dicts: {port, service_guess, open, banner}
    """
    ports = ports or COMMON_PORTS
    results = []

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning {host} — {len(ports)} ports...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
            except ValueError as e:
                print(f"Error: {e}")
                return []

            if is_open:
                banner = grab_banner(host, port)
                results.append({
                    "port": port,
                    "service_guess": ports.get(port, "Unknown"),
                    "open": True,
                    "banner": banner,
                })

    results.sort(key=lambda r: r["port"])
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Done. {len(results)} open ports found.")
    return results


if __name__ == "__main__":
    # Quick test against localhost
    findings = scan_target("127.0.0.1")
    for f in findings:
        print(f"  Port {f['port']:>5} ({f['service_guess']:<10}) — OPEN"
              + (f" — banner: {f['banner']}" if f["banner"] else ""))