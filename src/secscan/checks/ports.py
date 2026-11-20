"""TCP port scan of common service ports, with passive banner grabbing."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from secscan.checks.base import Check, ScanContext
from secscan.models import CheckResult, Finding, Severity

COMMON_PORTS: dict[int, str] = {
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

_DB = (
    Severity.HIGH,
    "A database service is reachable over the network.",
    "Bind the database to localhost or restrict access with a firewall.",
)

# Ports whose exposure is a finding in itself: (severity, description, recommendation)
RISKY_PORTS: dict[int, tuple[Severity, str, str]] = {
    21: (
        Severity.MEDIUM,
        "FTP sends credentials and data in cleartext.",
        "Disable FTP or replace it with SFTP/FTPS.",
    ),
    23: (
        Severity.HIGH,
        "Telnet sends everything, including passwords, in cleartext.",
        "Disable Telnet and use SSH instead.",
    ),
    445: (
        Severity.HIGH,
        "SMB exposed to the network is a frequent target for worms and ransomware.",
        "Block SMB at the firewall for untrusted networks.",
    ),
    3389: (
        Severity.HIGH,
        "Exposed RDP is a common brute-force and exploit target.",
        "Put RDP behind a VPN and enable Network Level Authentication.",
    ),
    5900: (
        Severity.HIGH,
        "VNC often has weak or no authentication and may be unencrypted.",
        "Restrict VNC to a VPN or SSH tunnel.",
    ),
    3306: _DB,
    5432: _DB,
    6379: _DB,
    27017: _DB,
}


def scan_port(address: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to address:port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((address, port)) == 0
    except OSError:
        return False


def grab_banner(address: str, port: int, timeout: float) -> str | None:
    """Return whatever the service sends on its own right after connecting, if anything."""
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            sock.settimeout(0.8)
            banner = sock.recv(256).decode(errors="replace").strip()
            return banner or None
    except OSError:
        return None


def findings_for_port(port: int, service: str) -> list[Finding]:
    if port not in RISKY_PORTS:
        return []
    severity, description, recommendation = RISKY_PORTS[port]
    return [
        Finding(
            id=f"PORT-EXPOSED-{port}",
            title=f"{service} exposed on port {port}",
            severity=severity,
            description=description,
            evidence=f"TCP port {port} accepted a connection.",
            recommendation=recommendation,
        )
    ]


class PortCheck(Check):
    name = "ports"
    title = "Open ports"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        ports = ctx.config.ports or COMMON_PORTS
        address = ctx.target.address
        workers = max(1, min(ctx.config.workers, len(ports)))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            is_open = pool.map(lambda p: scan_port(address, p, ctx.config.connect_timeout), ports)
            open_ports = sorted(p for p, ok in zip(ports, is_open, strict=True) if ok)
            banners = list(
                pool.map(lambda p: grab_banner(address, p, ctx.config.connect_timeout), open_ports)
            )

        result.data = {
            "scanned": len(ports),
            "open": [
                {"port": p, "service": ports.get(p, "Unknown"), "banner": b}
                for p, b in zip(open_ports, banners, strict=True)
            ],
        }
        for p in open_ports:
            result.findings.extend(findings_for_port(p, ports.get(p, "Unknown")))
        return result
