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

# Ports where a TLS service is expected; the TLS check inspects these when they are open.
TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 5986, 8443, 9443}

_EXTRA_NAMES = {
    20: "FTP-Data",
    69: "TFTP",
    88: "Kerberos",
    111: "RPC",
    135: "MSRPC",
    137: "NetBIOS-NS",
    139: "NetBIOS",
    161: "SNMP",
    389: "LDAP",
    514: "Syslog",
    873: "rsync",
    1723: "PPTP",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "HTTP-Alt",
    5000: "HTTP-Alt",
    5672: "AMQP",
    6443: "Kubernetes",
    8081: "HTTP-Alt",
    465: "SMTPS",
    587: "Submission",
    636: "LDAPS",
    853: "DNS-over-TLS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
    8000: "HTTP-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    9443: "HTTPS-Alt",
    11211: "Memcached",
}


class PortSpecError(ValueError):
    """Invalid --ports specification."""


def service_name(port: int) -> str:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    # A static table: socket.getservbyport is very slow on Windows for large ranges.
    return _EXTRA_NAMES.get(port, "Unknown")


def parse_port_spec(spec: str) -> dict[int, str]:
    """Parse e.g. "common", "1-1024", "22,80,8000-8100", "common,3000", "all"."""
    ports: set[int] = set()
    for part in (p.strip().lower() for p in spec.split(",")):
        if not part:
            continue
        if part in ("common", "default"):
            ports.update(COMMON_PORTS)
            continue
        if part == "all":
            ports.update(range(1, 65536))
            continue
        try:
            if "-" in part:
                lo_s, hi_s = part.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
            else:
                lo = hi = int(part)
        except ValueError:
            raise PortSpecError(f"invalid port or range: {part!r}") from None
        if not 1 <= lo <= hi <= 65535:
            raise PortSpecError(f"ports must be between 1 and 65535: {part!r}")
        ports.update(range(lo, hi + 1))
    if not ports:
        raise PortSpecError("no ports given")
    return {p: service_name(p) for p in sorted(ports)}


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
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
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
