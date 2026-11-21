"""TLS check: protocol versions, weak ciphers, certificate trust and quality, on every TLS port."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from secscan.checks.base import Check, ScanContext
from secscan.checks.ports import TLS_PORTS
from secscan.models import CheckResult, Finding, Severity

EXPIRY_WARNING_DAYS = 30
MIN_RSA_BITS = 2048
MIN_EC_BITS = 224

# Protocol versions probed one at a time. A server should accept only TLS 1.2 and 1.3.
PROTOCOLS: list[tuple[str, ssl.TLSVersion]] = [
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]
DEPRECATED = {"SSLv3": Severity.HIGH, "TLSv1": Severity.MEDIUM, "TLSv1.1": Severity.MEDIUM}
WEAK_CIPHERS = "RC4:3DES:DES:NULL:EXPORT:aNULL:eNULL:MD5:@SECLEVEL=0"

# OpenSSL errors that mean *this machine* cannot attempt the handshake (so: untested).
_LOCAL_LIMITS = {"NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_CIPHER_MATCH"}

# X509 verification error codes worth naming specifically.
_SELF_SIGNED_CODES = {18, 19}  # self-signed leaf / self-signed cert in chain
_HOSTNAME_MISMATCH = 62
_EXPIRED = 10

SUPPORTED, REJECTED, UNTESTED, ERROR = "supported", "rejected", "untested", "error"


def _permissive_context() -> ssl.SSLContext:
    """No verification and legacy algorithms allowed: used to observe, not to trust."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        # Python defaults to TLS 1.2+; go lower so legacy-only servers are still reachable.
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def _handshake(
    ctx: ssl.SSLContext, address: str, host: str, port: int, timeout: float
) -> tuple[str | None, str | None, bytes | None]:
    """Connect and handshake. Returns (protocol, cipher, DER certificate)."""
    with (
        socket.create_connection((address, port), timeout=timeout) as sock,
        ctx.wrap_socket(sock, server_hostname=host) as ssock,
    ):
        cipher = ssock.cipher()
        return ssock.version(), cipher[0] if cipher else None, ssock.getpeercert(binary_form=True)


def probe_protocol(
    address: str, host: str, port: int, version: ssl.TLSVersion, timeout: float
) -> str:
    """Does the server accept exactly this protocol version?"""
    ctx = _permissive_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return UNTESTED
    try:
        _handshake(ctx, address, host, port, timeout)
        return SUPPORTED
    except ssl.SSLError as e:
        return UNTESTED if e.reason in _LOCAL_LIMITS else REJECTED
    except ConnectionResetError:
        return REJECTED  # many servers drop the connection on an unsupported hello
    except OSError:
        return ERROR


def probe_weak_ciphers(
    address: str, host: str, port: int, timeout: float
) -> tuple[str, str | None]:
    """Does the server accept any broken cipher (RC4, DES/3DES, NULL, EXPORT, anonymous)?"""
    ctx = _permissive_context()
    try:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 has no weak suites
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers(WEAK_CIPHERS)
    except (ValueError, ssl.SSLError):
        return UNTESTED, None
    try:
        _proto, cipher, _cert = _handshake(ctx, address, host, port, timeout)
        return SUPPORTED, cipher
    except ssl.SSLError as e:
        return (UNTESTED if e.reason in _LOCAL_LIMITS else REJECTED), None
    except ConnectionResetError:
        return REJECTED, None
    except OSError:
        return ERROR, None


def verify_chain(address: str, host: str, port: int, timeout: float) -> tuple[int | None, str]:
    """Verify the certificate like a browser would. Returns (error code or None, message)."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    try:
        _handshake(ctx, address, host, port, timeout)
        return None, "trusted"
    except ssl.SSLCertVerificationError as e:
        return e.verify_code, e.verify_message or str(e)
    except (ssl.SSLError, OSError) as e:
        # e.g. the server only speaks protocols a modern client refuses
        return -1, f"verification handshake failed: {getattr(e, 'reason', None) or e}"


def _name(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def parse_certificate(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []

    key = cert.public_key()
    key_bits: int | None
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = f"EC {key.curve.name}", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, key_bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, key_bits = "Ed448", 456
    else:
        key_type, key_bits = type(key).__name__, None

    sig_hash = cert.signature_hash_algorithm
    return {
        "subject": _name(cert.subject, NameOID.COMMON_NAME),
        "issuer": _name(cert.issuer, NameOID.ORGANIZATION_NAME)
        or _name(cert.issuer, NameOID.COMMON_NAME),
        "sans": sans,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature": sig_hash.name if sig_hash else None,
        "self_signed": cert.issuer == cert.subject,
        "serial": format(cert.serial_number, "x"),
    }


def analyze_endpoint(address: str, host: str, port: int, timeout: float) -> dict[str, Any]:
    """Collect everything about one TLS endpoint. Datetimes stay as datetime objects."""
    ep: dict[str, Any] = {
        "port": port,
        "reachable": False,
        "error": None,
        "protocol": None,
        "cipher": None,
        "protocols": {},
        "weak_cipher": None,
        "weak_cipher_name": None,
        "certificate": None,
        "verify_code": None,
        "verification": None,
    }
    try:
        ep["protocol"], ep["cipher"], der = _handshake(
            _permissive_context(), address, host, port, timeout
        )
    except (ssl.SSLError, OSError) as e:
        ep["error"] = str(getattr(e, "reason", None) or e) or type(e).__name__
        return ep
    ep["reachable"] = True
    if der:
        try:
            ep["certificate"] = parse_certificate(der)
        except ValueError as e:
            ep["error"] = f"could not parse certificate: {e}"

    with ThreadPoolExecutor(max_workers=len(PROTOCOLS) + 2) as pool:
        protocol_futures = {
            name: pool.submit(probe_protocol, address, host, port, version, timeout)
            for name, version in PROTOCOLS
        }
        weak_future = pool.submit(probe_weak_ciphers, address, host, port, timeout)
        verify_future = pool.submit(verify_chain, address, host, port, timeout)
        ep["protocols"] = {name: f.result() for name, f in protocol_futures.items()}
        ep["weak_cipher"], ep["weak_cipher_name"] = weak_future.result()
        ep["verify_code"], ep["verification"] = verify_future.result()
    return ep


def evaluate(ep: dict[str, Any], now: datetime, host_is_ip: bool = False) -> list[Finding]:
    """Turn one endpoint's details into findings. Pure function, easy to test."""
    if not ep["reachable"]:
        return []
    port = ep["port"]
    findings: list[Finding] = []

    def add(fid: str, title: str, severity: Severity, **kw: Any) -> None:
        findings.append(Finding(id=f"{fid}:{port}", title=title, severity=severity, **kw))

    code, message = ep["verify_code"], ep["verification"]
    if code is not None and code != _EXPIRED:  # expiry is reported below with the date
        if code in _SELF_SIGNED_CODES:
            add(
                "TLS-CERT-SELF-SIGNED",
                f"Self-signed TLS certificate on port {port}",
                Severity.HIGH,
                description="Browsers and clients will not trust it, and users learn to click "
                "through warnings, which enables interception.",
                evidence=f"Port {port}: {message}",
                recommendation="Use a certificate from a trusted CA (e.g. Let's Encrypt).",
            )
        elif code == _HOSTNAME_MISMATCH:
            ip_note = (
                " The target was scanned by IP address, so a mismatch is expected."
                if host_is_ip
                else ""
            )
            add(
                "TLS-CERT-HOSTNAME-MISMATCH",
                f"TLS certificate does not match the host name (port {port})",
                Severity.INFO if host_is_ip else Severity.HIGH,
                description="The certificate was issued for other names; clients will reject it."
                + ip_note,
                evidence=f"Port {port}: {message}",
                recommendation="Issue a certificate that lists this host name.",
            )
        elif code != -1:
            add(
                "TLS-CERT-UNTRUSTED",
                f"TLS certificate is not trusted (port {port})",
                Severity.HIGH,
                description="The chain does not lead to a trusted CA, or a required "
                "intermediate certificate is missing.",
                evidence=f"Port {port}: {message}",
                recommendation="Install a certificate from a trusted CA with its full "
                "intermediate chain.",
            )

    cert = ep["certificate"]
    if cert:
        not_after, not_before = cert["not_after"], cert["not_before"]
        days_left = (not_after - now).days
        validity = f"Port {port}: valid {not_before:%Y-%m-%d} to {not_after:%Y-%m-%d}"
        if days_left < 0:
            add(
                "TLS-CERT-EXPIRED",
                f"TLS certificate expired {-days_left} days ago (port {port})",
                Severity.HIGH,
                description="Clients reject the connection or show a security warning.",
                evidence=validity,
                recommendation="Renew the certificate now and automate renewal (e.g. ACME).",
            )
        elif days_left < EXPIRY_WARNING_DAYS:
            add(
                "TLS-CERT-EXPIRING",
                f"TLS certificate expires in {days_left} days (port {port})",
                Severity.MEDIUM,
                description="The certificate will expire soon.",
                evidence=validity,
                recommendation="Renew the certificate and automate renewal (e.g. ACME).",
            )
        if not_before > now:
            add(
                "TLS-CERT-NOT-YET-VALID",
                f"TLS certificate is not valid yet (port {port})",
                Severity.MEDIUM,
                evidence=validity,
                recommendation="Check the server clock and the certificate dates.",
            )

        bits, key_type = cert["key_bits"], cert["key_type"]
        weak_key = bits is not None and (
            (key_type in ("RSA", "DSA") and bits < MIN_RSA_BITS)
            or (key_type.startswith("EC") and bits < MIN_EC_BITS)
        )
        if weak_key:
            add(
                "TLS-WEAK-KEY",
                f"Weak {key_type} key of {bits} bits (port {port})",
                Severity.HIGH,
                description="Short keys can be broken with practical effort.",
                evidence=f"Port {port}: {key_type} {bits} bits",
                recommendation=f"Use RSA {MIN_RSA_BITS}+ bits or an EC key (P-256 or better).",
            )
        if cert["signature"] in ("md5", "sha1"):
            add(
                "TLS-WEAK-SIGNATURE",
                f"Certificate signed with {cert['signature'].upper()} (port {port})",
                Severity.MEDIUM,
                description="MD5 and SHA-1 signatures are vulnerable to collision attacks.",
                evidence=f"Port {port}: signature hash {cert['signature']}",
                recommendation="Reissue the certificate with a SHA-256 (or stronger) signature.",
            )

    supported_old = [p for p in DEPRECATED if ep["protocols"].get(p) == SUPPORTED]
    if supported_old:
        severity = max((DEPRECATED[p] for p in supported_old), key=lambda s: s.rank)
        add(
            "TLS-DEPRECATED-PROTOCOL",
            f"Deprecated protocol accepted on port {port}: {', '.join(supported_old)}",
            severity,
            description="SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses (POODLE, BEAST) "
            "and are deprecated by RFC 8996.",
            evidence=f"Port {port}: handshake succeeded with {', '.join(supported_old)}",
            recommendation="Allow only TLS 1.2 and TLS 1.3.",
        )
    modern = [ep["protocols"].get(p) for p in ("TLSv1.2", "TLSv1.3")]
    if all(status == REJECTED for status in modern):
        add(
            "TLS-NO-MODERN-PROTOCOL",
            f"Neither TLS 1.2 nor TLS 1.3 is supported (port {port})",
            Severity.HIGH,
            description="Modern clients refuse to connect.",
            recommendation="Enable TLS 1.2 and TLS 1.3.",
        )
    if ep["weak_cipher"] == SUPPORTED:
        add(
            "TLS-WEAK-CIPHER",
            f"Broken cipher suite accepted on port {port}",
            Severity.HIGH,
            description="RC4, DES/3DES, NULL, EXPORT and anonymous suites can be decrypted "
            "or allow man-in-the-middle attacks.",
            evidence=f"Port {port}: negotiated {ep['weak_cipher_name']}",
            recommendation="Allow only AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE.",
        )
    return findings


def _serializable(ep: dict[str, Any]) -> dict[str, Any]:
    out = dict(ep)
    if ep["certificate"]:
        cert = dict(ep["certificate"])
        cert["not_before"] = cert["not_before"].strftime("%Y-%m-%d")
        cert["not_after"] = cert["not_after"].strftime("%Y-%m-%d")
        out["certificate"] = cert
    return out


def tls_ports_for(ctx: ScanContext) -> list[int]:
    """Which ports to inspect: the target's own HTTPS port, plus open TLS ports found."""
    target = ctx.target
    ports: set[int] = set()
    if target.port is not None and target.scheme != "http":
        ports.add(target.port)
    port_result = ctx.results.get("ports")
    if port_result is not None and not port_result.error and "open" in port_result.data:
        ports.update(p["port"] for p in port_result.data["open"] if p["port"] in TLS_PORTS)
    elif not ports:
        ports.add(443)  # port scan not run: try the default HTTPS port
    return sorted(ports)


class TLSCheck(Check):
    name = "tls"
    title = "TLS"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        target = ctx.target
        ports = tls_ports_for(ctx)
        if not ports:
            result.notes.append("No open TLS ports were found by the port scan.")
            result.data = {"endpoints": []}
            return result

        now = datetime.now(timezone.utc)
        endpoints = [
            analyze_endpoint(target.address, target.host, p, ctx.config.timeout) for p in ports
        ]
        for ep in endpoints:
            result.findings.extend(evaluate(ep, now, target.host_is_ip))
            if not ep["reachable"]:
                result.notes.append(f"No TLS service answered on port {ep['port']}.")
        untested = sorted(
            {p for ep in endpoints for p, st in ep["protocols"].items() if st == UNTESTED}
        )
        if untested:
            result.notes.append(
                f"This machine's OpenSSL cannot test {', '.join(untested)}; "
                "those results are unknown."
            )
        result.data = {"endpoints": [_serializable(ep) for ep in endpoints]}
        return result
