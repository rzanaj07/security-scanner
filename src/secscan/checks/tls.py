"""TLS certificate and protocol check."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import certifi

from secscan.checks.base import Check, ScanContext
from secscan.models import CheckResult, Finding, Severity

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARNING_DAYS = 30


def _name_field(rdns: Any, *keys: str) -> str | None:
    """Pick the first matching attribute from a certificate subject/issuer."""
    parts = {k: v for rdn in rdns or () for k, v in rdn}
    for key in keys:
        if parts.get(key):
            return str(parts[key])
    return None


def fetch_tls_info(address: str, host: str, port: int, timeout: float) -> dict[str, Any]:
    """Perform a verified TLS handshake and collect protocol and certificate details."""
    info: dict[str, Any] = {
        "port": port,
        "reachable": False,
        "protocol": None,
        "issuer": None,
        "subject": None,
        "not_after": None,
        "verify_error": None,
        "error": None,
    }
    # Use the same CA bundle as `requests` so results do not depend on the OS trust store.
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with (
            socket.create_connection((address, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            info["reachable"] = True
            info["protocol"] = ssock.version()
            cert = ssock.getpeercert() or {}
            info["issuer"] = _name_field(cert.get("issuer"), "organizationName", "commonName")
            info["subject"] = _name_field(cert.get("subject"), "commonName")
            not_after = cert.get("notAfter")
            if isinstance(not_after, str):
                ts = ssl.cert_time_to_seconds(not_after)
                info["not_after"] = datetime.fromtimestamp(ts, tz=timezone.utc)
    except ssl.SSLCertVerificationError as e:
        info["reachable"] = True
        info["verify_error"] = e.verify_message or str(e)
    except OSError as e:  # includes ssl.SSLError, timeouts and refused connections
        info["error"] = str(e) or type(e).__name__
    return info


def evaluate(info: dict[str, Any], now: datetime) -> list[Finding]:
    """Turn collected TLS details into findings. Pure function, easy to test."""
    findings: list[Finding] = []
    port = info["port"]

    if info["verify_error"]:
        findings.append(
            Finding(
                id="TLS-CERT-UNTRUSTED",
                title="TLS certificate could not be verified",
                severity=Severity.HIGH,
                description="Browsers will warn visitors; the certificate may be self-signed, "
                "issued for another name, or have an incomplete chain.",
                evidence=f"Port {port}: {info['verify_error']}",
                recommendation="Install a certificate from a trusted CA that matches the hostname, "
                "with the full intermediate chain.",
            )
        )

    not_after = info["not_after"]
    if isinstance(not_after, datetime):
        days_left = (not_after - now).days
        evidence = f"Port {port}: valid until {not_after:%Y-%m-%d}"
        if days_left < 0:
            findings.append(
                Finding(
                    id="TLS-CERT-EXPIRED",
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    description="Clients will reject the connection or show a security warning.",
                    evidence=evidence,
                    recommendation="Renew the certificate now and automate renewal (e.g. ACME).",
                )
            )
        elif days_left < EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    id="TLS-CERT-EXPIRING",
                    title=f"TLS certificate expires in {days_left} days",
                    severity=Severity.MEDIUM,
                    description="The certificate will expire soon.",
                    evidence=evidence,
                    recommendation="Renew the certificate and automate renewal (e.g. ACME).",
                )
            )

    if info["protocol"] in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                id="TLS-WEAK-PROTOCOL",
                title=f"Outdated protocol negotiated: {info['protocol']}",
                severity=Severity.HIGH,
                description="SSLv2/3 and TLS 1.0/1.1 have known weaknesses and are deprecated.",
                evidence=f"Port {port}: negotiated {info['protocol']}",
                recommendation="Allow only TLS 1.2 and TLS 1.3.",
            )
        )
    return findings


class TLSCheck(Check):
    name = "tls"
    title = "TLS certificate"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        target = ctx.target
        port = target.port if target.scheme == "https" and target.port else 443

        info = fetch_tls_info(target.address, target.host, port, ctx.config.timeout)
        result.findings = evaluate(info, datetime.now(timezone.utc))
        if isinstance(info["not_after"], datetime):
            info["not_after"] = info["not_after"].strftime("%Y-%m-%d")
        if not info["reachable"]:
            result.notes.append(f"No TLS service answered on port {port}.")
        result.data = info
        return result
