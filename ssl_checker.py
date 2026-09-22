"""
ssl_checker.py
Checks a host's SSL/TLS certificate: expiration, algorithm, protocol version.
Identifies common issues: expired certificate, self-signed, outdated protocol.
"""

import ssl
import socket
from datetime import datetime, timezone

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def check_ssl(host: str, port: int = 443, timeout: float = 5.0):
    """
    Connects to host:port via TLS and returns a report of the findings.
    Returns dict with: valid, expires_in_days, protocol, issuer, warnings[]
    """
    report = {
        "host": host,
        "port": port,
        "reachable": False,
        "protocol": None,
        "issuer": None,
        "expires_on": None,
        "expires_in_days": None,
        "warnings": [],
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                report["reachable"] = True
                report["protocol"] = ssock.version()
                cert = ssock.getpeercert()

                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                report["issuer"] = issuer_parts.get("organizationName") or issuer_parts.get("commonName")

                not_after = cert.get("notAfter")
                if not_after:
                    expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    report["expires_on"] = expire_date.strftime("%Y-%m-%d")
                    days_left = (expire_date - datetime.now(timezone.utc)).days
                    report["expires_in_days"] = days_left

                    if days_left < 0:
                        report["warnings"].append("Certificate has EXPIRED.")
                    elif days_left < 30:
                        report["warnings"].append(f"Certificate expires soon ({days_left} days).")

                if report["protocol"] in WEAK_PROTOCOLS:
                    report["warnings"].append(f"Outdated/insecure protocol: {report['protocol']}.")

    except ssl.SSLCertVerificationError as e:
        report["reachable"] = True
        report["warnings"].append(f"Certificate could not be verified (possibly self-signed or invalid): {e.reason}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        report["warnings"].append("Could not establish an HTTPS connection on this port (TLS may not be active).")
    except Exception as e:
        report["warnings"].append(f"Error during check: {e}")

    return report


if __name__ == "__main__":
    result = check_ssl("example.com", 443)
    print(f"Host: {result['host']}:{result['port']}")
    print(f"  Reachable: {result['reachable']}")
    print(f"  Protocol: {result['protocol']}")
    print(f"  Issuer: {result['issuer']}")
    print(f"  Expires: {result['expires_on']} ({result['expires_in_days']} days)")
    if result["warnings"]:
        print("  Warnings:")
        for w in result["warnings"]:
            print(f"    - {w}")
    else:
        print("  No issues found.")