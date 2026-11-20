"""HTTP security header check."""

from __future__ import annotations

import re

import requests

from secscan import __version__
from secscan.checks.base import Check, ScanContext
from secscan.models import CheckResult, Finding, Severity

# header -> (severity if missing, why it matters, recommended value)
SECURITY_HEADERS: dict[str, tuple[Severity, str, str]] = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "Without HSTS, browsers can be downgraded from HTTPS to HTTP.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Without a CSP, injected scripts (XSS) can run without restriction.",
        "Define a Content-Security-Policy that allows only trusted sources.",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "The page can be embedded in a foreign iframe (clickjacking).",
        "X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Browsers may MIME-sniff responses into an executable type.",
        "X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Full URLs may leak to other sites through the Referer header.",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Browser features such as camera, microphone and location are not restricted.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
}

DISCLOSURE_HEADERS = ("Server", "X-Powered-By")


def _slug(header: str) -> str:
    return header.upper().replace("-", "_")


class HeaderCheck(Check):
    name = "headers"
    title = "HTTP security headers"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        target = ctx.target
        scheme = target.scheme or "https"
        netloc = target.host if target.port is None else f"{target.host}:{target.port}"
        url = f"{scheme}://{netloc}/"

        try:
            resp = requests.get(
                url,
                timeout=ctx.config.timeout,
                allow_redirects=True,
                headers={"User-Agent": f"secscan/{__version__}"},
            )
        except requests.exceptions.SSLError:
            result.error = f"TLS error while connecting to {url} (see the TLS check)."
            return result
        except requests.exceptions.Timeout:
            result.error = f"Request to {url} timed out."
            return result
        except requests.exceptions.RequestException:
            result.error = f"Could not connect to {url}."
            return result

        headers = resp.headers
        present = [h for h in SECURITY_HEADERS if h in headers]
        missing = [h for h in SECURITY_HEADERS if h not in headers]
        result.data = {
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "present": {h: headers[h] for h in present},
            "missing": missing,
        }

        for header in missing:
            severity, why, recommended = SECURITY_HEADERS[header]
            result.findings.append(
                Finding(
                    id=f"HEADER-MISSING-{_slug(header)}",
                    title=f"Missing {header} header",
                    severity=severity,
                    description=why,
                    evidence=f"Not present in the response from {resp.url}",
                    recommendation=recommended,
                )
            )

        for header in DISCLOSURE_HEADERS:
            value = headers.get(header)
            if value:
                has_version = bool(re.search(r"\d", value))
                result.findings.append(
                    Finding(
                        id=f"HEADER-DISCLOSURE-{_slug(header)}",
                        title=f"{header} header discloses software"
                        + (" version" if has_version else ""),
                        severity=Severity.LOW if has_version else Severity.INFO,
                        description="Software and version details help attackers pick exploits.",
                        evidence=f"{header}: {value}",
                        recommendation=f"Remove the {header} header or strip the version from it.",
                    )
                )

        if resp.url.startswith("http://"):
            result.findings.append(
                Finding(
                    id="HTTP-NO-TLS",
                    title="Site is served over unencrypted HTTP",
                    severity=Severity.HIGH,
                    description="Traffic, including cookies and form data, can be read "
                    "and modified in transit.",
                    evidence=f"Final URL: {resp.url}",
                    recommendation="Serve the site over HTTPS and redirect all HTTP requests.",
                )
            )
        return result
