"""HTTP check: security headers and their values, HTTPS redirect, cookie flags, disclosure."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import requests

from secscan import __version__
from secscan.checks.base import Check, ScanContext
from secscan.models import CheckResult, Finding, Severity

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days

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
        Severity.INFO,
        "Modern browsers default to strict-origin-when-cross-origin, but an explicit policy "
        "protects older clients.",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Browser features such as camera, microphone and location are not restricted.",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
}

DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")
WEAK_REFERRER_POLICIES = {"unsafe-url", "no-referrer-when-downgrade"}


def _sentence(text: str) -> str:
    """Upper-case the first letter only (str.capitalize would lower-case the rest)."""
    return text[:1].upper() + text[1:] + "."


def _slug(text: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", text.upper()).strip("_")


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP header into {directive: [sources]} (first occurrence wins, per spec)."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def analyze_csp(value: str) -> list[Finding]:
    directives = parse_csp(value)
    script_src = directives.get("script-src", directives.get("default-src"))
    evidence = f"Content-Security-Policy: {value}"
    findings: list[Finding] = []
    if script_src is None:
        return [
            Finding(
                id="CSP-NO-SCRIPT-RESTRICTION",
                title="Content-Security-Policy does not restrict scripts",
                severity=Severity.MEDIUM,
                description="The policy has neither script-src nor default-src, so it does not "
                "protect against injected scripts.",
                evidence=evidence,
                recommendation="Add script-src (or default-src) with trusted sources only.",
            )
        ]
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_src
    )
    strict_dynamic = "'strict-dynamic'" in script_src
    if "'unsafe-inline'" in script_src and not (has_nonce_or_hash or strict_dynamic):
        findings.append(
            Finding(
                id="CSP-UNSAFE-INLINE",
                title="Content-Security-Policy allows inline scripts",
                severity=Severity.MEDIUM,
                description="'unsafe-inline' lets injected <script> tags run, which defeats most "
                "of the XSS protection a CSP provides.",
                evidence=evidence,
                recommendation="Remove 'unsafe-inline' and use nonces or hashes for inline code.",
            )
        )
    if "'unsafe-eval'" in script_src:
        findings.append(
            Finding(
                id="CSP-UNSAFE-EVAL",
                title="Content-Security-Policy allows eval()",
                severity=Severity.LOW,
                description="'unsafe-eval' allows strings to be executed as code.",
                evidence=evidence,
                recommendation="Remove 'unsafe-eval' and avoid eval()/new Function().",
            )
        )
    broad = [s for s in script_src if s in ("*", "http:", "https:", "data:", "blob:")]
    if broad and not strict_dynamic:
        findings.append(
            Finding(
                id="CSP-BROAD-SCRIPT-SOURCE",
                title="Content-Security-Policy allows scripts from anywhere",
                severity=Severity.MEDIUM,
                description="Sources like * or https: allow scripts from any host, so an "
                "attacker can load their own script.",
                evidence=evidence,
                recommendation="List specific trusted hosts, or use nonces with 'strict-dynamic'.",
            )
        )
    return findings


def analyze_hsts(value: str) -> list[Finding]:
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else None
    if max_age is not None and max_age >= HSTS_MIN_MAX_AGE:
        return []
    return [
        Finding(
            id="HSTS-WEAK",
            title="Strict-Transport-Security max-age is too short"
            if max_age is not None
            else "Strict-Transport-Security has no valid max-age",
            severity=Severity.LOW,
            description="A short or missing max-age leaves a large window for downgrade attacks"
            + (" (max-age=0 disables HSTS)." if max_age == 0 else "."),
            evidence=f"Strict-Transport-Security: {value}",
            recommendation="Use max-age=31536000 (one year) or more.",
        )
    ]


def parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    """Split a Set-Cookie header into (cookie name, {lowercased attribute: value})."""
    first, *attrs = header.split(";")
    name = first.split("=", 1)[0].strip()
    parsed: dict[str, str] = {}
    for attr in attrs:
        key, _, val = attr.strip().partition("=")
        if key:
            parsed[key.lower()] = val.strip()
    return name, parsed


def analyze_cookie(header: str, over_https: bool) -> tuple[dict[str, Any], Finding | None]:
    name, attrs = parse_set_cookie(header)
    secure, httponly = "secure" in attrs, "httponly" in attrs
    samesite = attrs.get("samesite")
    info = {"name": name, "secure": secure, "httponly": httponly, "samesite": samesite}

    problems: list[tuple[Severity, str]] = []
    if over_https and not secure:
        problems.append((Severity.MEDIUM, "no Secure flag (can be sent over plain HTTP)"))
    if not httponly:
        problems.append((Severity.LOW, "no HttpOnly flag (readable by JavaScript, e.g. via XSS)"))
    if samesite is None:
        problems.append((Severity.LOW, "no SameSite attribute (weaker CSRF protection)"))
    elif samesite.lower() == "none" and not secure:
        problems.append((Severity.MEDIUM, "SameSite=None without Secure (rejected by browsers)"))
    if not problems:
        return info, None

    severity = max((p[0] for p in problems), key=lambda s: s.rank)
    finding = Finding(
        id=f"COOKIE-FLAGS:{name}",
        title=f"Cookie '{name}' is missing security attributes",
        severity=severity,
        description=_sentence("; ".join(p[1] for p in problems)),
        evidence=f"Set-Cookie: {header}",
        recommendation="Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies. "
        "Leave out HttpOnly only for cookies JavaScript must read.",
    )
    return info, finding


def _set_cookie_headers(resp: requests.Response) -> list[str]:
    raw_headers = getattr(resp.raw, "headers", None)
    getlist = getattr(raw_headers, "getlist", None)
    if callable(getlist):
        return [str(h) for h in getlist("Set-Cookie")]
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


def check_https_redirect(
    session: requests.Session, http_url: str, timeout: float, max_hops: int = 10
) -> tuple[str, str | None]:
    """Follow redirects from the plain-HTTP URL hop by hop. Returns (status, last URL);
    status is "redirects" (reaches an https:// URL), "no-redirect" or "unreachable"."""
    url = http_url
    for _ in range(max_hops):
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            return ("unreachable" if url == http_url else "no-redirect"), url
        location = resp.headers.get("Location")
        if not (resp.is_redirect and location):
            return "no-redirect", url
        url = urljoin(url, location)
        if url.startswith("https://"):
            return "redirects", url
    return "no-redirect", url


class HeaderCheck(Check):
    name = "headers"
    title = "HTTP security"

    def run(self, ctx: ScanContext) -> CheckResult:
        result = self.result()
        target = ctx.target
        timeout = ctx.config.timeout
        netloc = target.netloc(target.port)
        session = requests.Session()
        session.headers["User-Agent"] = f"secscan/{__version__}"

        schemes = [target.scheme] if target.scheme else ["https", "http"]
        resp: requests.Response | None = None
        failures: list[str] = []
        for scheme in schemes:
            url = f"{scheme}://{netloc}/"
            try:
                resp = session.get(url, timeout=timeout, allow_redirects=True)
                break
            except requests.exceptions.SSLError:
                failures.append(f"TLS error at {url}")
            except requests.exceptions.Timeout:
                failures.append(f"timeout at {url}")
            except requests.exceptions.RequestException:
                failures.append(f"could not connect to {url}")
        if resp is None:
            result.error = _sentence("; ".join(failures))
            return result
        if failures:
            result.notes.append("HTTPS failed (" + "; ".join(failures) + "), tested HTTP instead.")

        over_https = resp.url.startswith("https://")
        headers = resp.headers
        present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
        csp_value = headers.get("Content-Security-Policy")
        frame_ancestors = csp_value is not None and "frame-ancestors" in parse_csp(csp_value)

        for header, (severity, why, recommended) in SECURITY_HEADERS.items():
            if header in present:
                continue
            if header == "Strict-Transport-Security" and not over_https:
                continue  # HSTS is ignored on HTTP; HTTP-NO-TLS covers this case
            if header == "X-Frame-Options" and frame_ancestors:
                continue  # CSP frame-ancestors supersedes X-Frame-Options
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

        # Values of headers that are present
        if over_https and "Strict-Transport-Security" in present:
            result.findings.extend(analyze_hsts(present["Strict-Transport-Security"]))
        if csp_value:
            result.findings.extend(analyze_csp(csp_value))
        elif "Content-Security-Policy-Report-Only" in headers:
            result.notes.append("A CSP is only in report-only mode, so it is not enforced.")
        xfo = present.get("X-Frame-Options")
        if xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN") and not frame_ancestors:
            result.findings.append(
                Finding(
                    id="HEADER-INVALID-X_FRAME_OPTIONS",
                    title="X-Frame-Options has an ineffective value",
                    severity=Severity.LOW,
                    description="Only DENY and SAMEORIGIN are supported by current browsers "
                    "(ALLOW-FROM is ignored).",
                    evidence=f"X-Frame-Options: {xfo}",
                    recommendation="Use DENY or SAMEORIGIN, or CSP frame-ancestors.",
                )
            )
        xcto = present.get("X-Content-Type-Options")
        if xcto and xcto.strip().lower() != "nosniff":
            result.findings.append(
                Finding(
                    id="HEADER-INVALID-X_CONTENT_TYPE_OPTIONS",
                    title="X-Content-Type-Options has an invalid value",
                    severity=Severity.LOW,
                    description="The only valid value is nosniff; anything else is ignored.",
                    evidence=f"X-Content-Type-Options: {xcto}",
                    recommendation="X-Content-Type-Options: nosniff",
                )
            )
        referrer = present.get("Referrer-Policy")
        if referrer:
            policies = {p.strip().lower() for p in referrer.split(",")}
            weak = sorted(policies & WEAK_REFERRER_POLICIES)
            if weak:
                result.findings.append(
                    Finding(
                        id="HEADER-WEAK-REFERRER_POLICY",
                        title="Referrer-Policy leaks full URLs",
                        severity=Severity.LOW,
                        description=f"'{weak[0]}' sends the full URL, including paths and query "
                        "strings, to other sites.",
                        evidence=f"Referrer-Policy: {referrer}",
                        recommendation="Referrer-Policy: strict-origin-when-cross-origin",
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

        # Cookies set anywhere along the redirect chain
        cookies: list[dict[str, Any]] = []
        seen: set[str] = set()
        for r in [*resp.history, resp]:
            for header in _set_cookie_headers(r):
                info, finding = analyze_cookie(header, r.url.startswith("https://"))
                if info["name"] in seen:
                    continue
                seen.add(info["name"])
                cookies.append(info)
                if finding:
                    result.findings.append(finding)

        # Plain HTTP
        redirect_status, redirect_url = None, None
        if not over_https:
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
        elif target.port is None:
            redirect_status, redirect_url = check_https_redirect(
                session, f"http://{netloc}/", timeout
            )
            if redirect_status == "no-redirect":
                result.findings.append(
                    Finding(
                        id="HTTP-NO-HTTPS-REDIRECT",
                        title="HTTP version of the site does not redirect to HTTPS",
                        severity=Severity.MEDIUM,
                        description="Visitors who type the address or follow an http:// link "
                        "use an unencrypted connection.",
                        evidence=f"http://{netloc}/ ended at {redirect_url}",
                        recommendation="Redirect all HTTP requests to HTTPS with a 301 and "
                        "enable HSTS.",
                    )
                )

        result.data = {
            "url": resp.history[0].url if resp.history else resp.url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "redirects": [r.url for r in resp.history],
            "present": present,
            "missing": [h for h in SECURITY_HEADERS if h not in present],
            "cookies": cookies,
            "http_redirect": redirect_status,
        }
        return result
