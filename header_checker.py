"""
header_checker.py
Checks whether a website has the main HTTP security headers.
Missing headers reveal exposure to clickjacking, XSS, MIME-sniffing, etc.
"""

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against HTTPS->HTTP downgrade attacks (HSTS).",
    "Content-Security-Policy": "Restricts resources (scripts, images) that can be loaded — protects against XSS.",
    "X-Frame-Options": "Prevents clickjacking (page being loaded in a foreign iframe).",
    "X-Content-Type-Options": "Prevents MIME-sniffing (nosniff).",
    "Referrer-Policy": "Controls what information is sent to other sites as referrer.",
    "Permissions-Policy": "Restricts browser access to camera, microphone, location, etc.",
}


def check_headers(url: str, timeout: float = 6.0):
    """
    Makes a GET request to url and checks the security headers.
    Returns dict: {reachable, status_code, present[], missing[], server_banner, warnings[]}
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    report = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "present": [],
        "missing": [],
        "server_banner": None,
        "warnings": [],
    }

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        report["reachable"] = True
        report["status_code"] = resp.status_code
        headers = resp.headers

        for header, explanation in SECURITY_HEADERS.items():
            if header in headers:
                report["present"].append(header)
            else:
                report["missing"].append(header)
                report["warnings"].append(f"Missing '{header}' — {explanation}")

        # Server banner may reveal the version (info leakage)
        if "Server" in headers:
            report["server_banner"] = headers["Server"]
            report["warnings"].append(
                f"'Server' header reveals: '{headers['Server']}' — may help attackers target the version."
            )

        if url.startswith("http://"):
            report["warnings"].append("Website uses unencrypted HTTP, not HTTPS.")

    except requests.exceptions.SSLError:
        report["warnings"].append("SSL certificate error during connection.")
    except requests.exceptions.ConnectionError:
        report["warnings"].append("Could not connect to this URL.")
    except requests.exceptions.Timeout:
        report["warnings"].append("Request timed out.")
    except Exception as e:
        report["warnings"].append(f"Error: {e}")

    return report


if __name__ == "__main__":
    result = check_headers("https://github.com")
    print(f"URL: {result['url']} — Status: {result['status_code']}")
    print(f"Headers present: {result['present']}")
    print("Warnings:")
    for w in result["warnings"]:
        print(f"  - {w}")