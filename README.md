# secscan

[![CI](https://github.com/rzanaj07/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/rzanaj07/security-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A defensive security scanner for an initial audit of a host: it finds exposed services,
checks the TLS certificate and verifies HTTP security headers, then rates every issue by
severity in an HTML and/or JSON report.

## ⚠️ Legal notice: read before use

Use this tool **only** against:
- systems you own (server, VM, laptop), or
- systems whose owner has given you **written permission** (contract / rules of engagement).

Scanning systems without authorization is illegal in almost every country, even if the
intent is "just to learn" or "to help". secscan only observes; it does not exploit anything.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/rzanaj07/security-scanner.git
cd security-scanner
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
pip install -e .
```

## Usage

```bash
secscan example.com                         # all checks, HTML report report_example_com.html
secscan 192.168.1.10 -o client_report.html  # custom report name
secscan https://example.com --json out.json # HTML + JSON
secscan example.com --checks tls,headers    # only some checks
secscan example.com --fail-on high          # exit code 1 if any HIGH/CRITICAL finding (for CI)
python -m secscan --help                    # all options
```

| Exit code | Meaning |
|---|---|
| 0 | Scan finished (and `--fail-on` threshold not reached) |
| 1 | A finding at or above the `--fail-on` severity was found |
| 2 | Error: target could not be resolved, report could not be written |

## Checks

| Check | What it looks for |
|---|---|
| `ports` | 20 common service ports with passive banner grabbing; flags risky exposed services (Telnet, FTP, SMB, RDP, VNC, databases) |
| `tls` | Certificate trust, expiry (expired / < 30 days) and the negotiated protocol version |
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; version disclosure in `Server` / `X-Powered-By`; plain HTTP |

Every issue is reported as a **finding** with an ID, a severity (`critical`, `high`, `medium`,
`low`, `info`), evidence and a recommendation.

## Project structure

```
src/secscan/
├── cli.py               # command-line interface
├── scanner.py           # runs checks against a target
├── target.py            # parses and resolves the target
├── models.py            # Finding, CheckResult, ScanResult, Severity
├── checks/
│   ├── base.py          # Check interface, ScanConfig, ScanContext
│   ├── ports.py
│   ├── tls.py
│   └── headers.py
└── reporting/
    ├── html.py          # Jinja2, auto-escaped
    ├── json_report.py
    └── templates/report.html
tests/                   # pytest suite, uses local test servers only
```

### Adding a check

Subclass `Check`, set `name` and `title`, implement `run(ctx) -> CheckResult`, and register it
in `CHECKS` in `src/secscan/checks/__init__.py`. Results from earlier checks are available in
`ctx.results`.

## Development

```bash
pip install -e ".[dev]"
pytest              # tests
ruff check .        # lint
ruff format .       # format
mypy                # type check (strict)
```

CI runs all of the above on Python 3.10, 3.12 and 3.13 for every push and pull request.

## Roadmap

- **Phase 2:** probe every TLS version separately (detect TLS 1.0/1.1 support), certificate
  details for untrusted certs, TLS on all detected ports, HTTP to HTTPS redirect check, header
  value validation, cookie flags, custom port ranges, IPv6
- **Phase 3:** rich console output, risk score, PDF export, multi-target scans, CVE lookup from
  service banners (NVD), DNS / email security checks (SPF, DMARC, CAA)
- **Phase 4:** Docker image, PyPI release, scheduled scans with diffing, web dashboard

## License

[MIT](LICENSE)
