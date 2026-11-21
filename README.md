# secscan

[![CI](https://github.com/rzanaj07/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/rzanaj07/security-scanner/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A defensive security scanner for an initial audit of a host: it finds exposed services,
checks the TLS certificate and verifies HTTP security headers, rates every issue by severity
and gives the host a security score (0-100, grade A-F).

Use it from the command line, or run the **local web dashboard** to start scans from the
browser, follow them live, keep a history per target and see what changed since the last scan.

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

## Web dashboard

```bash
secscan serve            # opens http://127.0.0.1:8000 in your browser
secscan serve --port 9000 --no-browser --db ./scans.db
```

- Start scans from a form (an authorization confirmation is required for every scan)
- Live progress while checks run; scans continue in the background
- Every scan is stored in SQLite (default `~/.secscan/scans.db`)
- Per-target security score with trend, and **new / fixed findings** compared with the
  previous scan
- Export any scan as an HTML or JSON report
- REST API with interactive docs at `/api/docs`

The dashboard has no login, so it listens on `127.0.0.1` only by default. It rejects requests
for foreign hostnames (DNS-rebinding protection), sends strict security headers and renders
all scanned data as text, never as markup. Use `--host 0.0.0.0` only on a trusted network.

> If Windows blocks `secscan.exe` (e.g. by an Application Control policy), run
> `python -m secscan ...` instead; it is the same program.

## Command line

```bash
secscan example.com                         # all checks, HTML report report_example_com.html
secscan 192.168.1.10 -o client_report.html  # custom report name
secscan https://example.com --json out.json # HTML + JSON
secscan example.com --checks tls,headers    # only some checks
secscan 10.0.0.5 --ports 1-1024             # custom ports: 1-1024, 22,80,8000-8100, common,3000, all
secscan ::1                                 # IPv6 works too
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
| `ports` | Common service ports (or your own list/range) with banner grabbing; flags risky exposed services (Telnet, FTP, SMB, RDP, VNC, databases). IPv4 and IPv6. |
| `tls` | Runs on every open TLS port (443, 8443, 993, 995, 465, 636, ...). Probes SSLv3 and TLS 1.0, 1.1, 1.2 and 1.3 one by one, probes for broken ciphers (RC4, 3DES, NULL, EXPORT), verifies trust like a browser (self-signed, hostname mismatch, untrusted chain) and inspects the certificate: expiry, names, key type/size, signature algorithm. |
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, **including their values** (short HSTS max-age, CSP `unsafe-inline`/`unsafe-eval`/wildcards, invalid values); HTTP to HTTPS redirect; cookie flags (Secure, HttpOnly, SameSite); version disclosure (`Server`, `X-Powered-By`, ...); falls back to HTTP when HTTPS is not available. |

Every issue is reported as a **finding** with an ID, a severity (`critical`, `high`, `medium`,
`low`, `info`), evidence and a recommendation.

## Project structure

```
src/secscan/
├── cli.py               # command-line interface (`secscan`, `secscan serve`)
├── scanner.py           # runs checks against a target
├── target.py            # parses and resolves the target
├── models.py            # Finding, CheckResult, ScanResult, Severity, score
├── store.py             # SQLite scan history
├── checks/
│   ├── base.py          # Check interface, ScanConfig, ScanContext
│   ├── ports.py
│   ├── tls.py
│   └── headers.py
├── reporting/
│   ├── html.py          # Jinja2, auto-escaped
│   ├── json_report.py
│   └── templates/report.html
└── web/
    ├── app.py           # FastAPI app: JSON API + dashboard
    ├── service.py       # background scan runner, scan comparison
    └── static/          # dashboard (HTML/CSS/vanilla JS, no build step)
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

- **Phase 3:** PDF export, multi-target scans, CVE lookup from service banners (NVD),
  DNS / email security checks (SPF, DMARC, CAA)
- **Phase 4:** dashboard login, scheduled scans with alerts, Docker image, PyPI release

## License

[MIT](LICENSE)
