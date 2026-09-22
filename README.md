# Basic Security Scanner

A simple Python tool for initial security auditing: scans open ports,
checks the SSL/TLS certificate, and verifies HTTP security headers — then
generates a professional HTML report.

## ⚠️ Legal notice — read before use

Use this tool **ONLY** against:
- systems you own yourself (server, VM, laptop), or
- systems for which you have **written permission** (contract/authorization) from the owner.

Scanning systems you do not own without authorization is **illegal** in almost every country
(even if the intent is "just for learning" or "to help"). When working with
real clients, always sign an authorization agreement (Rules of
Engagement) before scanning their systems.

## Installation

```bash
pip install requests
```

(All other modules — `socket`, `ssl`, `concurrent.futures` — are part of
the Python standard library and don't require installation.)

## Usage

```bash
python3 main.py <target>

# Examples:
python3 main.py example.com
python3 main.py 192.168.1.10
python3 main.py mywebsite.com -o client_report.html
```

The HTML report is saved in the directory where you run the script — open it with any browser.

## Project structure

| File | Function |
|---|---|
| `port_scanner.py` | Scans ~20 of the most common ports (SSH, HTTP, DB, etc.) with threading |
| `ssl_checker.py` | Checks the SSL/TLS certificate: expiration, protocol, issuer |
| `header_checker.py` | Checks 6 main HTTP security headers |
| `report_generator.py` | Builds the final HTML report from the results |
| `main.py` | Orchestrates everything — the program's entry point |

## What it currently checks

- **Open ports** — the 20 most critical ports (FTP, SSH, HTTP/S, main DBs, RDP, VNC, etc.) + banner grabbing
- **SSL/TLS** — certificate expiration, outdated protocol (SSLv2/3, TLS 1.0/1.1), certificate verification
- **HTTP Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

## Ideas for expansion (next steps)

- **CVE lookup**: integration with the NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) to
  compare found service versions (from banner grabbing) against known vulnerabilities
- **Backup module**: add a separate script (`backup_agent.py`) that does backup + encryption + cloud upload
  to offer as an additional service to clients
- **Multi-target**: read a list of IPs/hostnames from a CSV file, scan them all at once
- **PDF export**: generate the report directly as PDF (not just HTML) with `weasyprint` or by converting the HTML
- **Scheduling**: integrate with `cron` for automatic periodic scans + email notification if new issues are found
- **Web dashboard**: wrap these modules with Flask/FastAPI to have a web interface instead of the CLI

## Technical note

This tool only identifies possible **signs** of problems (open ports,
missing headers, outdated certificate). It does not perform exploitation or active attacks — it is a
**defensive/informational** tool, suitable for initial audits and demos
with clients. For more in-depth testing (real penetration testing), you need
additional tools and certifications (e.g. OSCP) and always clear authorization.