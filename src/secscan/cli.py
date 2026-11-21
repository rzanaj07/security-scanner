"""Command-line interface: `secscan <target>`."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence

from secscan import __version__
from secscan.checks import CHECKS, Check, ScanConfig
from secscan.checks.ports import PortSpecError, parse_port_spec
from secscan.models import CheckResult, Severity
from secscan.reporting import write_html, write_json
from secscan.scanner import run_scan
from secscan.target import TargetError, resolve_target

EXIT_OK = 0
EXIT_FINDINGS = 1  # --fail-on threshold reached
EXIT_ERROR = 2

LEGAL_NOTICE = "Scan only systems you own or have written authorization to test."


def _check_list(value: str) -> list[str]:
    names = [n.strip() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in CHECKS]
    if unknown or not names:
        raise argparse.ArgumentTypeError(
            f"unknown check(s): {', '.join(unknown) or '(none)'}; available: {', '.join(CHECKS)}"
        )
    return names


def _port_spec(value: str) -> dict[int, str]:
    try:
        return parse_port_spec(value)
    except PortSpecError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Defensive security scanner: open ports, TLS certificate, HTTP headers.",
        epilog=LEGAL_NOTICE,
    )
    p.add_argument(
        "target",
        help="hostname, IP address or URL (e.g. example.com, 10.0.0.5); "
        "or use `secscan serve` to start the web dashboard",
    )
    p.add_argument("-o", "--output", help="HTML report path (default: report_<target>.html)")
    p.add_argument("--json", metavar="PATH", help="also write a JSON report to PATH")
    p.add_argument("--no-html", action="store_true", help="do not write the HTML report")
    p.add_argument(
        "--checks",
        type=_check_list,
        default=list(CHECKS),
        metavar="LIST",
        help=f"comma-separated checks to run (default: {','.join(CHECKS)})",
    )
    p.add_argument(
        "--ports",
        type=_port_spec,
        default=None,
        metavar="SPEC",
        help="ports to scan: common (default), 1-1024, 22,80,8000-8100, common,3000, all",
    )
    p.add_argument("--timeout", type=float, default=6.0, help="TLS/HTTP timeout in seconds")
    p.add_argument(
        "--connect-timeout", type=float, default=1.0, help="per-port connect timeout in seconds"
    )
    p.add_argument("--workers", type=int, default=100, help="parallel port-scan workers")
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit with code 1 if any finding is at or above this severity",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _default_report_name(host: str) -> str:
    return f"report_{re.sub(r'[^A-Za-z0-9_-]', '_', host)}.html"


LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def build_serve_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan serve",
        description="Start the local web dashboard.",
        epilog=LEGAL_NOTICE,
    )
    p.add_argument(
        "--host", default="127.0.0.1", help="interface to listen on (default: 127.0.0.1)"
    )
    p.add_argument("--port", type=int, default=8000, help="port to listen on (default: 8000)")
    p.add_argument("--db", default=None, help="SQLite database path (default: ~/.secscan/scans.db)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    return p


def serve(argv: Sequence[str]) -> int:
    args = build_serve_parser().parse_args(argv)
    import threading
    import webbrowser

    import uvicorn

    from secscan.store import DEFAULT_DB_PATH
    from secscan.web.app import create_app

    local = args.host in LOCAL_HOSTS
    if not local:
        print(
            "WARNING: the dashboard has no login. Anyone who can reach "
            f"{args.host}:{args.port} can start scans from this machine.",
            file=sys.stderr,
        )
    db = args.db or DEFAULT_DB_PATH
    app = create_app(db, allowed_hosts=["127.0.0.1", "localhost", "[::1]"] if local else None)

    browse_host = "127.0.0.1" if local or args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{browse_host}:{args.port}/"
    print(f"secscan {__version__} dashboard: {url}  (database: {db})")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return serve(argv[1:])
    args = build_parser().parse_args(argv)

    try:
        target = resolve_target(args.target)
    except TargetError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    config = ScanConfig(
        connect_timeout=args.connect_timeout,
        timeout=args.timeout,
        workers=args.workers,
        ports=args.ports,
    )
    checks = [CHECKS[name]() for name in args.checks]

    print(f"secscan {__version__} - target {target.host} ({target.address})")
    print(f"Note: {LEGAL_NOTICE}\n")

    total = len(checks)
    position = 0

    def on_start(check: Check) -> None:
        nonlocal position
        position += 1
        print(f"[{position}/{total}] {check.title}...")

    def on_done(result: CheckResult) -> None:
        if result.error:
            print(f"      error: {result.error}")
        elif result.findings:
            print(f"      {len(result.findings)} finding(s)")
        elif not result.notes:
            print("      OK")
        for note in result.notes:
            print(f"      {note}")

    scan = run_scan(target, checks, config, on_check_start=on_start, on_check_done=on_done)

    counts = scan.severity_counts()
    summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n) or "no findings"
    print(f"\nScore: {scan.score()}/100 (grade {scan.grade()})")
    print(f"Summary: {summary}")

    try:
        if not args.no_html:
            path = write_html(scan, args.output or _default_report_name(target.host))
            print(f"HTML report: {path}")
        if args.json:
            print(f"JSON report: {write_json(scan, args.json)}")
    except OSError as e:
        print(f"error: could not write report: {e}", file=sys.stderr)
        return EXIT_ERROR

    if args.fail_on:
        threshold = Severity(args.fail_on)
        worst = scan.highest_severity()
        if worst is not None and worst.rank >= threshold.rank:
            return EXIT_FINDINGS
    return EXIT_OK
