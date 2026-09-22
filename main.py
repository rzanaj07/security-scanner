#!/usr/bin/env python3
"""
main.py — Basic Security Scanner
Orchestrates: port scanning + SSL check + HTTP header check -> HTML report.

USAGE:
    python3 main.py <target>

    Example:
    python3 main.py example.com
    python3 main.py 192.168.1.10

LEGAL NOTICE:
    Use this tool ONLY against systems you own, or
    where you have written permission (contract/authorization) to perform security testing.
    Scanning systems you do not own without authorization is illegal in most countries.
"""

import sys
import argparse

from port_scanner import scan_target
from ssl_checker import check_ssl
from header_checker import check_headers
from report_generator import generate_report


def run_scan(target: str, output: str = None):
    output = output or f"report_{target.replace('.', '_')}.html"

    print(f"\n{'=' * 60}")
    print(f"  BASIC SECURITY SCANNER — Target: {target}")
    print(f"{'=' * 60}\n")

    # 1. Port scan
    print(">> Step 1/3: Scanning ports...")
    port_results = scan_target(target)

    # 2. SSL check (only if port 443 is open, or try anyway)
    print("\n>> Step 2/3: SSL/TLS check (port 443)...")
    ssl_result = check_ssl(target, 443)
    if ssl_result["warnings"]:
        for w in ssl_result["warnings"]:
            print(f"   ! {w}")
    else:
        print("   OK — no issues found.")

    # 3. HTTP security headers check
    print("\n>> Step 3/3: Checking HTTP security headers...")
    header_result = check_headers(target)
    if header_result["missing"]:
        print(f"   {len(header_result['missing'])} security headers are missing.")
    else:
        print("   OK — all main headers are present.")

    # Generate the report
    print("\n>> Generating HTML report...")
    report_path = generate_report(
        target=target,
        port_results=port_results,
        ssl_result=ssl_result,
        header_result=header_result,
        output_path=output,
    )

    print(f"\n{'=' * 60}")
    print(f"  DONE. Report saved to: {report_path}")
    print(f"{'=' * 60}\n")

    return report_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Basic Security Scanner - ports, SSL, HTTP headers")
    parser.add_argument("target", help="Target hostname or IP (e.g. example.com or 192.168.1.10)")
    parser.add_argument("-o", "--output", help="Report file name (default: report_<target>.html)")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    run_scan(args.target, args.output)