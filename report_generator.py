"""
report_generator.py
Generates a readable HTML report from the scan results.
"""

from datetime import datetime

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — {target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; max-width: 820px; margin: 40px auto; color: #222; background: #fafafa; }}
  h1 {{ color: #1F2A44; border-bottom: 3px solid #2E6F5E; padding-bottom: 10px; }}
  h2 {{ color: #2E6F5E; margin-top: 36px; }}
  .meta {{ color: #666; font-size: 14px; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; background: white; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e0e0e0; font-size: 14px; }}
  th {{ background: #F2F5F4; color: #1F2A44; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
  .high {{ background: #FCE4E4; color: #B00020; }}
  .medium {{ background: #FFF4E0; color: #B36B00; }}
  .low {{ background: #E8F5E9; color: #2E7D32; }}
  .ok {{ background: #E8F5E9; color: #2E7D32; }}
  ul {{ background: white; padding: 16px 16px 16px 34px; border-radius: 6px; }}
  li {{ margin-bottom: 6px; font-size: 14px; }}
  .summary-box {{ background: white; border-left: 4px solid #2E6F5E; padding: 16px 20px; border-radius: 4px; }}
  footer {{ margin-top: 40px; font-size: 12px; color: #999; border-top: 1px solid #e0e0e0; padding-top: 12px; }}
</style>
</head>
<body>
  <h1>Security Audit Report</h1>
  <div class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated on: {timestamp}</div>

  <div class="summary-box">
    <strong>Summary:</strong> {open_ports_count} open ports,
    {ssl_warnings_count} SSL/TLS warnings,
    {header_warnings_count} missing/problematic security headers.
  </div>

  <h2>1. Open Ports</h2>
  {ports_table}

  <h2>2. SSL/TLS Certificate</h2>
  {ssl_section}

  <h2>3. HTTP Security Headers</h2>
  {headers_section}

  <footer>
    Report generated automatically. For a complete security assessment, additional manual audit by a specialist is recommended.
  </footer>
</body>
</html>
"""


def _ports_table(port_results):
    if not port_results:
        return "<p>No open ports were found among the ones checked.</p>"
    rows = ""
    for p in port_results:
        banner = p["banner"] or "—"
        rows += f"<tr><td>{p['port']}</td><td>{p['service_guess']}</td><td>{banner}</td></tr>"
    return f"""<table>
      <tr><th>Port</th><th>Service (guessed)</th><th>Banner</th></tr>
      {rows}
    </table>"""


def _ssl_section(ssl_result):
    if not ssl_result:
        return "<p>SSL check was not run (there may be no active HTTPS port).</p>"

    lines = f"""<ul>
      <li>Reachable via TLS: <strong>{'Yes' if ssl_result['reachable'] else 'No'}</strong></li>
      <li>Protocol: {ssl_result['protocol'] or '—'}</li>
      <li>Issuer: {ssl_result['issuer'] or '—'}</li>
      <li>Expires on: {ssl_result['expires_on'] or '—'} ({ssl_result['expires_in_days']} days)</li>
    </ul>"""

    if ssl_result["warnings"]:
        badge = '<span class="badge high">ISSUES FOUND</span>'
        warn_list = "<ul>" + "".join(f"<li>{w}</li>" for w in ssl_result["warnings"]) + "</ul>"
    else:
        badge = '<span class="badge ok">OK</span>'
        warn_list = "<p>No issues found.</p>"

    return f"{badge}{lines}{warn_list}"


def _headers_section(header_result):
    if not header_result:
        return "<p>Header check was not run.</p>"

    present = "".join(f"<li>{h}</li>" for h in header_result["present"]) or "<li>None</li>"
    missing = "".join(f"<li>{h}</li>" for h in header_result["missing"]) or "<li>None — all are present</li>"

    badge = '<span class="badge medium">NEEDS IMPROVEMENT</span>' if header_result["missing"] else '<span class="badge ok">OK</span>'

    return f"""{badge}
    <h3 style="font-size:15px;">Headers present</h3>
    <ul>{present}</ul>
    <h3 style="font-size:15px;">Headers missing</h3>
    <ul>{missing}</ul>
    """


def generate_report(target: str, port_results=None, ssl_result=None, header_result=None, output_path="report.html"):
    ssl_warnings = len(ssl_result["warnings"]) if ssl_result else 0
    header_warnings = len(header_result["missing"]) if header_result else 0

    html = HTML_TEMPLATE.format(
        target=target,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        open_ports_count=len(port_results) if port_results else 0,
        ssl_warnings_count=ssl_warnings,
        header_warnings_count=header_warnings,
        ports_table=_ports_table(port_results),
        ssl_section=_ssl_section(ssl_result),
        headers_section=_headers_section(header_result),
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path