from __future__ import annotations

from html import escape

from repo_security_scanner.models import ScanReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#6b7280",
    Severity.UNKNOWN: "#9ca3af",
}

SOURCE_LABELS = {
    "cisa_kev": "CISA KEV",
    "pypi_registry": "PyPI Registry",
    "npm_registry": "npm Registry",
    "hackernews": "Hacker News",
    "github_issues": "GitHub Issues",
    "rss_bleepingcomputer": "Bleeping Computer",
    "rss_google_security": "Google Security Blog",
    "opencve": "OpenCVE",
}


def generate_html_report(report: ScanReport) -> str:
    # Confirmed vulnerabilities
    vuln_rows = []
    for result in report.confirmed_results:
        for v in result.vulnerabilities:
            color = SEVERITY_COLORS.get(v.severity, "#9ca3af")
            refs_html = " ".join(
                f'<a href="{escape(r)}" target="_blank">[{i+1}]</a>'
                for i, r in enumerate(v.references[:3])
            )
            fix = escape(v.fixed_version) if v.fixed_version else "No fix available"
            vuln_rows.append(f"""
            <tr>
                <td>{escape(result.dependency.name)}</td>
                <td>{escape(result.dependency.version)}</td>
                <td>{escape(result.dependency.ecosystem.value)}</td>
                <td><span class="severity" style="background:{color}">{v.severity.value}</span></td>
                <td><strong>{escape(v.id)}</strong><br><small>{escape(v.summary[:120])}</small></td>
                <td>{fix}</td>
                <td>{refs_html}</td>
            </tr>""")

    vulns_table = "\n".join(vuln_rows) if vuln_rows else '<tr><td colspan="7" style="text-align:center;padding:2rem;color:#64748b;">No confirmed vulnerabilities found</td></tr>'

    # Early warning signals
    signal_rows = []
    for result in report.early_signals:
        for v in result.vulnerabilities:
            source_label = SOURCE_LABELS.get(v.source, v.source)
            signal_type = _signal_type(v)
            ref_link = v.references[0] if v.references else ""
            ref_html = f'<a href="{escape(ref_link)}" target="_blank">View</a>' if ref_link else ""
            signal_rows.append(f"""
            <tr>
                <td>{escape(result.dependency.name)}</td>
                <td>{escape(result.dependency.version)}</td>
                <td><span class="signal-badge">{signal_type}</span></td>
                <td>{escape(source_label)}</td>
                <td>{escape(v.summary[:120])}</td>
                <td>{ref_html}</td>
            </tr>""")

    signals_table = "\n".join(signal_rows) if signal_rows else ""

    signals_section = ""
    if signals_table:
        signals_section = f"""
  <h2 style="margin-top:2rem;color:#7c3aed;">Early Warning Signals</h2>
  <p style="color:#64748b;margin-bottom:1rem;font-size:0.9rem;">Unconfirmed signals from web sources — investigate before acting.</p>
  <table class="signals-table">
    <thead>
      <tr><th>Package</th><th>Version</th><th>Signal</th><th>Source</th><th>Details</th><th>Link</th></tr>
    </thead>
    <tbody>
      {signals_table}
    </tbody>
  </table>"""

    signal_card = ""
    if report.early_signal_count > 0:
        signal_card = f'<div class="card signal"><div class="number">{report.early_signal_count}</div><div class="label">Early Signals</div></div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.25rem; margin-bottom: 0.75rem; }}
  .meta {{ color: #64748b; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: white; border-radius: 8px; padding: 1rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 140px; }}
  .card .number {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ color: #64748b; font-size: 0.85rem; }}
  .critical .number {{ color: #dc2626; }}
  .high .number {{ color: #ea580c; }}
  .medium .number {{ color: #ca8a04; }}
  .signal .number {{ color: #7c3aed; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1rem; }}
  th {{ background: #1e293b; color: white; text-align: left; padding: 0.75rem 1rem; font-size: 0.85rem; }}
  .signals-table th {{ background: #5b21b6; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; vertical-align: top; }}
  tr:hover {{ background: #f1f5f9; }}
  .severity {{ color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .signal-badge {{ color: white; background: #7c3aed; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  a {{ color: #2563eb; }}
  small {{ color: #64748b; }}
</style>
</head>
<body>
<div class="container">
  <h1>Security Scan Report</h1>
  <div class="meta">
    Directory: {escape(report.directory)}<br>
    Scanned: {report.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")}<br>
    Dependencies scanned: {report.total_dependencies}
  </div>
  <div class="summary">
    <div class="card critical"><div class="number">{report.critical_count}</div><div class="label">Critical</div></div>
    <div class="card high"><div class="number">{report.high_count}</div><div class="label">High</div></div>
    <div class="card medium"><div class="number">{report.medium_count}</div><div class="label">Medium</div></div>
    <div class="card"><div class="number">{report.total_vulns}</div><div class="label">Total Vulnerabilities</div></div>
    {signal_card}
  </div>
  <h2>Confirmed Vulnerabilities</h2>
  <table>
    <thead>
      <tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Severity</th><th>Vulnerability</th><th>Fix</th><th>Refs</th></tr>
    </thead>
    <tbody>
      {vulns_table}
    </tbody>
  </table>
  {signals_section}
</div>
</body>
</html>"""


def _signal_type(v) -> str:
    if "YANKED" in v.id:
        return "YANKED"
    elif "DEPRECATED" in v.id:
        return "DEPRECATED"
    elif v.source == "hackernews":
        return "HN MENTION"
    elif v.source == "github_issues":
        return "GH ISSUE"
    elif v.source.startswith("rss_"):
        return "NEWS"
    elif v.source == "cisa_kev":
        return "CISA KEV"
    return "SIGNAL"
