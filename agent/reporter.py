import json
from pathlib import Path

from .db import FindingsDB


def export_reports(db: FindingsDB, output_dir: str = "reports") -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    findings = db.full_findings()

    json_path = out / "findings.json"
    md_path = out / "findings.md"
    html_path = out / "findings.html"

    json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    md_lines = ["# Security Findings", ""]
    for f in findings:
        md_lines += [
            f"## [{f['severity']}] {f['title']}",
            f"- Type: {f['vuln_type']}",
            f"- Confidence: {f['confidence']}",
            f"- Endpoint: `{f['endpoint']}`",
            f"- CWE: {f['cwe']}",
            f"- CVSS 3.1: {f['cvss_score']}",
            f"- Description: {f['description']}",
            f"- Remediation: {f['remediation']}",
            "",
        ]
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{f['severity']}</td>"
            f"<td>{f['title']}</td>"
            f"<td>{f['endpoint']}</td>"
            f"<td>{f['confidence']}</td>"
            "</tr>"
        )

    html = """
    <html><head><title>Security Findings</title></head><body>
    <h1>Security Findings</h1>
    <table border="1" cellpadding="6" cellspacing="0">
    <tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>Confidence</th></tr>
    """ + "\n".join(rows) + """
    </table>
    </body></html>
    """
    html_path.write_text(html, encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "html": str(html_path),
    }
