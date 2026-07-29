"""Report generation utilities for cloud security audit results."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from cloud_audit.models import AuditSummary, Finding


def export_json_report(
    summary: AuditSummary,
    output_path: str | Path,
) -> Path:
    """Export the audit summary as a formatted JSON report."""

    path = _prepare_output_path(output_path)

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            summary.to_dict(),
            file,
            indent=2,
            ensure_ascii=False,
        )

    return path


def export_csv_report(
    summary: AuditSummary,
    output_path: str | Path,
) -> Path:
    """Export audit findings as a CSV report."""

    path = _prepare_output_path(output_path)

    fieldnames = [
        "check_id",
        "title",
        "severity",
        "service",
        "resource_id",
        "region",
        "description",
        "remediation",
        "compliance",
        "evidence",
    ]

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for finding in summary.findings:
            writer.writerow(
                {
                    "check_id": finding.check_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "service": finding.service,
                    "resource_id": finding.resource_id,
                    "region": finding.region,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "compliance": "; ".join(finding.compliance),
                    "evidence": json.dumps(
                        finding.evidence,
                        ensure_ascii=False,
                    ),
                }
            )

    return path


def export_markdown_report(
    summary: AuditSummary,
    output_path: str | Path,
) -> Path:
    """Export the audit summary as a Markdown report."""

    path = _prepare_output_path(output_path)
    severity_counts = summary.severity_counts()

    lines = [
        "# Cloud Security Audit Report",
        "",
        "## Executive Summary",
        "",
        f"- **Cloud provider:** {summary.provider}",
        f"- **Account ID:** {summary.account_id}",
        f"- **Environment:** {summary.environment}",
        f"- **Resources audited:** {summary.total_resources}",
        f"- **Total findings:** {len(summary.findings)}",
        f"- **Security score:** {summary.security_score}/100",
        f"- **Risk rating:** {summary.risk_rating}",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Findings |",
        "|---|---:|",
    ]

    for severity, count in severity_counts.items():
        lines.append(f"| {severity} | {count} |")

    lines.extend(
        [
            "",
            "## Detailed Findings",
            "",
        ]
    )

    if not summary.findings:
        lines.append(
            "No security findings were detected in the audited environment."
        )

    for index, finding in enumerate(summary.findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- **Check ID:** {finding.check_id}",
                f"- **Severity:** {finding.severity.value}",
                f"- **Service:** {finding.service}",
                f"- **Resource:** `{finding.resource_id}`",
                f"- **Region:** {finding.region}",
                "",
                f"**Description:** {finding.description}",
                "",
                f"**Remediation:** {finding.remediation}",
                "",
                "**Compliance references:**",
            ]
        )

        for reference in finding.compliance:
            lines.append(f"- {reference}")

        lines.extend(
            [
                "",
                "**Evidence:**",
                "",
                "```json",
                json.dumps(
                    finding.evidence,
                    indent=2,
                    ensure_ascii=False,
                ),
                "```",
                "",
                "---",
                "",
            ]
        )

    path.write_text("\n".join(lines), encoding="utf-8")

    return path


def export_html_report(
    summary: AuditSummary,
    output_path: str | Path,
) -> Path:
    """Export the audit summary as a standalone HTML report."""

    path = _prepare_output_path(output_path)
    severity_counts = summary.severity_counts()

    severity_rows = "\n".join(
        (
            "<tr>"
            f"<td>{html.escape(severity)}</td>"
            f"<td>{count}</td>"
            "</tr>"
        )
        for severity, count in severity_counts.items()
    )

    findings_html = "\n".join(
        _finding_to_html(index, finding)
        for index, finding in enumerate(summary.findings, start=1)
    )

    if not findings_html:
        findings_html = (
            "<p>No security findings were detected in the audited "
            "environment.</p>"
        )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Security Audit Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1100px;
            margin: 0 auto;
            padding: 32px;
            background: #f4f7fb;
            color: #1f2937;
            line-height: 1.6;
        }}

        header,
        section {{
            background: #ffffff;
            padding: 24px;
            margin-bottom: 24px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }}

        h1,
        h2,
        h3 {{
            color: #0f172a;
        }}

        .score {{
            font-size: 28px;
            font-weight: bold;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th,
        td {{
            border: 1px solid #dbe3ed;
            padding: 10px;
            text-align: left;
        }}

        th {{
            background: #e9eff7;
        }}

        .finding {{
            border-left: 5px solid #334155;
            margin-bottom: 18px;
        }}

        code,
        pre {{
            background: #eef2f7;
            border-radius: 5px;
        }}

        pre {{
            padding: 14px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <header>
        <h1>Cloud Security Audit Report</h1>
        <p class="score">Security Score: {summary.security_score}/100</p>
        <p><strong>Risk Rating:</strong> {html.escape(summary.risk_rating)}</p>
    </header>

    <section>
        <h2>Executive Summary</h2>
        <p><strong>Cloud provider:</strong>
            {html.escape(summary.provider)}
        </p>
        <p><strong>Account ID:</strong>
            {html.escape(summary.account_id)}
        </p>
        <p><strong>Environment:</strong>
            {html.escape(summary.environment)}
        </p>
        <p><strong>Resources audited:</strong>
            {summary.total_resources}
        </p>
        <p><strong>Total findings:</strong>
            {len(summary.findings)}
        </p>
    </section>

    <section>
        <h2>Severity Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
                {severity_rows}
            </tbody>
        </table>
    </section>

    <section>
        <h2>Detailed Findings</h2>
        {findings_html}
    </section>
</body>
</html>
"""

    path.write_text(document, encoding="utf-8")

    return path


def export_all_reports(
    summary: AuditSummary,
    output_directory: str | Path,
) -> dict[str, Path]:
    """Export JSON, CSV, Markdown, and HTML reports."""

    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)

    return {
        "json": export_json_report(
            summary,
            directory / "cloud_audit_report.json",
        ),
        "csv": export_csv_report(
            summary,
            directory / "cloud_audit_report.csv",
        ),
        "markdown": export_markdown_report(
            summary,
            directory / "cloud_audit_report.md",
        ),
        "html": export_html_report(
            summary,
            directory / "cloud_audit_report.html",
        ),
    }


def _prepare_output_path(output_path: str | Path) -> Path:
    """Create the report directory and return the normalised path."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    return path


def _finding_to_html(index: int, finding: Finding) -> str:
    """Convert one audit finding into escaped HTML."""

    compliance_items = "".join(
        f"<li>{html.escape(reference)}</li>"
        for reference in finding.compliance
    )

    evidence = html.escape(
        json.dumps(
            finding.evidence,
            indent=2,
            ensure_ascii=False,
        )
    )

    return f"""
<div class="finding">
    <h3>{index}. {html.escape(finding.title)}</h3>
    <p><strong>Check ID:</strong>
        {html.escape(finding.check_id)}
    </p>
    <p><strong>Severity:</strong>
        {html.escape(finding.severity.value)}
    </p>
    <p><strong>Service:</strong>
        {html.escape(finding.service)}
    </p>
    <p><strong>Resource:</strong>
        <code>{html.escape(finding.resource_id)}</code>
    </p>
    <p><strong>Region:</strong>
        {html.escape(finding.region)}
    </p>
    <p><strong>Description:</strong>
        {html.escape(finding.description)}
    </p>
    <p><strong>Remediation:</strong>
        {html.escape(finding.remediation)}
    </p>
    <p><strong>Compliance references:</strong></p>
    <ul>{compliance_items}</ul>
    <p><strong>Evidence:</strong></p>
    <pre>{evidence}</pre>
</div>
"""
