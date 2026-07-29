"""Command-line interface for the Cloud Security Audit Toolkit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cloud_audit.auditor import run_audit
from cloud_audit.loader import CloudDataError, load_cloud_data
from cloud_audit.reporter import export_all_reports


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Audit cloud configuration data for security "
            "misconfigurations and generate remediation reports."
        )
    )

    parser.add_argument(
        "input_file",
        help="Path to the cloud configuration JSON file.",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="reports",
        help=(
            "Directory where audit reports will be saved. "
            "Default: reports"
        ),
    )

    return parser


def print_summary(summary: object, report_paths: dict[str, Path]) -> None:
    """Display a concise audit summary in the terminal."""

    severity_counts = summary.severity_counts()

    print("\nCloud Security Audit Completed")
    print("=" * 40)
    print(f"Provider: {summary.provider}")
    print(f"Account ID: {summary.account_id}")
    print(f"Environment: {summary.environment}")
    print(f"Resources audited: {summary.total_resources}")
    print(f"Total findings: {len(summary.findings)}")
    print(f"Security score: {summary.security_score}/100")
    print(f"Risk rating: {summary.risk_rating}")

    print("\nSeverity Breakdown")
    print("-" * 40)

    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")

    print("\nGenerated Reports")
    print("-" * 40)

    for report_type, path in report_paths.items():
        print(f"{report_type.upper()}: {path}")

    print()


def main() -> int:
    """Run the Cloud Security Audit Toolkit."""

    parser = build_parser()
    arguments = parser.parse_args()

    try:
        cloud_data = load_cloud_data(arguments.input_file)
        summary = run_audit(cloud_data)
        report_paths = export_all_reports(
            summary,
            arguments.output,
        )
    except CloudDataError as error:
        print(f"Input error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Report generation error: {error}", file=sys.stderr)
        return 1

    print_summary(summary, report_paths)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
