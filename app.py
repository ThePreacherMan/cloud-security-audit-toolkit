"""Streamlit interface for the Cloud Security Audit Toolkit."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from cloud_audit.auditor import run_audit
from cloud_audit.loader import CloudDataError, load_cloud_data
from cloud_audit.models import AuditSummary
from cloud_audit.reporter import (
    export_csv_report,
    export_html_report,
    export_json_report,
    export_markdown_report,
)


APP_TITLE = "Cloud Security Audit Toolkit"

SAMPLE_DIRECTORY = Path("sample_data")

SAMPLE_FILES = {
    "Vulnerable Environment": (
        SAMPLE_DIRECTORY / "vulnerable_environment.json"
    ),
    "Secure Environment": (
        SAMPLE_DIRECTORY / "secure_environment.json"
    ),
}


def configure_page() -> None:
    """Configure Streamlit page settings."""

    st.set_page_config(
        page_title=APP_TITLE,
        page_icon="☁️",
        layout="wide",
        initial_sidebar_state="expanded",
    )


def apply_custom_styles() -> None:
    """Apply custom interface styling."""

    st.markdown(
        """
        <style>
        .main {
            background-color: #f5f7fb;
        }

        .block-container {
            max-width: 1400px;
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        .hero {
            background:
                linear-gradient(
                    135deg,
                    #0f172a 0%,
                    #1e3a8a 55%,
                    #0f766e 100%
                );
            padding: 2.2rem;
            border-radius: 18px;
            color: white;
            margin-bottom: 1.5rem;
        }

        .hero h1 {
            margin-bottom: 0.5rem;
            font-size: 2.5rem;
        }

        .hero p {
            font-size: 1.05rem;
            color: #dbeafe;
            max-width: 850px;
        }

        .metric-card {
            background: white;
            padding: 1.2rem;
            border-radius: 14px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.06);
            min-height: 125px;
        }

        .finding-card {
            background: white;
            padding: 1rem 1.2rem;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
            margin-bottom: 0.8rem;
        }

        .severity-critical {
            border-left: 6px solid #991b1b;
        }

        .severity-high {
            border-left: 6px solid #dc2626;
        }

        .severity-medium {
            border-left: 6px solid #d97706;
        }

        .severity-low {
            border-left: 6px solid #2563eb;
        }

        .severity-informational {
            border-left: 6px solid #64748b;
        }

        .footer {
            text-align: center;
            color: #64748b;
            padding-top: 2rem;
            font-size: 0.9rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header() -> None:
    """Render the application introduction."""

    st.markdown(
        """
        <div class="hero">
            <h1>☁️ Cloud Security Audit Toolkit</h1>
            <p>
                Audit cloud configuration data, detect security
                misconfigurations, calculate posture scores, and generate
                actionable remediation reports without requiring live
                cloud credentials.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def load_json_from_upload(uploaded_file: Any) -> dict[str, Any]:
    """Load JSON cloud configuration data from an uploaded file."""

    try:
        uploaded_file.seek(0)
        data = json.load(uploaded_file)
    except json.JSONDecodeError as error:
        raise CloudDataError(
            f"The uploaded file contains invalid JSON: {error}"
        ) from error

    if not isinstance(data, dict):
        raise CloudDataError(
            "The uploaded cloud configuration must be a JSON object."
        )

    return data


def load_sample_environment(sample_name: str) -> dict[str, Any]:
    """Load one of the included sample cloud environments."""

    sample_path = SAMPLE_FILES[sample_name]
    return load_cloud_data(sample_path)


def render_sidebar() -> tuple[str, Any, str]:
    """Render audit-input controls."""

    st.sidebar.header("Audit Configuration")

    input_method = st.sidebar.radio(
        "Choose input source",
        options=[
            "Upload JSON file",
            "Use sample environment",
        ],
    )

    uploaded_file = None
    selected_sample = "Vulnerable Environment"

    if input_method == "Upload JSON file":
        uploaded_file = st.sidebar.file_uploader(
            "Upload cloud configuration",
            type=["json"],
            help=(
                "Upload a structured JSON file containing cloud resources "
                "and configuration settings."
            ),
        )
    else:
        selected_sample = st.sidebar.selectbox(
            "Select sample environment",
            options=list(SAMPLE_FILES),
        )

    st.sidebar.markdown("---")

    run_button = st.sidebar.button(
        "Run Security Audit",
        type="primary",
        use_container_width=True,
    )

    st.sidebar.markdown("---")

    st.sidebar.subheader("Audit Coverage")

    st.sidebar.markdown(
        """
        - Identity and Access Management
        - Object Storage
        - Network Security
        - Encryption
        - Logging and Monitoring
        """
    )

    return input_method, uploaded_file, selected_sample, run_button


def render_summary(summary: AuditSummary) -> None:
    """Render audit summary cards."""

    severity_counts = summary.severity_counts()

    first_column, second_column, third_column, fourth_column = st.columns(4)

    with first_column:
        st.metric(
            "Security Score",
            f"{summary.security_score}/100",
        )

    with second_column:
        st.metric(
            "Risk Rating",
            summary.risk_rating,
        )

    with third_column:
        st.metric(
            "Resources Audited",
            summary.total_resources,
        )

    with fourth_column:
        st.metric(
            "Total Findings",
            len(summary.findings),
        )

    st.markdown("### Severity Overview")

    critical_column, high_column, medium_column, low_column = st.columns(4)

    with critical_column:
        st.metric(
            "Critical",
            severity_counts.get("Critical", 0),
        )

    with high_column:
        st.metric(
            "High",
            severity_counts.get("High", 0),
        )

    with medium_column:
        st.metric(
            "Medium",
            severity_counts.get("Medium", 0),
        )

    with low_column:
        st.metric(
            "Low",
            severity_counts.get("Low", 0),
        )


def findings_to_dataframe(summary: AuditSummary) -> pd.DataFrame:
    """Convert audit findings into a display-friendly dataframe."""

    rows = []

    for finding in summary.findings:
        rows.append(
            {
                "Check ID": finding.check_id,
                "Severity": finding.severity.value,
                "Service": finding.service,
                "Resource": finding.resource_id,
                "Region": finding.region,
                "Title": finding.title,
            }
        )

    return pd.DataFrame(rows)


def render_findings(summary: AuditSummary) -> None:
    """Render finding filters, table, and detailed findings."""

    st.markdown("## Audit Findings")

    if not summary.findings:
        st.success(
            "No security misconfigurations were detected in this environment."
        )
        return

    severity_options = sorted(
        {
            finding.severity.value
            for finding in summary.findings
        }
    )

    service_options = sorted(
        {
            finding.service
            for finding in summary.findings
        }
    )

    filter_column_one, filter_column_two = st.columns(2)

    with filter_column_one:
        selected_severities = st.multiselect(
            "Filter by severity",
            options=severity_options,
            default=severity_options,
        )

    with filter_column_two:
        selected_services = st.multiselect(
            "Filter by service",
            options=service_options,
            default=service_options,
        )

    filtered_findings = [
        finding
        for finding in summary.findings
        if finding.severity.value in selected_severities
        and finding.service in selected_services
    ]

    filtered_summary = AuditSummary(
        provider=summary.provider,
        account_id=summary.account_id,
        environment=summary.environment,
        total_resources=summary.total_resources,
        findings=filtered_findings,
        security_score=summary.security_score,
        risk_rating=summary.risk_rating,
    )

    dataframe = findings_to_dataframe(filtered_summary)

    if not dataframe.empty:
        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("### Detailed Findings")

    for finding in filtered_findings:
        severity_class = (
            f"severity-{finding.severity.value.lower()}"
        )

        st.markdown(
            f"""
            <div class="finding-card {severity_class}">
                <strong>{finding.severity.value}</strong>
                · {finding.service}
                · {finding.check_id}
                <h4>{finding.title}</h4>
                <p><strong>Resource:</strong>
                    {finding.resource_id}
                </p>
                <p><strong>Region:</strong>
                    {finding.region}
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander("View finding details"):
            st.markdown("**Description**")
            st.write(finding.description)

            st.markdown("**Remediation**")
            st.write(finding.remediation)

            st.markdown("**Compliance references**")

            for reference in finding.compliance:
                st.write(f"- {reference}")

            st.markdown("**Evidence**")
            st.json(finding.evidence)


def generate_download_reports(
    summary: AuditSummary,
) -> dict[str, bytes]:
    """Generate report files and return their binary contents."""

    with tempfile.TemporaryDirectory() as temporary_directory:
        directory = Path(temporary_directory)

        paths = {
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

        return {
            report_type: path.read_bytes()
            for report_type, path in paths.items()
        }


def render_downloads(summary: AuditSummary) -> None:
    """Render report-download buttons."""

    st.markdown("## Download Reports")

    reports = generate_download_reports(summary)

    json_column, csv_column, markdown_column, html_column = st.columns(4)

    with json_column:
        st.download_button(
            "Download JSON",
            data=reports["json"],
            file_name="cloud_audit_report.json",
            mime="application/json",
            use_container_width=True,
        )

    with csv_column:
        st.download_button(
            "Download CSV",
            data=reports["csv"],
            file_name="cloud_audit_report.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with markdown_column:
        st.download_button(
            "Download Markdown",
            data=reports["markdown"],
            file_name="cloud_audit_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

    with html_column:
        st.download_button(
            "Download HTML",
            data=reports["html"],
            file_name="cloud_audit_report.html",
            mime="text/html",
            use_container_width=True,
        )


def render_environment_details(summary: AuditSummary) -> None:
    """Render audited environment metadata."""

    st.markdown("## Environment Details")

    environment_data = {
        "Cloud Provider": summary.provider,
        "Account ID": summary.account_id,
        "Environment": summary.environment,
        "Resources Audited": summary.total_resources,
    }

    st.json(environment_data)


def execute_audit(
    input_method: str,
    uploaded_file: Any,
    selected_sample: str,
) -> AuditSummary:
    """Load selected input data and run the security audit."""

    if input_method == "Upload JSON file":
        if uploaded_file is None:
            raise CloudDataError(
                "Upload a JSON cloud configuration file before running "
                "the audit."
            )

        cloud_data = load_json_from_upload(uploaded_file)
    else:
        cloud_data = load_sample_environment(selected_sample)

    return run_audit(cloud_data)


def main() -> None:
    """Run the Streamlit web interface."""

    configure_page()
    apply_custom_styles()
    render_header()

    (
        input_method,
        uploaded_file,
        selected_sample,
        run_button,
    ) = render_sidebar()

    if "audit_summary" not in st.session_state:
        st.session_state.audit_summary = None

    if run_button:
        try:
            with st.spinner(
                "Auditing cloud resources and calculating security risk..."
            ):
                st.session_state.audit_summary = execute_audit(
                    input_method=input_method,
                    uploaded_file=uploaded_file,
                    selected_sample=selected_sample,
                )

            st.success("Cloud security audit completed successfully.")
        except CloudDataError as error:
            st.session_state.audit_summary = None
            st.error(str(error))
        except (OSError, ValueError, TypeError) as error:
            st.session_state.audit_summary = None
            st.error(
                f"The audit could not be completed: {error}"
            )

    summary = st.session_state.audit_summary

    if summary is None:
        st.info(
            "Choose a sample environment or upload a JSON file, "
            "then click **Run Security Audit**."
        )

        st.markdown("## What This Toolkit Detects")

        first_column, second_column, third_column = st.columns(3)

        with first_column:
            st.markdown(
                """
                ### Identity Risks

                - Missing MFA
                - Old access keys
                - Excessive credentials
                - Direct administrator privileges
                """
            )

        with second_column:
            st.markdown(
                """
                ### Infrastructure Risks

                - Public storage buckets
                - Exposed SSH and RDP
                - Open database ports
                - Unrestricted outbound traffic
                """
            )

        with third_column:
            st.markdown(
                """
                ### Data and Monitoring Risks

                - Missing encryption
                - Unencrypted snapshots
                - Disabled audit logging
                - Insufficient log retention
                """
            )
    else:
        render_summary(summary)

        overview_tab, findings_tab, reports_tab = st.tabs(
            [
                "Environment Overview",
                "Security Findings",
                "Reports",
            ]
        )

        with overview_tab:
            render_environment_details(summary)

        with findings_tab:
            render_findings(summary)

        with reports_tab:
            render_downloads(summary)

    st.markdown(
        """
        <div class="footer">
            Built by Chigoziem Ibeh · Defensive Cloud Security Automation
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
