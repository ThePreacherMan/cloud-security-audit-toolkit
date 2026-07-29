"""Main cloud security audit engine."""

from __future__ import annotations

from typing import Any

from checks.encryption_checks import check_encryption_resources
from checks.iam_checks import check_iam_resources
from checks.logging_checks import check_logging_resources
from checks.network_checks import check_network_resources
from checks.storage_checks import check_storage_resources
from cloud_audit.models import AuditSummary, Finding
from cloud_audit.risk import calculate_risk_metrics


def run_audit(cloud_data: dict[str, Any]) -> AuditSummary:
    """Run all supported security checks against cloud configuration data."""

    resources = cloud_data.get("resources", [])

    findings: list[Finding] = []

    findings.extend(check_iam_resources(resources))
    findings.extend(check_storage_resources(resources))
    findings.extend(check_network_resources(resources))
    findings.extend(check_encryption_resources(resources))
    findings.extend(check_logging_resources(resources))

    findings = sort_findings(findings)

    security_score, risk_rating = calculate_risk_metrics(findings)

    return AuditSummary(
        provider=str(cloud_data.get("provider", "unknown")),
        account_id=str(cloud_data.get("account_id", "unknown")),
        environment=str(cloud_data.get("environment", "unknown")),
        total_resources=len(resources),
        findings=findings,
        security_score=security_score,
        risk_rating=risk_rating,
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity, service, resource, and check identifier."""

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }

    return sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.severity.value, 5),
            finding.service.lower(),
            finding.resource_id.lower(),
            finding.check_id,
        ),
    )
