"""Cloud logging and monitoring security checks."""

from __future__ import annotations

from typing import Any

from cloud_audit.models import Finding, Severity


SUPPORTED_RESOURCE_TYPES = {
    "cloudtrail",
    "audit_log",
    "logging_service",
    "monitoring_service",
    "account_logging",
}


def check_logging_resources(
    resources: list[dict[str, Any]],
) -> list[Finding]:
    """Run logging and monitoring checks against cloud resources."""

    findings: list[Finding] = []

    for resource in resources:
        resource_type = resource.get("type", "").lower()

        if resource_type not in SUPPORTED_RESOURCE_TYPES:
            continue

        resource_id = resource.get("id", "unknown-logging-resource")
        region = resource.get("region", "global")
        configuration = resource.get("configuration", {})

        findings.extend(
            _check_audit_logging(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_log_validation(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_log_encryption(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_monitoring_alerts(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_log_retention(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

    return findings


def _check_audit_logging(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect disabled account-level audit logging."""

    if configuration.get("enabled", False):
        return []

    return [
        Finding(
            check_id="LOGGING-001",
            title="Cloud audit logging is disabled",
            description=(
                "Account-level audit logging is disabled, preventing "
                "reliable tracking of administrative and API activity."
            ),
            severity=Severity.CRITICAL,
            service="Logging and Monitoring",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable account-wide audit logging across all supported "
                "regions and send logs to a protected central destination."
            ),
            evidence={
                "enabled": configuration.get("enabled", False),
            },
            compliance=[
                "CIS AWS Foundations 3.1",
                "NIST DE.AE-3",
                "NIST DE.CM-7",
            ],
        )
    ]


def _check_log_validation(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect disabled log integrity validation."""

    if not configuration.get("enabled", False):
        return []

    if configuration.get("log_file_validation_enabled", False):
        return []

    return [
        Finding(
            check_id="LOGGING-002",
            title="Log file integrity validation is disabled",
            description=(
                "Audit logging is enabled, but log integrity validation "
                "is not configured to detect alteration or deletion."
            ),
            severity=Severity.HIGH,
            service="Logging and Monitoring",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable log file validation or equivalent integrity "
                "controls for audit records."
            ),
            evidence={
                "log_file_validation_enabled": configuration.get(
                    "log_file_validation_enabled",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 3.2",
                "NIST PR.DS-6",
            ],
        )
    ]


def _check_log_encryption(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect audit logs that are not encrypted."""

    if not configuration.get("enabled", False):
        return []

    if configuration.get("encryption_enabled", False):
        return []

    return [
        Finding(
            check_id="LOGGING-003",
            title="Audit log encryption is disabled",
            description=(
                "Cloud audit logs are stored without enforced encryption, "
                "which may expose sensitive operational records."
            ),
            severity=Severity.HIGH,
            service="Logging and Monitoring",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable encryption for audit logs using a managed or "
                "customer-managed encryption key."
            ),
            evidence={
                "encryption_enabled": configuration.get(
                    "encryption_enabled",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 3.7",
                "NIST PR.DS-1",
            ],
        )
    ]


def _check_monitoring_alerts(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect missing security monitoring and alerting."""

    if configuration.get("security_alerts_enabled", False):
        return []

    return [
        Finding(
            check_id="LOGGING-004",
            title="Security monitoring alerts are disabled",
            description=(
                "The environment is not configured to generate alerts for "
                "suspicious administrative or security-related activity."
            ),
            severity=Severity.HIGH,
            service="Logging and Monitoring",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable security monitoring alerts for privileged activity, "
                "authentication failures, policy changes, and logging changes."
            ),
            evidence={
                "security_alerts_enabled": configuration.get(
                    "security_alerts_enabled",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 4.1",
                "NIST DE.CM-1",
                "NIST DE.AE-5",
            ],
        )
    ]


def _check_log_retention(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect insufficient audit-log retention."""

    retention_days = configuration.get("retention_days", 0)

    if isinstance(retention_days, int) and retention_days >= 90:
        return []

    return [
        Finding(
            check_id="LOGGING-005",
            title="Audit log retention is insufficient",
            description=(
                "Audit logs are retained for fewer than 90 days, which may "
                "limit incident investigation and compliance evidence."
            ),
            severity=Severity.MEDIUM,
            service="Logging and Monitoring",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Retain security and audit logs for at least 90 days, or "
                "longer where regulatory and business requirements apply."
            ),
            evidence={
                "retention_days": retention_days,
                "recommended_minimum_days": 90,
            },
            compliance=[
                "NIST PR.PT-1",
                "NIST DE.AE-3",
            ],
        )
    ]
