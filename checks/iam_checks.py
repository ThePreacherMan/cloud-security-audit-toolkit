"""Identity and access management security checks."""

from __future__ import annotations

from typing import Any

from cloud_audit.models import Finding, Severity


def check_iam_resources(resources: list[dict[str, Any]]) -> list[Finding]:
    """Run IAM-related security checks against cloud resources."""

    findings: list[Finding] = []

    for resource in resources:
        resource_type = resource.get("type", "").lower()

        if resource_type != "iam_user":
            continue

        resource_id = resource.get("id", "unknown-user")
        region = resource.get("region", "global")
        configuration = resource.get("configuration", {})

        findings.extend(
            _check_mfa(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_access_keys(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_admin_privileges(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

    return findings


def _check_mfa(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect IAM users without multi-factor authentication."""

    if configuration.get("mfa_enabled", False):
        return []

    return [
        Finding(
            check_id="IAM-001",
            title="Multi-factor authentication is disabled",
            description=(
                "The IAM user does not have multi-factor authentication "
                "enabled, increasing the risk of account compromise."
            ),
            severity=Severity.HIGH,
            service="IAM",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable multi-factor authentication for the IAM user and "
                "require MFA for privileged or sensitive operations."
            ),
            evidence={
                "mfa_enabled": configuration.get("mfa_enabled", False),
            },
            compliance=[
                "CIS AWS Foundations 1.10",
                "NIST PR.AC-7",
            ],
        )
    ]


def _check_access_keys(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect old, inactive, or excessive IAM access keys."""

    findings: list[Finding] = []
    access_keys = configuration.get("access_keys", [])

    if len(access_keys) > 1:
        findings.append(
            Finding(
                check_id="IAM-002",
                title="Multiple active access keys detected",
                description=(
                    "The IAM user has more than one active access key, "
                    "which increases credential exposure."
                ),
                severity=Severity.MEDIUM,
                service="IAM",
                resource_id=resource_id,
                region=region,
                remediation=(
                    "Remove unnecessary access keys and retain only the "
                    "minimum number of credentials required."
                ),
                evidence={
                    "active_access_key_count": len(access_keys),
                },
                compliance=[
                    "CIS AWS Foundations 1.13",
                    "NIST PR.AC-1",
                ],
            )
        )

    for access_key in access_keys:
        key_id = access_key.get("id", "unknown-key")
        age_days = access_key.get("age_days", 0)
        active = access_key.get("active", True)

        if active and age_days > 90:
            findings.append(
                Finding(
                    check_id="IAM-003",
                    title="Access key exceeds rotation threshold",
                    description=(
                        "An active IAM access key has not been rotated "
                        "within the recommended 90-day period."
                    ),
                    severity=Severity.HIGH,
                    service="IAM",
                    resource_id=resource_id,
                    region=region,
                    remediation=(
                        "Rotate the access key immediately, update dependent "
                        "applications, and remove the old credential."
                    ),
                    evidence={
                        "access_key_id": key_id,
                        "age_days": age_days,
                        "active": active,
                    },
                    compliance=[
                        "CIS AWS Foundations 1.14",
                        "NIST PR.AC-1",
                    ],
                )
            )

        if not active:
            findings.append(
                Finding(
                    check_id="IAM-004",
                    title="Inactive access key remains configured",
                    description=(
                        "An inactive IAM access key remains associated with "
                        "the user and should be removed."
                    ),
                    severity=Severity.LOW,
                    service="IAM",
                    resource_id=resource_id,
                    region=region,
                    remediation=(
                        "Delete inactive access keys that are no longer needed."
                    ),
                    evidence={
                        "access_key_id": key_id,
                        "active": active,
                    },
                    compliance=[
                        "CIS AWS Foundations 1.12",
                        "NIST PR.AC-1",
                    ],
                )
            )

    return findings


def _check_admin_privileges(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect IAM users with direct administrator privileges."""

    if not configuration.get("administrator_access", False):
        return []

    return [
        Finding(
            check_id="IAM-005",
            title="IAM user has direct administrator access",
            description=(
                "The IAM user has unrestricted administrator privileges, "
                "which may violate least-privilege principles."
            ),
            severity=Severity.CRITICAL,
            service="IAM",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Remove direct administrator access and assign only the "
                "permissions required for the user's responsibilities."
            ),
            evidence={
                "administrator_access": configuration.get(
                    "administrator_access",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 1.16",
                "NIST PR.AC-4",
            ],
        )
    ]
