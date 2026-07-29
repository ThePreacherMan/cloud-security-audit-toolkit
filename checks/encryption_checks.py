"""Cloud encryption and data-protection security checks."""

from __future__ import annotations

from typing import Any

from cloud_audit.models import Finding, Severity


SUPPORTED_RESOURCE_TYPES = {
    "database",
    "rds_instance",
    "virtual_machine",
    "ec2_instance",
    "disk",
    "volume",
    "snapshot",
}


def check_encryption_resources(
    resources: list[dict[str, Any]],
) -> list[Finding]:
    """Run encryption-related checks against supported cloud resources."""

    findings: list[Finding] = []

    for resource in resources:
        resource_type = resource.get("type", "").lower()

        if resource_type not in SUPPORTED_RESOURCE_TYPES:
            continue

        resource_id = resource.get("id", "unknown-resource")
        region = resource.get("region", "unknown")
        configuration = resource.get("configuration", {})

        findings.extend(
            _check_encryption_at_rest(
                resource_id=resource_id,
                region=region,
                resource_type=resource_type,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_customer_managed_key(
                resource_id=resource_id,
                region=region,
                resource_type=resource_type,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_snapshot_encryption(
                resource_id=resource_id,
                region=region,
                resource_type=resource_type,
                configuration=configuration,
            )
        )

    return findings


def _check_encryption_at_rest(
    resource_id: str,
    region: str,
    resource_type: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect cloud resources without encryption at rest."""

    if configuration.get("encryption_enabled", False):
        return []

    return [
        Finding(
            check_id="ENCRYPTION-001",
            title="Encryption at rest is disabled",
            description=(
                "The cloud resource does not enforce encryption at rest, "
                "which may expose stored data if the resource is compromised."
            ),
            severity=Severity.HIGH,
            service="Encryption",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable encryption at rest using a cloud-managed or "
                "customer-managed encryption key."
            ),
            evidence={
                "resource_type": resource_type,
                "encryption_enabled": configuration.get(
                    "encryption_enabled",
                    False,
                ),
            },
            compliance=[
                "NIST PR.DS-1",
                "CIS Controls 3.11",
            ],
        )
    ]


def _check_customer_managed_key(
    resource_id: str,
    region: str,
    resource_type: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect encrypted resources not using customer-managed keys."""

    if not configuration.get("encryption_enabled", False):
        return []

    key_type = str(
        configuration.get("encryption_key_type", "provider_managed")
    ).lower()

    if key_type in {
        "customer_managed",
        "customer-managed",
        "cmk",
    }:
        return []

    return [
        Finding(
            check_id="ENCRYPTION-002",
            title="Customer-managed encryption key is not configured",
            description=(
                "The resource uses provider-managed encryption rather than "
                "a customer-managed key with dedicated lifecycle controls."
            ),
            severity=Severity.MEDIUM,
            service="Encryption",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Use a customer-managed encryption key for sensitive or "
                "regulated workloads and enforce key rotation."
            ),
            evidence={
                "resource_type": resource_type,
                "encryption_key_type": key_type,
            },
            compliance=[
                "NIST PR.DS-1",
                "NIST PR.DS-2",
            ],
        )
    ]


def _check_snapshot_encryption(
    resource_id: str,
    region: str,
    resource_type: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect unencrypted snapshots and backups."""

    if resource_type not in {"snapshot", "volume", "disk"}:
        return []

    snapshot_encrypted = configuration.get(
        "snapshot_encryption_enabled",
        configuration.get("encryption_enabled", False),
    )

    if snapshot_encrypted:
        return []

    return [
        Finding(
            check_id="ENCRYPTION-003",
            title="Snapshot or backup encryption is disabled",
            description=(
                "Snapshots or backup copies associated with the resource "
                "are not protected with encryption."
            ),
            severity=Severity.HIGH,
            service="Encryption",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable encryption for all snapshots and backup copies, "
                "including copies shared across accounts or regions."
            ),
            evidence={
                "resource_type": resource_type,
                "snapshot_encryption_enabled": snapshot_encrypted,
            },
            compliance=[
                "NIST PR.DS-1",
                "CIS Controls 3.11",
            ],
        )
    ]
