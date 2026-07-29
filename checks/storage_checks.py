"""Cloud storage security checks."""

from __future__ import annotations

from typing import Any

from cloud_audit.models import Finding, Severity


def check_storage_resources(
    resources: list[dict[str, Any]],
) -> list[Finding]:
    """Run storage-related security checks against cloud resources."""

    findings: list[Finding] = []

    for resource in resources:
        resource_type = resource.get("type", "").lower()

        if resource_type not in {"s3_bucket", "storage_bucket"}:
            continue

        resource_id = resource.get("id", "unknown-bucket")
        region = resource.get("region", "unknown")
        configuration = resource.get("configuration", {})

        findings.extend(
            _check_public_access(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_encryption(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_versioning(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_access_logging(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

    return findings


def _check_public_access(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect publicly accessible storage buckets."""

    public_access = configuration.get("public_access", False)
    block_public_access = configuration.get(
        "block_public_access",
        True,
    )

    if not public_access and block_public_access:
        return []

    return [
        Finding(
            check_id="STORAGE-001",
            title="Storage bucket allows public access",
            description=(
                "The storage bucket is publicly accessible or does not "
                "enforce public-access blocking controls."
            ),
            severity=Severity.CRITICAL,
            service="Object Storage",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Disable public access, enable the public-access block, "
                "and review bucket policies and access control lists."
            ),
            evidence={
                "public_access": public_access,
                "block_public_access": block_public_access,
            },
            compliance=[
                "CIS AWS Foundations 2.1.5",
                "NIST PR.AC-3",
            ],
        )
    ]


def _check_encryption(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect storage buckets without encryption at rest."""

    if configuration.get("encryption_enabled", False):
        return []

    return [
        Finding(
            check_id="STORAGE-002",
            title="Storage encryption is disabled",
            description=(
                "The storage bucket does not enforce encryption at rest, "
                "which may expose sensitive data if storage is compromised."
            ),
            severity=Severity.HIGH,
            service="Object Storage",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable server-side encryption using a cloud-managed or "
                "customer-managed encryption key."
            ),
            evidence={
                "encryption_enabled": configuration.get(
                    "encryption_enabled",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 2.1.1",
                "NIST PR.DS-1",
            ],
        )
    ]


def _check_versioning(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect storage buckets without object versioning."""

    if configuration.get("versioning_enabled", False):
        return []

    return [
        Finding(
            check_id="STORAGE-003",
            title="Storage versioning is disabled",
            description=(
                "Object versioning is disabled, limiting recovery from "
                "accidental deletion, modification, or ransomware."
            ),
            severity=Severity.MEDIUM,
            service="Object Storage",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable object versioning and define retention and recovery "
                "procedures for critical data."
            ),
            evidence={
                "versioning_enabled": configuration.get(
                    "versioning_enabled",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 2.1.3",
                "NIST PR.IP-4",
            ],
        )
    ]


def _check_access_logging(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect storage buckets without access logging."""

    if configuration.get("access_logging_enabled", False):
        return []

    return [
        Finding(
            check_id="STORAGE-004",
            title="Storage access logging is disabled",
            description=(
                "The storage bucket does not record access requests, "
                "reducing visibility during investigations."
            ),
            severity=Severity.MEDIUM,
            service="Object Storage",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Enable storage access logging and send logs to a protected "
                "central logging destination."
            ),
            evidence={
                "access_logging_enabled": configuration.get(
                    "access_logging_enabled",
                    False,
                ),
            },
            compliance=[
                "CIS AWS Foundations 2.1.2",
                "NIST DE.AE-3",
            ],
        )
    ]
