"""Tests for cloud security audit checks."""

from checks.encryption_checks import check_encryption_resources
from checks.iam_checks import check_iam_resources
from checks.logging_checks import check_logging_resources
from checks.network_checks import check_network_resources
from checks.storage_checks import check_storage_resources
from cloud_audit.models import Severity


def test_iam_user_without_mfa_is_flagged() -> None:
    """IAM users without MFA should generate a high-severity finding."""

    resources = [
        {
            "type": "iam_user",
            "id": "test-user",
            "region": "global",
            "configuration": {
                "mfa_enabled": False,
                "administrator_access": False,
                "access_keys": [],
            },
        }
    ]

    findings = check_iam_resources(resources)

    assert any(
        finding.check_id == "IAM-001"
        and finding.severity == Severity.HIGH
        for finding in findings
    )


def test_administrator_access_is_critical() -> None:
    """Direct administrator access should be treated as critical."""

    resources = [
        {
            "type": "iam_user",
            "id": "admin-user",
            "region": "global",
            "configuration": {
                "mfa_enabled": True,
                "administrator_access": True,
                "access_keys": [],
            },
        }
    ]

    findings = check_iam_resources(resources)

    assert any(
        finding.check_id == "IAM-005"
        and finding.severity == Severity.CRITICAL
        for finding in findings
    )


def test_public_storage_bucket_is_flagged() -> None:
    """Public storage buckets should generate a critical finding."""

    resources = [
        {
            "type": "s3_bucket",
            "id": "public-bucket",
            "region": "eu-west-1",
            "configuration": {
                "public_access": True,
                "block_public_access": False,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "access_logging_enabled": True,
            },
        }
    ]

    findings = check_storage_resources(resources)

    assert any(
        finding.check_id == "STORAGE-001"
        and finding.severity == Severity.CRITICAL
        for finding in findings
    )


def test_public_ssh_access_is_flagged() -> None:
    """SSH exposed to the public internet should be critical."""

    resources = [
        {
            "type": "security_group",
            "id": "public-ssh-group",
            "region": "eu-west-1",
            "configuration": {
                "attached": True,
                "inbound_rules": [
                    {
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "source": "0.0.0.0/0",
                    }
                ],
                "outbound_rules": [],
            },
        }
    ]

    findings = check_network_resources(resources)

    assert any(
        finding.check_id == "NETWORK-002"
        and finding.severity == Severity.CRITICAL
        for finding in findings
    )


def test_unencrypted_database_is_flagged() -> None:
    """Databases without encryption should generate a high finding."""

    resources = [
        {
            "type": "rds_instance",
            "id": "test-database",
            "region": "eu-west-1",
            "configuration": {
                "encryption_enabled": False,
            },
        }
    ]

    findings = check_encryption_resources(resources)

    assert any(
        finding.check_id == "ENCRYPTION-001"
        and finding.severity == Severity.HIGH
        for finding in findings
    )


def test_disabled_audit_logging_is_critical() -> None:
    """Disabled cloud audit logging should be critical."""

    resources = [
        {
            "type": "cloudtrail",
            "id": "test-audit-trail",
            "region": "global",
            "configuration": {
                "enabled": False,
                "security_alerts_enabled": False,
                "retention_days": 0,
            },
        }
    ]

    findings = check_logging_resources(resources)

    assert any(
        finding.check_id == "LOGGING-001"
        and finding.severity == Severity.CRITICAL
        for finding in findings
    )


def test_secure_resources_produce_no_findings() -> None:
    """Secure example resources should not generate findings."""

    resources = [
        {
            "type": "iam_user",
            "id": "secure-user",
            "region": "global",
            "configuration": {
                "mfa_enabled": True,
                "administrator_access": False,
                "access_keys": [
                    {
                        "id": "AKIASECURE",
                        "age_days": 30,
                        "active": True,
                    }
                ],
            },
        },
        {
            "type": "s3_bucket",
            "id": "secure-bucket",
            "region": "eu-west-1",
            "configuration": {
                "public_access": False,
                "block_public_access": True,
                "encryption_enabled": True,
                "versioning_enabled": True,
                "access_logging_enabled": True,
            },
        },
    ]

    findings = []
    findings.extend(check_iam_resources(resources))
    findings.extend(check_storage_resources(resources))
    findings.extend(check_network_resources(resources))
    findings.extend(check_encryption_resources(resources))
    findings.extend(check_logging_resources(resources))

    assert findings == []
