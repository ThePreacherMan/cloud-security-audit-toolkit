"""Tests for the main cloud security audit engine."""

from cloud_audit.auditor import run_audit, sort_findings
from cloud_audit.models import Finding, Severity


def create_finding(
    check_id: str,
    severity: Severity,
    service: str = "Test Service",
    resource_id: str = "test-resource",
) -> Finding:
    """Create a reusable finding for audit-engine tests."""

    return Finding(
        check_id=check_id,
        title="Test finding",
        description="A test security finding.",
        severity=severity,
        service=service,
        resource_id=resource_id,
        region="global",
        remediation="Resolve the test finding.",
        evidence={},
        compliance=[],
    )


def test_run_audit_returns_clean_summary_for_secure_environment() -> None:
    """A secure environment should receive a score of 100."""

    cloud_data = {
        "provider": "AWS",
        "account_id": "111122223333",
        "environment": "test",
        "resources": [
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
            }
        ],
    }

    summary = run_audit(cloud_data)

    assert summary.provider == "AWS"
    assert summary.account_id == "111122223333"
    assert summary.environment == "test"
    assert summary.total_resources == 1
    assert summary.findings == []
    assert summary.security_score == 100
    assert summary.risk_rating == "Low Risk"


def test_run_audit_detects_multiple_misconfigurations() -> None:
    """The audit engine should combine findings from different checks."""

    cloud_data = {
        "provider": "AWS",
        "account_id": "444455556666",
        "environment": "production",
        "resources": [
            {
                "type": "iam_user",
                "id": "admin-user",
                "region": "global",
                "configuration": {
                    "mfa_enabled": False,
                    "administrator_access": True,
                    "access_keys": [],
                },
            },
            {
                "type": "s3_bucket",
                "id": "public-bucket",
                "region": "eu-west-1",
                "configuration": {
                    "public_access": True,
                    "block_public_access": False,
                    "encryption_enabled": False,
                    "versioning_enabled": False,
                    "access_logging_enabled": False,
                },
            },
        ],
    }

    summary = run_audit(cloud_data)
    check_ids = {
        finding.check_id
        for finding in summary.findings
    }

    assert summary.total_resources == 2
    assert "IAM-001" in check_ids
    assert "IAM-005" in check_ids
    assert "STORAGE-001" in check_ids
    assert "STORAGE-002" in check_ids
    assert summary.security_score < 100
    assert summary.risk_rating in {
        "Moderate Risk",
        "High Risk",
        "Critical Risk",
    }


def test_findings_are_sorted_by_severity() -> None:
    """Critical findings should appear before lower-severity findings."""

    findings = [
        create_finding("TEST-LOW", Severity.LOW),
        create_finding("TEST-HIGH", Severity.HIGH),
        create_finding("TEST-CRITICAL", Severity.CRITICAL),
        create_finding("TEST-MEDIUM", Severity.MEDIUM),
    ]

    sorted_results = sort_findings(findings)

    assert [
        finding.severity
        for finding in sorted_results
    ] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
    ]


def test_findings_with_same_severity_are_sorted_consistently() -> None:
    """Matching severities should sort by service, resource, and check ID."""

    findings = [
        create_finding(
            "CHECK-002",
            Severity.HIGH,
            service="Storage",
            resource_id="bucket-b",
        ),
        create_finding(
            "CHECK-001",
            Severity.HIGH,
            service="IAM",
            resource_id="user-a",
        ),
        create_finding(
            "CHECK-003",
            Severity.HIGH,
            service="Storage",
            resource_id="bucket-a",
        ),
    ]

    sorted_results = sort_findings(findings)

    assert [
        finding.check_id
        for finding in sorted_results
    ] == [
        "CHECK-001",
        "CHECK-003",
        "CHECK-002",
    ]


def test_audit_summary_contains_correct_severity_counts() -> None:
    """The summary should group findings by severity correctly."""

    cloud_data = {
        "provider": "AWS",
        "account_id": "777788889999",
        "environment": "development",
        "resources": [
            {
                "type": "iam_user",
                "id": "old-user",
                "region": "global",
                "configuration": {
                    "mfa_enabled": False,
                    "administrator_access": False,
                    "access_keys": [
                        {
                            "id": "OLDKEY",
                            "age_days": 150,
                            "active": True,
                        }
                    ],
                },
            }
        ],
    }

    summary = run_audit(cloud_data)
    counts = summary.severity_counts()

    assert counts["High"] == 2
    assert counts["Critical"] == 0
    assert counts["Medium"] == 0
    assert counts["Low"] == 0
