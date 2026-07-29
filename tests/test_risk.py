"""Tests for cloud security risk scoring."""

from cloud_audit.models import Finding, Severity
from cloud_audit.risk import (
    calculate_risk_metrics,
    calculate_security_score,
    determine_risk_rating,
)


def create_finding(severity: Severity) -> Finding:
    """Create a reusable finding for risk-scoring tests."""

    return Finding(
        check_id="TEST-001",
        title="Test finding",
        description="A finding created for automated testing.",
        severity=severity,
        service="Test Service",
        resource_id="test-resource",
        region="global",
        remediation="Resolve the test finding.",
        evidence={},
        compliance=[],
    )


def test_score_is_100_when_no_findings_exist() -> None:
    """A clean environment should receive the maximum score."""

    assert calculate_security_score([]) == 100


def test_score_decreases_using_severity_weights() -> None:
    """Finding penalties should reduce the security score correctly."""

    findings = [
        create_finding(Severity.CRITICAL),
        create_finding(Severity.HIGH),
        create_finding(Severity.MEDIUM),
        create_finding(Severity.LOW),
    ]

    assert calculate_security_score(findings) == 49


def test_score_never_falls_below_zero() -> None:
    """The security score should not become negative."""

    findings = [
        create_finding(Severity.CRITICAL)
        for _ in range(10)
    ]

    assert calculate_security_score(findings) == 0


def test_risk_rating_thresholds() -> None:
    """Scores should map to the correct risk-rating bands."""

    assert determine_risk_rating(100) == "Low Risk"
    assert determine_risk_rating(90) == "Low Risk"
    assert determine_risk_rating(89) == "Moderate Risk"
    assert determine_risk_rating(75) == "Moderate Risk"
    assert determine_risk_rating(74) == "High Risk"
    assert determine_risk_rating(50) == "High Risk"
    assert determine_risk_rating(49) == "Critical Risk"
    assert determine_risk_rating(0) == "Critical Risk"


def test_calculate_risk_metrics_returns_score_and_rating() -> None:
    """The combined helper should return both risk values."""

    findings = [
        create_finding(Severity.HIGH),
    ]

    score, rating = calculate_risk_metrics(findings)

    assert score == 85
    assert rating == "Moderate Risk"
