"""Risk scoring utilities for cloud security audit findings."""

from collections.abc import Iterable

from cloud_audit.models import Finding, Severity


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 0,
}


def calculate_security_score(findings: Iterable[Finding]) -> int:
    """Calculate a security posture score between 0 and 100.

    The score starts at 100 and decreases based on the severity
    of detected findings.
    """

    total_penalty = sum(
        SEVERITY_WEIGHTS[finding.severity]
        for finding in findings
    )

    return max(0, 100 - total_penalty)


def determine_risk_rating(score: int) -> str:
    """Return a human-readable risk rating for a security score."""

    if score >= 90:
        return "Low Risk"

    if score >= 75:
        return "Moderate Risk"

    if score >= 50:
        return "High Risk"

    return "Critical Risk"


def calculate_risk_metrics(
    findings: list[Finding],
) -> tuple[int, str]:
    """Calculate the security score and corresponding risk rating."""

    score = calculate_security_score(findings)
    rating = determine_risk_rating(score)

    return score, rating
