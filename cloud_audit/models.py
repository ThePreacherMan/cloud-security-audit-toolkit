"""Core data models for the Cloud Security Audit Toolkit."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Supported security finding severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


@dataclass(frozen=True)
class Finding:
    """Represents a single cloud security audit finding."""

    check_id: str
    title: str
    description: str
    severity: Severity
    service: str
    resource_id: str
    region: str
    remediation: str
    evidence: dict[str, Any]
    compliance: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding into a serialisable dictionary."""

        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class AuditSummary:
    """Represents the final result of a cloud security audit."""

    provider: str
    account_id: str
    environment: str
    total_resources: int
    findings: list[Finding]
    security_score: int
    risk_rating: str

    def severity_counts(self) -> dict[str, int]:
        """Return the number of findings grouped by severity."""

        counts = {severity.value: 0 for severity in Severity}

        for finding in self.findings:
            counts[finding.severity.value] += 1

        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert the audit summary into a serialisable dictionary."""

        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "environment": self.environment,
            "total_resources": self.total_resources,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "security_score": self.security_score,
            "risk_rating": self.risk_rating,
            "findings": [finding.to_dict() for finding in self.findings],
        }
