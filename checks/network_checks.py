"""Cloud network security checks."""

from typing import Any

from cloud_audit.models import Finding, Severity


SENSITIVE_PORTS: dict[int, tuple[str, Severity]] = {
    22: ("SSH", Severity.CRITICAL),
    3389: ("RDP", Severity.CRITICAL),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    1433: ("Microsoft SQL Server", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
}


def check_network_resources(
    resources: list[dict[str, Any]],
) -> list[Finding]:
    """Run network-related security checks against cloud resources."""

    findings: list[Finding] = []

    for resource in resources:
        resource_type = resource.get("type", "").lower()

        if resource_type not in {
            "security_group",
            "network_security_group",
            "firewall_rule",
        }:
            continue

        resource_id = resource.get("id", "unknown-network-resource")
        region = resource.get("region", "unknown")
        configuration = resource.get("configuration", {})

        findings.extend(
            _check_inbound_rules(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_unrestricted_egress(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

        findings.extend(
            _check_unused_security_group(
                resource_id=resource_id,
                region=region,
                configuration=configuration,
            )
        )

    return findings


def _check_inbound_rules(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect dangerous inbound rules exposed to the internet."""

    findings: list[Finding] = []
    inbound_rules = configuration.get("inbound_rules", [])

    for index, rule in enumerate(inbound_rules):
        source = str(rule.get("source", ""))
        protocol = str(rule.get("protocol", "tcp")).lower()
        from_port = rule.get("from_port")
        to_port = rule.get("to_port", from_port)

        if not _is_public_source(source):
            continue

        if protocol in {"all", "-1"}:
            findings.append(
                Finding(
                    check_id="NETWORK-001",
                    title="All inbound network traffic is publicly allowed",
                    description=(
                        "The network rule permits all protocols and ports "
                        "from the public internet."
                    ),
                    severity=Severity.CRITICAL,
                    service="Network Security",
                    resource_id=resource_id,
                    region=region,
                    remediation=(
                        "Remove the unrestricted rule and allow only required "
                        "ports from trusted IP ranges or private networks."
                    ),
                    evidence={
                        "rule_index": index,
                        "protocol": protocol,
                        "source": source,
                    },
                    compliance=[
                        "CIS AWS Foundations 5.2",
                        "NIST PR.AC-5",
                    ],
                )
            )
            continue

        if not isinstance(from_port, int) or not isinstance(to_port, int):
            continue

        for port, (service_name, severity) in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                findings.append(
                    Finding(
                        check_id="NETWORK-002",
                        title=(
                            f"{service_name} port {port} is publicly exposed"
                        ),
                        description=(
                            f"The network rule allows public access to "
                            f"{service_name} on port {port}."
                        ),
                        severity=severity,
                        service="Network Security",
                        resource_id=resource_id,
                        region=region,
                        remediation=(
                            "Restrict access to trusted IP addresses, VPN "
                            "endpoints, bastion hosts, or private networks."
                        ),
                        evidence={
                            "rule_index": index,
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "source": source,
                            "exposed_port": port,
                        },
                        compliance=[
                            "CIS AWS Foundations 5.2",
                            "CIS AWS Foundations 5.3",
                            "NIST PR.AC-5",
                        ],
                    )
                )

    return findings


def _check_unrestricted_egress(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect unrestricted outbound network access."""

    outbound_rules = configuration.get("outbound_rules", [])

    for index, rule in enumerate(outbound_rules):
        destination = str(rule.get("destination", ""))
        protocol = str(rule.get("protocol", "")).lower()

        if _is_public_source(destination) and protocol in {"all", "-1"}:
            return [
                Finding(
                    check_id="NETWORK-003",
                    title="Unrestricted outbound network access detected",
                    description=(
                        "The network resource permits all outbound traffic "
                        "to the public internet."
                    ),
                    severity=Severity.MEDIUM,
                    service="Network Security",
                    resource_id=resource_id,
                    region=region,
                    remediation=(
                        "Restrict outbound traffic to approved destinations "
                        "and required services wherever operationally possible."
                    ),
                    evidence={
                        "rule_index": index,
                        "protocol": protocol,
                        "destination": destination,
                    },
                    compliance=[
                        "NIST PR.AC-5",
                        "NIST DE.CM-1",
                    ],
                )
            ]

    return []


def _check_unused_security_group(
    resource_id: str,
    region: str,
    configuration: dict[str, Any],
) -> list[Finding]:
    """Detect security groups not attached to cloud resources."""

    if configuration.get("attached", True):
        return []

    return [
        Finding(
            check_id="NETWORK-004",
            title="Unused network security group detected",
            description=(
                "The network security group is not attached to a resource "
                "and may represent unnecessary or outdated configuration."
            ),
            severity=Severity.LOW,
            service="Network Security",
            resource_id=resource_id,
            region=region,
            remediation=(
                "Review the security group and delete it if it is no longer "
                "required."
            ),
            evidence={
                "attached": configuration.get("attached", True),
            },
            compliance=[
                "NIST PR.IP-1",
            ],
        )
    ]


def _is_public_source(source: str) -> bool:
    """Return whether a network source represents public internet access."""

    normalised_source = source.strip().lower()

    return normalised_source in {
        "0.0.0.0/0",
        "::/0",
        "any",
        "*",
        "internet",
    }
