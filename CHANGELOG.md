# Changelog

All notable changes to the Cloud Security Audit Toolkit are documented in this file.

The project follows semantic versioning where practical.

## [1.0.0] - 2026-07-29

### Added

- Initial stable release of the Cloud Security Audit Toolkit
- Modular cloud-security audit engine
- AWS-style cloud resource support
- IAM security checks
- Object-storage security checks
- Network-security checks
- Encryption and data-protection checks
- Logging and monitoring checks
- Security findings with evidence and remediation guidance
- Critical, High, Medium, Low, and Informational severity levels
- Security posture score from 0 to 100
- Human-readable risk ratings
- JSON configuration loader and validation
- JSON report generation
- CSV report generation
- Markdown report generation
- Standalone HTML report generation
- Vulnerable sample cloud environment
- Secure sample cloud environment
- Command-line interface
- Automated unit tests
- Test coverage for audit logic, checks, and risk scoring
- GitHub Actions testing on Python 3.10, 3.11, and 3.12
- Automated sample-environment audits
- Generated report artifacts in GitHub Actions
- Ruff code-quality checks
- Complete project documentation
- Contribution guidelines
- Security policy
- MIT Licence

### Security Checks Included

#### IAM

- Missing multi-factor authentication
- Multiple active access keys
- Access keys older than 90 days
- Inactive access keys
- Direct administrator privileges

#### Storage

- Publicly accessible storage buckets
- Disabled public-access blocking
- Missing encryption at rest
- Disabled versioning
- Disabled access logging

#### Network

- Publicly exposed SSH
- Publicly exposed RDP
- Publicly exposed database services
- Unrestricted inbound access
- Unrestricted outbound access
- Unused security groups

#### Encryption

- Missing encryption at rest
- Provider-managed keys used instead of customer-managed keys
- Unencrypted snapshots and backups

#### Logging and Monitoring

- Disabled cloud audit logging
- Missing log integrity validation
- Unencrypted audit logs
- Disabled security alerts
- Insufficient log retention

## [Unreleased]

### Planned

- Microsoft Azure security checks
- Google Cloud Platform security checks
- Native cloud API integrations
- YAML input support
- Custom policy definitions
- Compliance profiles
- SARIF report export
- Docker support
- Web dashboard
- Historical audit comparison
- Risk-trend visualisation
