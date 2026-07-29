# Cloud Security Audit Toolkit

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Tests](https://img.shields.io/github/actions/workflow/status/ThePreacherMan/cloud-security-audit-toolkit/tests.yml?label=tests)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Focus-Cloud%20Security-red)

A Python-based cloud security posture auditing toolkit that detects misconfigurations, calculates security scores, maps findings to recognised security controls, and generates actionable remediation reports.

## Overview

Cloud Security Audit Toolkit is a portfolio-grade security automation project designed to simulate a lightweight Cloud Security Posture Management workflow.

It analyses structured cloud configuration data, identifies common security weaknesses, assigns severity levels, calculates an overall posture score, and exports detailed audit reports in multiple formats.

The current release supports AWS-style resource configurations and is designed for future extension to Microsoft Azure and Google Cloud Platform.

## Key Features

- IAM security assessment
- Public storage exposure detection
- Network security-group analysis
- Encryption-at-rest checks
- Logging and monitoring validation
- Access-key age and MFA checks
- Severity-based risk scoring
- Security posture score from 0 to 100
- Critical, High, Medium, Low, and Informational findings
- JSON, CSV, Markdown, and HTML reports
- Secure and vulnerable sample environments
- Automated testing across Python 3.10, 3.11, and 3.12
- GitHub Actions continuous integration
- Compliance references and remediation guidance
- No live cloud credentials required

## Security Checks

### Identity and Access Management

- Users without multi-factor authentication
- Multiple active access keys
- Access keys older than 90 days
- Inactive access keys
- Direct administrator privileges

### Object Storage

- Publicly accessible buckets
- Disabled public-access blocking
- Missing encryption
- Disabled versioning
- Disabled access logging

### Network Security

- Unrestricted inbound access
- Public SSH exposure
- Public RDP exposure
- Public database-port exposure
- Unrestricted outbound access
- Unused security groups

### Encryption

- Missing encryption at rest
- Provider-managed keys used instead of customer-managed keys
- Unencrypted snapshots and backups

### Logging and Monitoring

- Disabled cloud audit logging
- Missing log integrity validation
- Unencrypted audit logs
- Disabled security alerts
- Insufficient log retention

## Live Demo

[Launch the Cloud Security Audit Toolkit](https://cloud-security-audit-toolkit.streamlit.app/)

## Project Structure

```text
cloud-security-audit-toolkit/
├── cloud_audit/
│   ├── __init__.py
│   ├── auditor.py
│   ├── loader.py
│   ├── models.py
│   ├── reporter.py
│   └── risk.py
├── checks/
│   ├── __init__.py
│   ├── encryption_checks.py
│   ├── iam_checks.py
│   ├── logging_checks.py
│   ├── network_checks.py
│   └── storage_checks.py
├── sample_data/
│   ├── secure_environment.json
│   └── vulnerable_environment.json
├── tests/
│   ├── __init__.py
│   ├── test_auditor.py
│   ├── test_checks.py
│   └── test_risk.py
├── reports/
│   └── .gitkeep
├── .github/
│   └── workflows/
│       └── tests.yml
├── main.py
├── requirements.txt
├── pyproject.toml
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
└── LICENSE
