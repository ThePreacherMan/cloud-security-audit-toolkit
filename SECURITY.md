# Security Policy

## Supported Versions

Security updates are currently provided for the latest stable release of the Cloud Security Audit Toolkit.

| Version | Supported |
|---|---|
| 1.x | Yes |
| Earlier versions | No |

## Reporting a Vulnerability

Please do not disclose security vulnerabilities publicly through GitHub Issues, discussions, pull requests, or social media.

Report suspected vulnerabilities privately by contacting the project maintainer through the contact details available on the maintainer’s GitHub profile.

Include as much of the following information as possible:

- A clear description of the vulnerability
- The affected file, module, or feature
- Steps required to reproduce the issue
- The potential security impact
- Relevant logs, screenshots, or proof-of-concept details
- Suggested remediation, where available
- Whether the vulnerability is already publicly known

Do not include real cloud credentials, access tokens, private keys, customer data, or sensitive production information in the report.

## Response Process

After receiving a security report, the maintainer will aim to:

1. Acknowledge the report
2. Review and reproduce the issue
3. Assess its severity and impact
4. Develop and test an appropriate fix
5. Publish an updated release when necessary
6. Credit the reporter where appropriate and requested

Response times may vary because this is an independently maintained open-source portfolio project.

## Scope

Security reports may include vulnerabilities involving:

- Unsafe handling of configuration files
- Path traversal or arbitrary file access
- Insecure report generation
- HTML injection
- Improper input validation
- Dependency vulnerabilities
- Exposure of secrets or sensitive information
- Incorrect security findings that create material risk
- GitHub Actions or supply-chain weaknesses
- Packaging and installation security issues

## Out of Scope

The following are generally outside the project’s vulnerability-reporting scope:

- Security weaknesses in cloud environments being audited
- Issues caused by intentionally malformed local files without meaningful impact
- Feature requests
- General code-quality suggestions
- Missing security checks
- False positives that do not create a security vulnerability in the toolkit
- Social-engineering attacks against the maintainer
- Denial-of-service testing against GitHub or third-party services

These may still be submitted as normal GitHub Issues where appropriate.

## Safe Testing Guidelines

When investigating the toolkit:

- Use only systems, files, and cloud environments you own or are authorised to test
- Use synthetic configuration data whenever possible
- Do not access another person’s cloud account or data
- Do not perform destructive testing
- Do not attempt to obtain real credentials
- Do not intentionally disrupt project infrastructure or third-party services
- Stop testing if sensitive information is exposed unexpectedly

## Credential and Data Handling

The toolkit is designed to audit local JSON configuration files without requiring live cloud credentials.

Users should still ensure that input files do not contain:

- Access keys
- Secret keys
- Session tokens
- Passwords
- Private encryption keys
- Customer personal information
- Proprietary infrastructure details that should not be shared

Sample data included in the repository uses fictional identifiers only.

## Responsible Disclosure

Please allow reasonable time for investigation and remediation before publicly discussing a confirmed vulnerability.

Coordinated disclosure helps protect users and allows fixes to be prepared before technical details are published.

## Security Disclaimer

This project supports defensive security, authorised auditing, education, portfolio demonstration, and security research.

It does not provide formal compliance certification, guarantee that an environment is secure, or replace a complete cloud-security assessment conducted by qualified professionals.

Users remain responsible for validating findings and protecting their own systems, data, and credentials.
