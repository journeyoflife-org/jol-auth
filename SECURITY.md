# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security updates. Prior versions are not supported.

| Version         | Supported |
|-----------------|-----------|
| `main` (latest) | Yes       |
| Older releases  | No        |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a vulnerability in this repository, report it through one of the following channels:

1. **GitHub Security Advisories** — Use the "Report a vulnerability" button on the repository's Security tab (preferred).
2. **Email** — Send an encrypted message to `security@journeyoflife.org` using the organisation's published PGP key.

Include the following in your report:

- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept where feasible.
- Affected component, file path, and version.
- Any suggested remediation.

## Response Timeline

| Phase                    | Target SLA     |
|--------------------------|----------------|
| Acknowledgement          | 2 business days |
| Triage and severity      | 5 business days |
| Remediation plan         | 10 business days |
| Patch deployment         | Proportional to severity |

## Severity Classification

Severity is assessed using CVSS v3.1:

| Rating   | Score    | Response                                    |
|----------|----------|---------------------------------------------|
| Critical | 9.0–10.0 | Immediate remediation; emergency release    |
| High     | 7.0–8.9  | Prioritised remediation within one sprint   |
| Medium   | 4.0–6.9  | Scheduled remediation in next release cycle |
| Low      | 0.1–3.9  | Tracked; remediated as capacity allows      |

## Disclosure Policy

- The reporter receives credit unless they request anonymity.
- Public disclosure occurs only after a patch is available and affected parties have been notified.
- A minimum 90-day embargo applies unless the vulnerability is actively exploited.

## Security Controls

This repository enforces the following security baselines:

- **Signed commits** — All commits to protected branches must be GPG or SSH-signed.
- **Secret scanning** — GitHub Advanced Security secret scanning is enabled repository-wide.
- **Dependency scanning** — Dependabot alerts and CodeQL analysis run on every pull request.
- **Branch protection** — The `main` branch requires status checks, CODEOWNERS review, and up-to-date history.
- **Least privilege** — GitHub Actions workflows use the minimum required permissions via explicit `permissions` blocks.
