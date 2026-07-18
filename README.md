# JOL Auth

Authentication and identity management service for the **Journey of Life (JOL)** platform — serving approximately 400,000 religious institution websites across 27 EU member states.

## Purpose

`jol-auth` is the central identity service in the JOL Shared Services Layer. It provides:

- **OAuth 2.0 / OpenID Connect** token issuance and validation
- **Multi-tenant RBAC** with per-institution isolation
- **Short-lived credentials** for service-to-service communication
- **Session management** with GDPR-compliant consent tracking
- **Audit event emission** for all authentication operations

## Quick Start

```bash
# Clone the repository
git clone https://github.com/journeyoflife-org/<repository-name>.git
cd <repository-name>

# Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install development dependencies
make install-dev

# Install pre-commit hooks
pre-commit install
```

## Repository Structure

```
├── src/
│   └── jol_auth/          # Package source
├── tests/                 # Test suite
├── docs/
│   ├── architecture.md
│   └── DPIA-template.md
├── pyproject.toml
├── Makefile
└── .github/
    └── workflows/         # CI, compliance, CodeQL
```

## Compliance Baseline

| Standard       | Scope                                       |
|----------------|---------------------------------------------|
| GDPR           | Data processing, DPIA, cross-border transfer |
| ISO 27001      | Information security management              |
| SOC 2          | Trust service criteria                       |

All pull requests are subject to CODEOWNERS review. Security-sensitive paths require additional approvers as defined in `.github/CODEOWNERS`.

## Workflows

| Workflow             | Trigger                         | Purpose                                      |
|----------------------|---------------------------------|----------------------------------------------|
| `ci.yml`             | Push to `main`, pull requests   | Lint, test, build validation                 |
| `compliance-check.yml` | Pull requests                 | License header and policy enforcement        |
| `codeql.yml`         | Push to `main`, pull requests   | Static analysis and vulnerability scanning   |

## Development

```bash
# Run linting
make lint

# Run tests
make test

# Run full pre-commit suite
make check
```

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process and security policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and the development workflow.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
