# JOL Repository Template

Enterprise-grade repository template for the **Journey of Life (JOL)** platform — serving approximately 400,000 religious institution websites across 27 EU member states.

## Purpose

This template establishes the baseline structure, tooling configuration, and compliance scaffolding for all new JOL repositories. Every repository created from this template inherits:

- A CI/CD pipeline built on GitHub Actions
- Security controls aligned with ISO 27001 and SOC 2
- Privacy governance compatible with GDPR requirements
- Automated code-quality enforcement via pre-commit hooks and Qodana
- Dependabot-driven dependency updates routed through CODEOWNERS review

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
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── .gitignore
├── .editorconfig
├── Makefile
├── pyproject.toml
├── qodana.yaml
├── .pre-commit-config.yaml
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   └── feature_request.yml
│   └── workflows/
│       ├── ci.yml
│       ├── compliance-check.yml
│       └── codeql.yml
└── docs/
    ├── architecture.md
    └── DPIA-template.md
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
