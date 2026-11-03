# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Adopted mise: `mise.toml` + `mise.lock` pin python 3.12.16 and uv (per-platform SHA256 + GitHub attestations); CI Lint/Test/Pre-commit jobs bootstrap tools via pinned `jdx/mise-action` (were unpinned `setup-python@v5` + `pip install -e`). Job names preserved.

- Repository template baseline structure.
- GitHub Actions workflows: CI, compliance-check, and CodeQL.
- CODEOWNERS-driven review routing.
- Dependabot configuration for automated dependency updates.
- Pre-commit hook configuration.
- Qodana static analysis profile.
- `pyproject.toml` with build system and tooling configuration.
- Issue templates for bug reports and feature requests.
- Pull request template.
- Architecture and DPIA documentation.
