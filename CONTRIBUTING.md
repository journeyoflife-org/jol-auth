# Contributing to JOL

Thank you for contributing to the Journey of Life platform. This document defines the standards and workflow for all contributions to JOL repositories.

## Code of Conduct

Contributors are expected to conduct themselves in accordance with professional norms and applicable EU law. Harassment, discrimination, or abusive behaviour will not be tolerated.

## Development Workflow

### 1. Fork and Clone

Fork the repository and clone your fork locally. Add the upstream remote to stay synchronised:

```bash
git remote add upstream https://github.com/journeyoflife-org/<repository-name>.git
git fetch upstream
```

### 2. Branch

Create a feature or fix branch from `main`:

```bash
git checkout -b feature/<short-description>
```

Branch naming convention: `feature/<description>`, `fix/<description>`, `chore/<description>`.

### 3. Develop

- Follow PEP 8 for Python code.
- Write or update tests for any changed behaviour.
- Keep commits atomic and sign all commits (GPG or SSH).
- Run `make validate` and `make qodana` before pushing — see [Quality Gates](#quality-gates).

### 4. Test

```bash
make lint
make test
make qodana
make conformance
```

All checks must pass before submitting a pull request. See [Quality Gates](#quality-gates) for the full list of pre-push requirements.

### 5. Commit

Write clear, imperative commit messages:

```
feat: add pagination to congregation listing
fix: correct timezone handling in event scheduler
refactor: extract email validation into shared utility
```

Follow [Conventional Commits](https://www.conventionalcommits.org/) for consistent history.

### 6. Submit a Pull Request

- Open a pull request against `main`.
- Complete all sections of the pull request template.
- Request review from the appropriate CODEOWNERS team (auto-assigned).
- Ensure all CI checks pass.

## Review Process

- Every pull request requires at least one CODEOWNERS approval.
- Changes to security-sensitive paths (`.github/workflows/`, `SECURITY.md`, `CODEOWNERS`) require two approvals.
- Reviewers should provide actionable, constructive feedback.
- The author is responsible for addressing review comments and rebasing when requested.

## Merge Requirements

- All required status checks must pass.
- The branch must be up to date with `main`.
- No unresolved review comments.
- Signed commits enforced.

## Quality Gates

Before pushing or opening a PR, **all** of the following must pass locally:

- `make lint` — ruff check + ruff format check + mypy strict on `app/` and `src/`
- `pytest` must pass with coverage at or above the configured threshold (`--cov-fail-under`)
- `make qodana` must complete with **0 problems** (`--fail-threshold,1`)

These gates are mirrored in CI (`ci.yml`, `codeql.yml`, `qodana.yml`). A failing Qodana scan is
treated with the same severity as a lint or test failure — the change cannot merge until resolved.

### Running Qodana locally

Qodana can be invoked from the shell or directly inside PyCharm:

- **Shell:** `make qodana` (runs `qodana scan --results-dir qodana-results` via Docker).
- **PyCharm:** *Tools → Qodana → Configure* to point at `qodana.yaml` and the project root,
  then *Tools → Qodana → Run Qodana* to trigger a local scan and inspect problems inline.

The pinned linter `jetbrains/qodana-python-community:2026.1` (see `qodana.yaml`) is one of the
Python linters JetBrains ships for Qodana, so local and CI scans use the same baseline.

### Pre-push automation (optional but recommended)

To enforce the Qodana gate automatically, add a pre-push Git hook:

```bash
# .git/hooks/pre-push  (chmod +x after creating)
#!/usr/bin/env bash
set -euo pipefail
make qodana
```

If you prefer to keep all hooks under `pre-commit`, add a `pre-push` stage hook to
`.pre-commit-config.yaml` instead. Either way, the goal is identical: **no push leaves the
machine with an unclean Qodana scan.**

## Reporting Issues

Use the GitHub issue templates:

- **Bug report** — For unexpected behaviour or defects.
- **Feature request** — For proposed new functionality.

Security vulnerabilities must **not** be reported publicly. See [SECURITY.md](SECURITY.md).

## Data Protection

Given the GDPR-sensitive nature of this platform:

- Do not commit personal data, real institution identifiers, or production credentials.
- Use synthetic test data in all examples and fixtures.
- Flag any code path that processes personal data in your pull request description.

## Questions

Direct technical questions to the CODEOWNERS team listed in `.github/CODEOWNERS`.
