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
- Run `make check` before pushing.

### 4. Test

```bash
make lint
make test
make check
```

All checks must pass before submitting a pull request.

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
