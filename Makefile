# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

.DEFAULT_GOAL := help

PYTHON := python3
PIP := $(PYTHON) -m pip
PRE_COMMIT := $(PYTHON) -m pre_commit
PYTEST := $(PYTHON) -m pytest
RUFF := $(PYTHON) -m ruff
MYPY := $(PYTHON) -m mypy

.PHONY: help install install-dev lint test check scan validate conformance qodana clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -e .

install-dev: ## Install development dependencies
	$(PIP) install -e ".[dev]"
	$(PRE_COMMIT) install

lint: ## Run linting checks (ruff, format, mypy)
	$(RUFF) check .
	$(RUFF) format --check .
	$(MYPY) app/ src/

format: ## Auto-format code
	$(RUFF) check --fix .
	$(RUFF) format .

test: ## Run test suite with coverage threshold
	$(PYTEST) -v --tb=short --cov=app --cov=src --cov-report=term-missing --cov-fail-under=18

check: ## Run all pre-commit hooks
	$(PRE_COMMIT) run --all-files

scan: ## Run static analysis and dependency audit (detect-secrets, bandit rules, pip-audit)
	detect-secrets scan --baseline .secrets.baseline
	$(RUFF) check --select S app/
	pip-audit

validate: lint test scan ## Run full pre-push validation (lint + test + scan)

conformance: ## Run OIDC conformance test suite
	$(PYTEST) tests/integration/test_discovery_document.py tests/integration/test_jwks_endpoint.py tests/integration/test_authorization_code_flow.py tests/integration/test_client_credentials_flow.py -v --tb=short

qodana: ## Run Qodana static analysis (Docker)
	qodana scan --results-dir qodana-results

clean: ## Remove build artefacts and caches
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
