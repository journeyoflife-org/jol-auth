.DEFAULT_GOAL := help

PYTHON := python3
PIP := $(PYTHON) -m pip
PRE_COMMIT := $(PYTHON) -m pre_commit
PYTEST := $(PYTHON) -m pytest
RUFF := $(PYTHON) -m ruff

.PHONY: help install install-dev lint test check scan clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	$(PIP) install -e .

install-dev: ## Install development dependencies
	$(PIP) install -e ".[dev]"
	$(PRE_COMMIT) install

lint: ## Run linting checks
	$(RUFF) check .
	$(RUFF) format --check .

format: ## Auto-format code
	$(RUFF) check --fix .
	$(RUFF) format .

test: ## Run test suite
	$(PYTEST) -v --tb=short

check: ## Run all pre-commit hooks
	$(PRE_COMMIT) run --all-files

scan: ## Run Qodana static analysis
	qodana scan --clear-cache --results-dir .qodana/results --cache-dir .qodana/cache --save-report

clean: ## Remove build artefacts and caches
	rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
