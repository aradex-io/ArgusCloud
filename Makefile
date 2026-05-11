.PHONY: install lint format typecheck test test-cov serve clean

# Install the package with dev extras and activate the commit-msg hook
install:
	pip install -e ".[dev]"
	git config core.hooksPath .githooks
	@echo "Git hooks activated (core.hooksPath=.githooks). See CLAUDE.md for the commit-message policy."

# Lint with ruff
lint:
	ruff check .

# Format with black (and ruff --fix for import sorting)
format:
	ruff check --fix .
	black .

# Type-check with mypy
typecheck:
	mypy arguscloud/ awshound/

# Run tests (uses addopts from pyproject.toml)
test:
	pytest

# Run tests with coverage report (explicit flags, overriding addopts)
test-cov:
	pytest --cov=arguscloud --cov=awshound --cov-report=term-missing --cov-report=html

# Start the API server in development mode
serve:
	python -m arguscloud.api.wsgi

# Remove byte-code caches and build artifacts
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov dist build *.egg-info
