# HexStrike AI - Makefile

**Purpose:** Development automation and build management for the modularized HexStrike AI framework, providing convenient commands for common development tasks.

**Status:** Proposed (designed for modular architecture development workflow)

## Main Makefile

### Makefile
```makefile
# HexStrike AI Framework - Development Makefile
# Provides convenient commands for development, testing, and deployment

.PHONY: help install install-dev clean test lint format type-check security-check
.PHONY: run run-dev run-prod build docker-build docker-run docker-compose
.PHONY: docs docs-serve migrate backup restore deploy quality-check
.PHONY: ctf-setup bugbounty-setup cloud-setup tools-check

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := pip3
VENV := hexstrike_env
SRC_DIR := src/hexstrike
TEST_DIR := tests
DOCS_DIR := docs
CONFIG_DIR := config
DOCKER_IMAGE := hexstrike-ai
DOCKER_TAG := latest

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[0;37m
RESET := \033[0m

# Help target
help: ## Show this help message
	@echo "$(CYAN)HexStrike AI Framework - Development Commands$(RESET)"
	@echo ""
	@echo "$(YELLOW)Setup Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "(install|setup|clean)"
	@echo ""
	@echo "$(YELLOW)Development Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "(run|dev|test|lint|format)"
	@echo ""
	@echo "$(YELLOW)Quality Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "(quality|type|security)"
	@echo ""
	@echo "$(YELLOW)Deployment Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "(build|docker|deploy)"
	@echo ""
	@echo "$(YELLOW)Utility Commands:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST) | grep -E "(docs|migrate|backup|tools)"

# Setup Commands
install: ## Install production dependencies
	@echo "$(BLUE)Installing production dependencies...$(RESET)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)Production dependencies installed!$(RESET)"

install-dev: ## Install development dependencies and setup environment
	@echo "$(BLUE)Setting up development environment...$(RESET)"
	$(PYTHON) -m venv $(VENV)
	. $(VENV)/bin/activate && \
	$(PIP) install --upgrade pip && \
	$(PIP) install -r requirements-dev.txt && \
	pre-commit install
	@echo "$(GREEN)Development environment ready!$(RESET)"
	@echo "$(YELLOW)Activate with: source $(VENV)/bin/activate$(RESET)"

clean: ## Clean up generated files and caches
	@echo "$(BLUE)Cleaning up...$(RESET)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ coverage.xml test-results.xml
	rm -rf logs/*.log
	@echo "$(GREEN)Cleanup complete!$(RESET)"

# Development Commands
run: ## Run the application in production mode
	@echo "$(BLUE)Starting HexStrike AI (production mode)...$(RESET)"
	FLASK_ENV=production $(PYTHON) -m hexstrike.main

run-dev: ## Run the application in development mode with hot reload
	@echo "$(BLUE)Starting HexStrike AI (development mode)...$(RESET)"
	FLASK_ENV=development FLASK_DEBUG=1 $(PYTHON) -m hexstrike.main

run-prod: ## Run the application with production settings
	@echo "$(BLUE)Starting HexStrike AI (production mode with gunicorn)...$(RESET)"
	gunicorn --config gunicorn.conf.py hexstrike.main:app

# Testing Commands
test: ## Run all tests
	@echo "$(BLUE)Running all tests...$(RESET)"
	pytest $(TEST_DIR)/ -v --tb=short

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(RESET)"
	pytest $(TEST_DIR)/unit/ -v -m "unit"

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(RESET)"
	pytest $(TEST_DIR)/integration/ -v -m "integration"

test-e2e: ## Run end-to-end tests
	@echo "$(BLUE)Running end-to-end tests...$(RESET)"
	pytest $(TEST_DIR)/e2e/ -v -m "e2e"

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	pytest $(TEST_DIR)/ --cov=$(SRC_DIR) --cov-report=html --cov-report=term --cov-report=xml
	@echo "$(GREEN)Coverage report generated in htmlcov/$(RESET)"

test-performance: ## Run performance tests
	@echo "$(BLUE)Running performance tests...$(RESET)"
	pytest $(TEST_DIR)/performance/ -v -m "performance"

test-security: ## Run security tests
	@echo "$(BLUE)Running security tests...$(RESET)"
	pytest $(TEST_DIR)/security/ -v -m "security"

# Code Quality Commands
lint: ## Run linting checks
	@echo "$(BLUE)Running linting checks...$(RESET)"
	ruff check $(SRC_DIR)/ $(TEST_DIR)/
	@echo "$(GREEN)Linting complete!$(RESET)"

lint-fix: ## Run linting with auto-fix
	@echo "$(BLUE)Running linting with auto-fix...$(RESET)"
	ruff check $(SRC_DIR)/ $(TEST_DIR)/ --fix
	@echo "$(GREEN)Linting with auto-fix complete!$(RESET)"

format: ## Format code with ruff
	@echo "$(BLUE)Formatting code...$(RESET)"
	ruff format $(SRC_DIR)/ $(TEST_DIR)/
	@echo "$(GREEN)Code formatting complete!$(RESET)"

type-check: ## Run type checking with mypy
	@echo "$(BLUE)Running type checking...$(RESET)"
	mypy $(SRC_DIR)/ --config-file mypy.ini
	@echo "$(GREEN)Type checking complete!$(RESET)"

security-check: ## Run security checks
	@echo "$(BLUE)Running security checks...$(RESET)"
	bandit -r $(SRC_DIR)/ -f json -o security-report.json || true
	safety check --json --output safety-report.json || true
	@echo "$(GREEN)Security checks complete!$(RESET)"

quality-check: lint type-check security-check ## Run all quality checks
	@echo "$(GREEN)All quality checks complete!$(RESET)"

# Line limit and architecture checks
check-line-limits: ## Check that all modules are ≤300 lines
	@echo "$(BLUE)Checking line limits...$(RESET)"
	@find $(SRC_DIR)/ -name "*.py" -not -path "*/legacy/*" | while read file; do \
		lines=$$(wc -l < "$$file"); \
		if [ $$lines -gt 300 ]; then \
			echo "$(RED)❌ $$file: $$lines lines (exceeds 300)$(RESET)"; \
			exit 1; \
		else \
			echo "$(GREEN)✅ $$file: $$lines lines$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)All modules within 300-line limit!$(RESET)"

check-imports: ## Check for import cycles
	@echo "$(BLUE)Checking for import cycles...$(RESET)"
	$(PYTHON) -c "import grimp; graph = grimp.build_graph('$(SRC_DIR)'); cycles = graph.find_cycles(); print('✅ No cycles' if not cycles else f'❌ Cycles: {cycles}'); exit(1 if cycles else 0)"
	@echo "$(GREEN)No import cycles detected!$(RESET)"

check-duplication: ## Check for code duplication
	@echo "$(BLUE)Checking for code duplication...$(RESET)"
	jscpd --threshold 3 --min-lines 5 --reporters console $(SRC_DIR)/ || (echo "$(RED)❌ Code duplication exceeds 3% threshold$(RESET)" && exit 1)
	@echo "$(GREEN)Code duplication within acceptable limits!$(RESET)"

architecture-check: check-line-limits check-imports check-duplication ## Run all architecture compliance checks
	@echo "$(GREEN)All architecture checks passed!$(RESET)"

# Build Commands
build: clean ## Build the application
	@echo "$(BLUE)Building application...$(RESET)"
	$(PYTHON) setup.py sdist bdist_wheel
	@echo "$(GREEN)Build complete!$(RESET)"

# Docker Commands
docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(RESET)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(RESET)"

docker-run: ## Run Docker container
	@echo "$(BLUE)Running Docker container...$(RESET)"
	docker run -p 8888:8888 --env-file .env $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-compose: ## Run with docker-compose
	@echo "$(BLUE)Starting services with docker-compose...$(RESET)"
	docker-compose up -d
	@echo "$(GREEN)Services started! Access at http://localhost:8888$(RESET)"

docker-compose-dev: ## Run development environment with docker-compose
	@echo "$(BLUE)Starting development environment...$(RESET)"
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
	@echo "$(GREEN)Development environment started!$(RESET)"

docker-logs: ## View docker-compose logs
	docker-compose logs -f

docker-stop: ## Stop docker-compose services
	@echo "$(BLUE)Stopping services...$(RESET)"
	docker-compose down
	@echo "$(GREEN)Services stopped!$(RESET)"

# Documentation Commands
docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(RESET)"
	cd $(DOCS_DIR) && make html
	@echo "$(GREEN)Documentation generated in $(DOCS_DIR)/_build/html/$(RESET)"

docs-serve: ## Serve documentation locally
	@echo "$(BLUE)Serving documentation at http://localhost:8000$(RESET)"
	cd $(DOCS_DIR)/_build/html && $(PYTHON) -m http.server 8000

docs-clean: ## Clean documentation build
	@echo "$(BLUE)Cleaning documentation...$(RESET)"
	cd $(DOCS_DIR) && make clean
	@echo "$(GREEN)Documentation cleaned!$(RESET)"

# Database Commands
migrate: ## Run database migrations
	@echo "$(BLUE)Running database migrations...$(RESET)"
	alembic upgrade head
	@echo "$(GREEN)Migrations complete!$(RESET)"

migrate-create: ## Create new migration
	@echo "$(BLUE)Creating new migration...$(RESET)"
	@read -p "Migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"
	@echo "$(GREEN)Migration created!$(RESET)"

backup: ## Backup database
	@echo "$(BLUE)Creating database backup...$(RESET)"
	pg_dump $(DB_URL) > backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "$(GREEN)Database backup created!$(RESET)"

restore: ## Restore database from backup
	@echo "$(BLUE)Restoring database...$(RESET)"
	@read -p "Backup file path: " backup_file; \
	psql $(DB_URL) < $$backup_file
	@echo "$(GREEN)Database restored!$(RESET)"

# Specialized Setup Commands
ctf-setup: ## Setup CTF-specific tools and dependencies
	@echo "$(BLUE)Setting up CTF environment...$(RESET)"
	sudo apt-get update
	sudo apt-get install -y gdb radare2 binutils
	$(PIP) install pwntools ropper angr
	# Install additional CTF tools
	@if [ ! -d "/opt/ghidra" ]; then \
		echo "$(YELLOW)Please install Ghidra manually from https://ghidra-sre.org/$(RESET)"; \
	fi
	@echo "$(GREEN)CTF environment setup complete!$(RESET)"

bugbounty-setup: ## Setup bug bounty specific tools
	@echo "$(BLUE)Setting up bug bounty environment...$(RESET)"
	# Install common bug bounty tools
	go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
	go install github.com/projectdiscovery/katana/cmd/katana@latest
	# Update nuclei templates
	nuclei -update-templates
	@echo "$(GREEN)Bug bounty environment setup complete!$(RESET)"

cloud-setup: ## Setup cloud security tools
	@echo "$(BLUE)Setting up cloud security environment...$(RESET)"
	# Install cloud CLI tools
	$(PIP) install awscli azure-cli
	# Install cloud security tools
	$(PIP) install prowler scout-suite
	@echo "$(GREEN)Cloud security environment setup complete!$(RESET)"

tools-check: ## Check availability of security tools
	@echo "$(BLUE)Checking security tool availability...$(RESET)"
	@tools="nmap gobuster nuclei sqlmap ffuf hydra amass subfinder"; \
	for tool in $$tools; do \
		if command -v $$tool >/dev/null 2>&1; then \
			echo "$(GREEN)✅ $$tool$(RESET)"; \
		else \
			echo "$(RED)❌ $$tool (not found)$(RESET)"; \
		fi; \
	done
	@echo "$(BLUE)Tool check complete!$(RESET)"

# Deployment Commands
deploy-staging: ## Deploy to staging environment
	@echo "$(BLUE)Deploying to staging...$(RESET)"
	# Add staging deployment commands here
	@echo "$(GREEN)Deployed to staging!$(RESET)"

deploy-prod: ## Deploy to production environment
	@echo "$(BLUE)Deploying to production...$(RESET)"
	# Add production deployment commands here
	@echo "$(GREEN)Deployed to production!$(RESET)"

# Monitoring Commands
logs: ## View application logs
	@echo "$(BLUE)Viewing application logs...$(RESET)"
	tail -f logs/hexstrike.log

logs-error: ## View error logs only
	@echo "$(BLUE)Viewing error logs...$(RESET)"
	grep -i error logs/hexstrike.log | tail -20

monitor: ## Start monitoring dashboard
	@echo "$(BLUE)Starting monitoring dashboard...$(RESET)"
	# Start Prometheus and Grafana if available
	@if command -v prometheus >/dev/null 2>&1; then \
		prometheus --config.file=monitoring/prometheus.yml & \
	fi
	@if command -v grafana-server >/dev/null 2>&1; then \
		grafana-server --config=monitoring/grafana.ini & \
	fi
	@echo "$(GREEN)Monitoring dashboard started!$(RESET)"

# Utility Commands
config-validate: ## Validate configuration files
	@echo "$(BLUE)Validating configuration...$(RESET)"
	$(PYTHON) scripts/validate_config.py config/config.yaml
	@echo "$(GREEN)Configuration validation complete!$(RESET)"

secrets-check: ## Check for exposed secrets
	@echo "$(BLUE)Checking for exposed secrets...$(RESET)"
	truffleHog --regex --entropy=False .
	@echo "$(GREEN)Secret check complete!$(RESET)"

performance-profile: ## Run performance profiling
	@echo "$(BLUE)Running performance profiling...$(RESET)"
	$(PYTHON) -m cProfile -o profile.stats -m hexstrike.main &
	sleep 30
	pkill -f "hexstrike.main"
	$(PYTHON) -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(20)"
	@echo "$(GREEN)Performance profiling complete!$(RESET)"

# Development workflow shortcuts
dev-setup: install-dev tools-check config-validate ## Complete development setup
	@echo "$(GREEN)Development environment fully configured!$(RESET)"

quick-test: lint-fix test-unit ## Quick development test cycle
	@echo "$(GREEN)Quick test cycle complete!$(RESET)"

full-check: quality-check architecture-check test-coverage ## Full quality and test check
	@echo "$(GREEN)Full quality check complete!$(RESET)"

release-check: full-check build ## Pre-release validation
	@echo "$(GREEN)Release validation complete!$(RESET)"

# Environment info
env-info: ## Show environment information
	@echo "$(CYAN)Environment Information:$(RESET)"
	@echo "Python version: $$($(PYTHON) --version)"
	@echo "Pip version: $$($(PIP) --version)"
	@echo "Virtual env: $$(if [ -n "$$VIRTUAL_ENV" ]; then echo "$$VIRTUAL_ENV"; else echo "None"; fi)"
	@echo "Current directory: $$(pwd)"
	@echo "Git branch: $$(git branch --show-current 2>/dev/null || echo 'Not a git repo')"
	@echo "Git status: $$(git status --porcelain 2>/dev/null | wc -l) modified files"

# Include additional makefiles if they exist
-include Makefile.local
```

## Specialized Makefiles

### Makefile.docker
```makefile
# Docker-specific commands for HexStrike AI

# Docker variables
DOCKER_REGISTRY := hexstrike
DOCKER_IMAGE := hexstrike-ai
DOCKER_TAG := $(shell git rev-parse --short HEAD)
DOCKER_LATEST := latest

# Multi-stage build targets
docker-build-dev: ## Build development Docker image
	docker build --target development -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):dev .

docker-build-prod: ## Build production Docker image
	docker build --target production -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_LATEST)

docker-push: ## Push Docker images to registry
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_LATEST)

docker-scan: ## Scan Docker image for vulnerabilities
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy image $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-clean: ## Clean up Docker images and containers
	docker system prune -f
	docker image prune -f
```

### Makefile.ci
```makefile
# CI/CD specific commands

# CI variables
CI_PYTHON_VERSION := 3.11
CI_NODE_VERSION := 18

ci-setup: ## Setup CI environment
	$(PYTHON) -m pip install --upgrade pip
	$(PIP) install -r requirements-dev.txt

ci-test: ## Run tests in CI environment
	pytest $(TEST_DIR)/ \
		--junitxml=test-results.xml \
		--cov=$(SRC_DIR) \
		--cov-report=xml:coverage.xml \
		--cov-report=term

ci-quality: ## Run quality checks in CI
	ruff check $(SRC_DIR)/ --output-format=github
	mypy $(SRC_DIR)/ --junit-xml=mypy-results.xml
	bandit -r $(SRC_DIR)/ -f json -o bandit-results.json

ci-security: ## Run security checks in CI
	safety check --json --output=safety-results.json
	semgrep --config=auto --json --output=semgrep-results.json $(SRC_DIR)/

ci-deploy: ## Deploy in CI environment
	@echo "Deploying version $(DOCKER_TAG)..."
	# Add deployment commands here
```

## Development Scripts

### scripts/dev-setup.sh
```bash
#!/bin/bash
# Development environment setup script

set -e

echo "Setting up HexStrike AI development environment..."

# Check Python version
python_version=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.9"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python $required_version or higher is required (found $python_version)"
    exit 1
fi

# Create virtual environment
if [ ! -d "hexstrike_env" ]; then
    echo "Creating virtual environment..."
    python3 -m venv hexstrike_env
fi

# Activate virtual environment
source hexstrike_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements-dev.txt

# Install pre-commit hooks
echo "Setting up pre-commit hooks..."
pre-commit install

# Create necessary directories
mkdir -p logs data config/environments

# Copy example configuration
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Please edit .env file with your configuration"
fi

# Check tool availability
echo "Checking security tools..."
make tools-check

echo "Development environment setup complete!"
echo "Activate with: source hexstrike_env/bin/activate"
```

### scripts/release.sh
```bash
#!/bin/bash
# Release automation script

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2.0.0"
    exit 1
fi

echo "Preparing release $VERSION..."

# Run full quality checks
echo "Running quality checks..."
make full-check

# Update version in files
echo "Updating version numbers..."
sed -i "s/version: \".*\"/version: \"$VERSION\"/" config/config.yaml
sed -i "s/__version__ = \".*\"/__version__ = \"$VERSION\"/" src/hexstrike/__init__.py

# Build and test
echo "Building release..."
make build

# Create git tag
echo "Creating git tag..."
git add .
git commit -m "Release version $VERSION"
git tag -a "v$VERSION" -m "Release version $VERSION"

# Build Docker image
echo "Building Docker image..."
make docker-build-prod

echo "Release $VERSION prepared successfully!"
echo "Push with: git push origin main && git push origin v$VERSION"
```

---

**Note:** This Makefile provides comprehensive development automation for the modularized HexStrike AI framework, covering everything from environment setup to deployment, with convenient shortcuts for common development workflows.
