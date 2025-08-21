# HexStrike AI - Ruff Configuration

**Purpose:** Fast Python linter and code formatter configuration for the modularized HexStrike AI framework, enforcing code quality and consistency standards.

**Status:** Proposed (designed for modular architecture code quality)

## Ruff Configuration

### ruff.toml
```toml
# Ruff configuration for HexStrike AI modular framework
target-version = "py311"
line-length = 100
indent-width = 4

# Enable specific rule categories
select = [
    # Pyflakes
    "F",
    # pycodestyle errors
    "E",
    # pycodestyle warnings  
    "W",
    # isort
    "I",
    # pep8-naming
    "N",
    # pyupgrade
    "UP",
    # flake8-bugbear
    "B",
    # flake8-simplify
    "SIM",
    # flake8-comprehensions
    "C4",
    # flake8-pie
    "PIE",
    # flake8-return
    "RET",
    # flake8-self
    "SLF",
    # flake8-unused-arguments
    "ARG",
    # flake8-use-pathlib
    "PTH",
    # pandas-vet
    "PD",
    # numpy-specific rules
    "NPY",
    # Ruff-specific rules
    "RUF",
    # flake8-bandit (security)
    "S",
    # flake8-logging-format
    "G",
    # flake8-quotes
    "Q",
    # flake8-annotations
    "ANN",
    # flake8-async
    "ASYNC",
    # flake8-boolean-trap
    "FBT",
    # flake8-datetimez
    "DTZ",
    # flake8-errmsg
    "EM",
    # flake8-executable
    "EXE",
    # flake8-implicit-str-concat
    "ISC",
    # flake8-import-conventions
    "ICN",
    # flake8-logging
    "LOG",
    # flake8-no-pep420
    "INP",
    # flake8-print
    "T20",
    # flake8-pyi
    "PYI",
    # flake8-pytest-style
    "PT",
    # flake8-raise
    "RSE",
    # flake8-slots
    "SLOT",
    # flake8-tidy-imports
    "TID",
    # tryceratops
    "TRY",
    # flynt
    "FLY",
    # perflint
    "PERF",
    # refurb
    "FURB",
]

# Disable specific rules that are too strict for our use case
ignore = [
    # Allow print statements (useful for CLI tools)
    "T201",
    # Allow TODO comments
    "FIX002",
    # Allow relative imports within package
    "TID252",
    # Allow subprocess without shell=False (security tools need it)
    "S602",
    "S603",
    # Allow hardcoded passwords in test files
    "S105",
    "S106",
    # Allow assert statements (useful for type narrowing)
    "S101",
    # Allow magic values in tests
    "PLR2004",
    # Allow too many arguments (some security tools need many params)
    "PLR0913",
    # Allow too many branches (complex security logic)
    "PLR0912",
    # Allow too many statements (initialization code)
    "PLR0915",
    # Allow boolean positional arguments (common in security tools)
    "FBT001",
    "FBT002",
    # Allow implicit string concatenation (multiline strings)
    "ISC001",
    # Allow missing type annotations in legacy compatibility layer
    "ANN001",
    "ANN002",
    "ANN003",
    "ANN101",
    "ANN102",
    "ANN201",
    "ANN202",
    "ANN204",
    "ANN205",
    "ANN206",
]

# Files to exclude from linting
exclude = [
    ".bzr",
    ".direnv",
    ".eggs",
    ".git",
    ".git-rewrite",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pants.d",
    ".pytype",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pypackages__",
    "_build",
    "buck-out",
    "build",
    "dist",
    "node_modules",
    "venv",
    # Legacy compatibility files (more lenient rules)
    "src/hexstrike/legacy/",
    # Generated files
    "*_pb2.py",
    "*_pb2_grpc.py",
]

# Assume Python 3.11+ features are available
required-version = ">=0.1.0"

[tool.ruff.format]
# Use double quotes for strings
quote-style = "double"
# Use spaces around operators
indent-style = "space"
# Respect magic trailing commas
skip-magic-trailing-comma = false
# Automatically detect line ending
line-ending = "auto"

[tool.ruff.lint.isort]
# Import sorting configuration
known-first-party = ["hexstrike"]
known-third-party = [
    "flask",
    "requests", 
    "selenium",
    "beautifulsoup4",
    "psutil",
    "pydantic",
    "sqlalchemy",
    "redis",
    "cryptography",
    "scapy",
    "nmap",
    "boto3",
    "azure",
    "google",
    "kubernetes",
    "docker",
    "pwntools",
    "angr",
    "capstone",
    "keystone",
    "unicorn",
    "z3",
]
section-order = [
    "future",
    "standard-library", 
    "third-party",
    "first-party",
    "local-folder"
]
split-on-trailing-comma = true
force-single-line = false
force-sort-within-sections = true
combine-as-imports = true

[tool.ruff.lint.pep8-naming]
# Allow uppercase constants
constant-rgx = "^[A-Z][A-Z0-9_]*$"
# Allow single letter variable names in specific contexts
ignore-names = [
    "i", "j", "k",  # Loop counters
    "x", "y", "z",  # Coordinates
    "f",             # File handles
    "e",             # Exceptions
    "T",             # Type variables
]

[tool.ruff.lint.flake8-quotes]
# Use double quotes consistently
inline-quotes = "double"
multiline-quotes = "double"
docstring-quotes = "double"
avoid-escape = true

[tool.ruff.lint.flake8-bugbear]
# Extend immutable calls (security-related)
extend-immutable-calls = [
    "hexstrike.platform.constants.COLORS",
    "hexstrike.platform.constants.DEFAULT_TIMEOUTS",
]

[tool.ruff.lint.flake8-bandit]
# Security-specific configuration
check-typed-exception = true
hardcoded-tmp-directory = ["/tmp", "/var/tmp", "/dev/shm"]

[tool.ruff.lint.flake8-comprehensions]
# Allow dict/list/set comprehensions
allow-dict-calls-with-keyword-arguments = true

[tool.ruff.lint.flake8-pytest-style]
# Pytest configuration
fixture-parentheses = false
mark-parentheses = false
parametrize-names-type = "tuple"
parametrize-values-type = "tuple"
parametrize-values-row-type = "tuple"

[tool.ruff.lint.pylint]
# Pylint-style checks
max-args = 8  # Security tools often need many parameters
max-branches = 15  # Complex security logic
max-returns = 8
max-statements = 60  # Initialization and setup code

[tool.ruff.lint.pyupgrade]
# Keep runtime type checking for security
keep-runtime-typing = true

# Per-file ignores for specific patterns
[tool.ruff.lint.per-file-ignores]
# Test files can be more lenient
"tests/**/*.py" = [
    "S101",    # Allow assert statements
    "PLR2004", # Allow magic values
    "ANN",     # Don't require type annotations in tests
    "ARG001",  # Allow unused function arguments (fixtures)
    "FBT",     # Allow boolean arguments in tests
]

# Legacy compatibility layer can be more lenient
"src/hexstrike/legacy/**/*.py" = [
    "ANN",     # Don't require type annotations in legacy code
    "UP",      # Don't require modern Python features
    "RUF",     # Relax Ruff-specific rules
    "SIM",     # Don't require simplifications
    "RET",     # Don't require return consistency
    "ARG",     # Allow unused arguments (compatibility)
]

# CLI and main entry points
"src/hexstrike/main.py" = [
    "T201",    # Allow print statements in CLI
    "PLR0912", # Allow many branches in main logic
]

# Configuration files
"src/hexstrike/platform/config.py" = [
    "S105",    # Allow hardcoded passwords (will be env vars)
    "S106",    # Allow hardcoded passwords (will be env vars)
]

# Tool adapters may need subprocess and security exceptions
"src/hexstrike/adapters/**/*.py" = [
    "S602",    # Allow subprocess without shell=False
    "S603",    # Allow subprocess calls
    "S607",    # Allow subprocess with partial executable path
    "PLR0913", # Allow many arguments (tool parameters)
]

# CTF and security analysis modules
"src/hexstrike/services/ctf_*.py" = [
    "S324",    # Allow insecure hash functions (CTF challenges)
    "S501",    # Allow requests without timeout (CTF tools)
    "PLR0912", # Allow many branches (challenge analysis)
    "PLR0915", # Allow many statements (complex analysis)
]

# Binary analysis modules  
"src/hexstrike/services/*binary*.py" = [
    "S301",    # Allow pickle (binary analysis)
    "S324",    # Allow insecure hash functions (analysis)
    "PLR0912", # Allow many branches (binary analysis)
]
```

## Integration with Development Workflow

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml (ruff section)
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.6
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format
```

### VS Code Integration
```json
// .vscode/settings.json
{
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.linting.pylintEnabled": false,
    "python.linting.flake8Enabled": false,
    "python.formatting.provider": "none",
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff",
        "editor.formatOnSave": true,
        "editor.codeActionsOnSave": {
            "source.fixAll.ruff": true,
            "source.organizeImports.ruff": true
        }
    },
    "ruff.args": ["--config=ruff.toml"]
}
```

### GitHub Actions Integration
```yaml
# .github/workflows/lint.yml
name: Lint

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: chartboost/ruff-action@v1
        with:
          args: "check --output-format=github"
      - uses: chartboost/ruff-action@v1
        with:
          args: "format --check"
```

## Module-Specific Rules

### Platform Layer - Strictest Rules
```toml
# Extra strict rules for platform modules
[tool.ruff.lint.per-file-ignores]
"src/hexstrike/platform/**/*.py" = [
    # No exceptions - platform should be clean
]
```

### Domain Layer - Pure Business Logic
```toml
[tool.ruff.lint.per-file-ignores]
"src/hexstrike/domain/**/*.py" = [
    # Domain should avoid external dependencies
    "TID252",  # Allow relative imports within domain
]
```

### Security Tool Adapters - More Lenient
```toml
[tool.ruff.lint.per-file-ignores]
"src/hexstrike/adapters/*_tool_*.py" = [
    "S602",    # subprocess without shell=False (tools need it)
    "S603",    # subprocess calls
    "S607",    # subprocess with partial path
    "PLR0913", # Many arguments (tool parameters)
    "C901",    # Complex functions (tool logic)
]
```

## Custom Rules for Security Context

### Security Tool Exceptions
```toml
# Security tools often need to do "unsafe" things
[tool.ruff.lint.per-file-ignores]
"src/hexstrike/adapters/web_tool_adapters.py" = [
    "S602",  # nmap, gobuster need subprocess
    "S603",  # nuclei, sqlmap need subprocess  
]

"src/hexstrike/adapters/cloud_tool_adapters.py" = [
    "S602",  # prowler, trivy need subprocess
    "S603",  # kube-hunter needs subprocess
]

"src/hexstrike/services/ctf_*.py" = [
    "S324",  # CTF challenges use weak hashes intentionally
    "S301",  # pickle used in CTF binary analysis
    "S506",  # yaml.load used for CTF configs
]
```

### Performance-Critical Code
```toml
[tool.ruff.lint.per-file-ignores]
"src/hexstrike/services/process_service.py" = [
    "PERF401", # Allow manual list comprehension (performance)
    "PLR0912", # Allow many branches (process management)
]

"src/hexstrike/utils/formatting.py" = [
    "PERF401", # Manual optimization allowed
    "SIM108",  # Allow ternary operators for performance
]
```

## Ruff Scripts

### Local Linting Script
```bash
#!/bin/bash
# scripts/lint.sh

echo "Running Ruff linting and formatting..."

# Check for linting issues
echo "Checking for linting issues..."
ruff check src/ --config ruff.toml

# Check formatting
echo "Checking code formatting..."
ruff format --check src/ --config ruff.toml

# Fix auto-fixable issues
echo "Fixing auto-fixable issues..."
ruff check src/ --fix --config ruff.toml

# Format code
echo "Formatting code..."
ruff format src/ --config ruff.toml

echo "Linting complete!"
```

### CI Integration Script
```bash
#!/bin/bash
# scripts/ci-lint.sh

set -e

echo "Running Ruff in CI mode..."

# Check for linting issues (fail on any issues)
ruff check src/ --config ruff.toml --output-format=github

# Check formatting (fail if not formatted)
ruff format --check src/ --config ruff.toml

echo "All linting checks passed!"
```

## Migration from Existing Tools

### From flake8/black/isort
```bash
# Remove old configuration files
rm -f .flake8 setup.cfg pyproject.toml

# Remove old dependencies
pip uninstall flake8 black isort

# Install ruff
pip install ruff

# Run initial format
ruff format src/
ruff check src/ --fix
```

### Configuration Migration
```python
# scripts/migrate_config.py
"""
Migrate existing flake8/black/isort configuration to ruff.
"""

def migrate_flake8_config():
    """Convert .flake8 settings to ruff.toml"""
    # Implementation would read .flake8 and generate ruff.toml
    pass

def migrate_black_config():
    """Convert black settings to ruff format settings"""
    # Implementation would read pyproject.toml [tool.black] and convert
    pass

def migrate_isort_config():
    """Convert isort settings to ruff isort settings"""
    # Implementation would read .isort.cfg and convert
    pass
```

---

**Note:** This Ruff configuration provides fast, comprehensive linting and formatting for the modularized HexStrike AI framework while accommodating the unique requirements of security tools and maintaining code quality standards.
