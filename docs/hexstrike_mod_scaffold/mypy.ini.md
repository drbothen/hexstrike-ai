# HexStrike AI - MyPy Configuration

**Purpose:** Strict type checking configuration for the modularized HexStrike AI framework to ensure type safety and catch potential runtime errors.

**Status:** Proposed (designed for modular architecture type safety)

## MyPy Configuration

### mypy.ini
```ini
[mypy]
# Python version and basic settings
python_version = 3.11
warn_return_any = True
warn_unused_configs = True
disallow_untyped_defs = True
disallow_incomplete_defs = True
check_untyped_defs = True
disallow_untyped_decorators = True

# Strictness settings
strict = True
strict_optional = True
strict_equality = True

# Error reporting
show_error_codes = True
show_column_numbers = True
show_error_context = True
pretty = True
color_output = True
error_summary = True

# Import handling
ignore_missing_imports = False
follow_imports = normal
follow_imports_for_stubs = True

# Cache and performance
cache_dir = .mypy_cache
sqlite_cache = True
incremental = True

# Warnings
warn_redundant_casts = True
warn_unused_ignores = True
warn_no_return = True
warn_unreachable = True

# Advanced type checking
disallow_any_generics = True
disallow_any_unimported = True
disallow_any_expr = False  # Too strict for some cases
disallow_any_decorated = False  # Too strict for decorators
disallow_any_explicit = False  # Allow explicit Any when needed
disallow_subclassing_any = True

# Function signatures
disallow_untyped_calls = True
disallow_incomplete_defs = True
disallow_untyped_decorators = True

# None and Optional handling
no_implicit_optional = True
strict_optional = True

# Miscellaneous
allow_redefinition = False
local_partial_types = False
implicit_reexport = False
strict_concatenate = True

# Files to check
files = src/hexstrike

# Exclude patterns
exclude = (?x)(
    ^src/hexstrike/legacy/.*$
    | ^tests/.*$
    | ^build/.*$
    | ^dist/.*$
    | ^\..*$
)
```

## Module-Specific Configurations

### Platform Layer - Strict Type Checking
```ini
[mypy-hexstrike.platform.*]
# Platform modules should have the strictest type checking
strict = True
disallow_any_generics = True
disallow_any_unimported = True
disallow_subclassing_any = True
warn_return_any = True
no_implicit_optional = True

# No exceptions for platform code
ignore_errors = False
```

### Domain Layer - Pure Business Logic
```ini
[mypy-hexstrike.domain.*]
# Domain layer should be pure and strictly typed
strict = True
disallow_any_generics = True
disallow_any_unimported = True
disallow_subclassing_any = True
warn_return_any = True

# Domain should not depend on external libraries
follow_imports = silent
```

### Services Layer - Business Logic
```ini
[mypy-hexstrike.services.*]
# Services should be well-typed but may use some external libraries
strict = True
disallow_any_generics = True
warn_return_any = True

# Allow some flexibility for service orchestration
disallow_any_expr = False
```

### Adapters Layer - External Integration
```ini
[mypy-hexstrike.adapters.*]
# Adapters may need to work with untyped external libraries
strict = True
warn_return_any = True

# More lenient with external library types
disallow_any_unimported = False
ignore_missing_imports = True  # For some security tools
```

### Interfaces Layer - Contracts
```ini
[mypy-hexstrike.interfaces.*]
# Interfaces should be strictly typed as they define contracts
strict = True
disallow_any_generics = True
disallow_any_unimported = True
disallow_subclassing_any = True
warn_return_any = True
```

### Utils Layer - Pure Functions
```ini
[mypy-hexstrike.utils.*]
# Utilities should be pure and strictly typed
strict = True
disallow_any_generics = True
disallow_any_unimported = True
warn_return_any = True
```

## Third-Party Library Configurations

### Flask and Web Framework
```ini
[mypy-flask.*]
ignore_missing_imports = True

[mypy-werkzeug.*]
ignore_missing_imports = True

[mypy-requests.*]
ignore_missing_imports = True
```

### Security Tools (Often Untyped)
```ini
[mypy-nmap.*]
ignore_missing_imports = True

[mypy-scapy.*]
ignore_missing_imports = True

[mypy-selenium.*]
ignore_missing_imports = True

[mypy-beautifulsoup4.*]
ignore_missing_imports = True

[mypy-bs4.*]
ignore_missing_imports = True

[mypy-mitmproxy.*]
ignore_missing_imports = True
```

### System and Process Libraries
```ini
[mypy-psutil.*]
ignore_missing_imports = True

[mypy-subprocess32.*]
ignore_missing_imports = True
```

### CTF and Binary Analysis Tools
```ini
[mypy-pwntools.*]
ignore_missing_imports = True

[mypy-angr.*]
ignore_missing_imports = True

[mypy-capstone.*]
ignore_missing_imports = True

[mypy-keystone.*]
ignore_missing_imports = True

[mypy-unicorn.*]
ignore_missing_imports = True

[mypy-ropper.*]
ignore_missing_imports = True

[mypy-z3.*]
ignore_missing_imports = True
```

### Cloud and Container Libraries
```ini
[mypy-boto3.*]
ignore_missing_imports = True

[mypy-botocore.*]
ignore_missing_imports = True

[mypy-azure.*]
ignore_missing_imports = True

[mypy-google.cloud.*]
ignore_missing_imports = True

[mypy-kubernetes.*]
ignore_missing_imports = True

[mypy-docker.*]
ignore_missing_imports = True
```

## Type Stub Requirements

### py.typed Marker
```txt
# src/hexstrike/py.typed
# This file marks the package as typed for mypy
```

### Custom Type Stubs
```python
# src/hexstrike/types/__init__.py
"""
Custom type definitions for HexStrike AI framework.
"""

from typing import Any, Dict, List, Optional, Union, TypeVar, Protocol
from typing_extensions import TypedDict, Literal
from datetime import datetime
from pathlib import Path

# Common type aliases
JSONValue = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
JSONDict = Dict[str, JSONValue]
PathLike = Union[str, Path]

# Tool execution types
class ToolParameters(TypedDict, total=False):
    target: str
    timeout: int
    additional_args: str
    use_recovery: bool

class ExecutionResult(TypedDict):
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    parsed_output: JSONDict

# Target analysis types
TargetTypeStr = Literal[
    "web_application",
    "network_host", 
    "api_endpoint",
    "cloud_service",
    "binary_file",
    "unknown"
]

TechnologyStackStr = Literal[
    "apache",
    "nginx",
    "iis",
    "nodejs",
    "php",
    "python",
    "java",
    "dotnet",
    "wordpress",
    "drupal",
    "joomla",
    "react",
    "angular",
    "vue",
    "unknown"
]

# Error handling types
ErrorTypeStr = Literal[
    "timeout",
    "permission_denied",
    "network_unreachable",
    "rate_limited",
    "tool_not_found",
    "invalid_parameters",
    "resource_exhausted",
    "authentication_failed",
    "target_unreachable",
    "parsing_error",
    "unknown"
]

RecoveryActionStr = Literal[
    "retry_with_backoff",
    "retry_with_reduced_scope",
    "switch_to_alternative_tool",
    "adjust_parameters",
    "escalate_to_human",
    "graceful_degradation",
    "abort_operation"
]

# Protocol definitions for dependency injection
class ToolAdapter(Protocol):
    def execute(self, params: ToolParameters) -> ExecutionResult: ...
    def validate_parameters(self, params: ToolParameters) -> bool: ...
    def parse_output(self, output: str) -> JSONDict: ...

class ErrorHandler(Protocol):
    def classify_error(self, error_message: str, exception: Exception) -> ErrorTypeStr: ...
    def handle_tool_failure(self, tool_name: str, exception: Exception, context: JSONDict) -> JSONDict: ...

class VisualEngine(Protocol):
    def format_tool_status(self, tool_name: str, status: str, target: str) -> str: ...
    def format_error_card(self, error_type: str, tool_name: str, error_message: str) -> str: ...

# Generic type variables
T = TypeVar('T')
ToolAdapterT = TypeVar('ToolAdapterT', bound=ToolAdapter)
```

## Type Checking Scripts

### Local Type Checking
```bash
#!/bin/bash
# scripts/type-check.sh

echo "Running MyPy type checking..."

# Check core modules with strict settings
echo "Checking platform layer..."
mypy src/hexstrike/platform/ --strict

echo "Checking domain layer..."
mypy src/hexstrike/domain/ --strict

echo "Checking interfaces layer..."
mypy src/hexstrike/interfaces/ --strict

echo "Checking utils layer..."
mypy src/hexstrike/utils/ --strict

# Check other layers with standard settings
echo "Checking services layer..."
mypy src/hexstrike/services/

echo "Checking adapters layer..."
mypy src/hexstrike/adapters/

# Generate type coverage report
echo "Generating type coverage report..."
mypy src/hexstrike/ --html-report mypy-report/

echo "Type checking complete!"
echo "View detailed report: open mypy-report/index.html"
```

### CI Integration
```yaml
# .github/workflows/type-check.yml (excerpt)
- name: Run MyPy with coverage
  run: |
    mypy src/hexstrike/ --html-report mypy-report/ --cobertura-xml-report mypy-coverage.xml
    
- name: Upload type coverage
  uses: codecov/codecov-action@v3
  with:
    file: mypy-coverage.xml
    flags: types
    name: type-coverage
```

## Type Annotation Guidelines

### Function Signatures
```python
# Good: Complete type annotations
def execute_tool(
    tool_name: str, 
    parameters: ToolParameters,
    timeout: Optional[int] = None
) -> ExecutionResult:
    """Execute a security tool with given parameters."""
    ...

# Bad: Missing type annotations
def execute_tool(tool_name, parameters, timeout=None):
    """Execute a security tool with given parameters."""
    ...
```

### Class Definitions
```python
# Good: Typed class with generic support
from typing import Generic, TypeVar

T = TypeVar('T')

class Registry(Generic[T]):
    def __init__(self) -> None:
        self._items: Dict[str, T] = {}
    
    def register(self, name: str, item: T) -> None:
        self._items[name] = item
    
    def get(self, name: str) -> Optional[T]:
        return self._items.get(name)

# Usage with specific types
tool_registry: Registry[ToolAdapter] = Registry()
```

### Error Handling
```python
# Good: Specific exception types
from typing import NoReturn

def validate_target(target: str) -> None:
    if not target:
        raise ValueError("Target cannot be empty")
    if not target.startswith(('http://', 'https://')):
        raise ValueError("Target must be a valid URL")

def handle_critical_error(error: Exception) -> NoReturn:
    logger.critical(f"Critical error: {error}")
    sys.exit(1)
```

## Migration Strategy

### Phase 1: Add Basic Types
- Add type annotations to function signatures
- Use `Any` temporarily for complex types
- Focus on public APIs first

### Phase 2: Refine Types
- Replace `Any` with specific types
- Add custom type definitions
- Create protocol definitions for interfaces

### Phase 3: Strict Enforcement
- Enable strict mode for all modules
- Remove all `# type: ignore` comments
- Achieve 100% type coverage

### Phase 4: Advanced Types
- Use generic types where appropriate
- Add runtime type checking for critical paths
- Implement type-safe dependency injection

---

**Note:** This MyPy configuration ensures type safety across the modularized HexStrike AI framework while accommodating the realities of working with security tools that may not have complete type annotations.
