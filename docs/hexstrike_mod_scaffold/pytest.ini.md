# HexStrike AI - Pytest Configuration

**Purpose:** Comprehensive testing configuration for the modularized HexStrike AI framework, ensuring thorough test coverage and quality assurance.

**Status:** Proposed (designed for modular architecture testing)

## Pytest Configuration

### pytest.ini
```ini
[tool:pytest]
# Test discovery
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*

# Minimum version
minversion = 7.0

# Add options
addopts = 
    # Output options
    --verbose
    --tb=short
    --strict-markers
    --strict-config
    
    # Coverage options
    --cov=src/hexstrike
    --cov-report=html:htmlcov
    --cov-report=xml:coverage.xml
    --cov-report=term-missing
    --cov-fail-under=80
    
    # Performance options
    --durations=10
    --maxfail=5
    
    # Warnings
    --disable-warnings
    -p no:warnings
    
    # Parallel execution
    -n auto
    
    # Test output
    --junitxml=test-results.xml

# Test markers
markers =
    unit: Unit tests (fast, no external dependencies)
    integration: Integration tests (slower, may use external services)
    e2e: End-to-end tests (slowest, full system tests)
    security: Security-related tests
    performance: Performance and load tests
    ctf: CTF-specific functionality tests
    bugbounty: Bug bounty workflow tests
    slow: Tests that take more than 1 second
    network: Tests that require network access
    docker: Tests that require Docker
    privileged: Tests that require elevated privileges
    external_tools: Tests that require external security tools
    
# Test filtering
filterwarnings =
    ignore::UserWarning
    ignore::DeprecationWarning:requests.*
    ignore::DeprecationWarning:urllib3.*
    ignore::PendingDeprecationWarning
    error::FutureWarning
    
# Logging configuration
log_cli = true
log_cli_level = INFO
log_cli_format = %(asctime)s [%(levelname)8s] %(name)s: %(message)s
log_cli_date_format = %Y-%m-%d %H:%M:%S

log_file = tests.log
log_file_level = DEBUG
log_file_format = %(asctime)s [%(levelname)8s] %(filename)s:%(lineno)d %(funcName)s(): %(message)s
log_file_date_format = %Y-%m-%d %H:%M:%S

# Timeout for tests
timeout = 300
timeout_method = thread

# Asyncio configuration
asyncio_mode = auto

# Temporary directory
tmp_path_retention_count = 3
tmp_path_retention_policy = failed

# Collection configuration
collect_ignore = [
    "setup.py",
    "conftest.py",
    "build/",
    "dist/",
    ".tox/",
    ".venv/",
    "venv/",
    "node_modules/",
]

# Doctest configuration
doctest_optionflags = NORMALIZE_WHITESPACE IGNORE_EXCEPTION_DETAIL ELLIPSIS
```

## Test Structure and Organization

### Test Directory Structure
```
tests/
├── conftest.py                     # Global test configuration
├── fixtures/                       # Test data and fixtures
│   ├── __init__.py
│   ├── sample_targets.py           # Sample target data
│   ├── mock_tool_outputs.py        # Mock tool execution results
│   └── test_configs.py             # Test configuration data
│
├── unit/                           # Unit tests (fast, isolated)
│   ├── __init__.py
│   ├── platform/
│   │   ├── test_constants.py
│   │   ├── test_errors.py
│   │   ├── test_logging.py
│   │   └── test_validation.py
│   ├── domain/
│   │   ├── test_target_analysis.py
│   │   ├── test_vulnerability_models.py
│   │   └── test_attack_models.py
│   ├── services/
│   │   ├── test_decision_service.py
│   │   ├── test_tool_execution_service.py
│   │   ├── test_process_service.py
│   │   └── test_ctf_service.py
│   ├── adapters/
│   │   ├── test_tool_registry.py
│   │   ├── test_web_tool_adapters.py
│   │   └── test_cloud_tool_adapters.py
│   ├── interfaces/
│   │   ├── test_visual_engine.py
│   │   └── test_api_schemas.py
│   └── utils/
│       ├── test_formatting.py
│       └── test_system.py
│
├── integration/                    # Integration tests (moderate speed)
│   ├── __init__.py
│   ├── test_service_integration.py
│   ├── test_adapter_integration.py
│   ├── test_api_endpoints.py
│   └── test_workflow_integration.py
│
├── e2e/                           # End-to-end tests (slow)
│   ├── __init__.py
│   ├── test_full_scan_workflow.py
│   ├── test_ctf_challenge_workflow.py
│   └── test_bugbounty_workflow.py
│
├── performance/                    # Performance tests
│   ├── __init__.py
│   ├── test_load_testing.py
│   ├── test_memory_usage.py
│   └── test_concurrent_execution.py
│
└── security/                      # Security-specific tests
    ├── __init__.py
    ├── test_input_validation.py
    ├── test_command_injection.py
    └── test_privilege_escalation.py
```

### Global Test Configuration

#### tests/conftest.py
```python
"""
Global test configuration and fixtures for HexStrike AI tests.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock
from typing import Dict, Any, Generator

from hexstrike.platform.config import ConfigManager
from hexstrike.platform.logging import LogManager
from hexstrike.services.decision_service import DecisionService
from hexstrike.services.tool_execution_service import ToolExecutionService
from hexstrike.adapters.tool_registry import ToolRegistry
from hexstrike.domain.target_analysis import TargetProfile, TargetType

# Test configuration
pytest_plugins = [
    "pytest_asyncio",
    "pytest_cov",
    "pytest_mock",
    "pytest_timeout",
    "pytest_xdist",
]

@pytest.fixture(scope="session")
def test_config() -> Dict[str, Any]:
    """Test configuration settings."""
    return {
        "test_mode": True,
        "log_level": "DEBUG",
        "timeout": 30,
        "max_workers": 2,
        "cache_enabled": False,
    }

@pytest.fixture(scope="session")
def temp_dir() -> Generator[Path, None, None]:
    """Create temporary directory for test files."""
    temp_path = Path(tempfile.mkdtemp(prefix="hexstrike_test_"))
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)

@pytest.fixture
def mock_config_manager() -> Mock:
    """Mock configuration manager."""
    mock = Mock(spec=ConfigManager)
    mock.get.return_value = "test_value"
    mock.get_bool.return_value = True
    mock.get_int.return_value = 42
    return mock

@pytest.fixture
def mock_log_manager() -> Mock:
    """Mock log manager."""
    mock = Mock(spec=LogManager)
    mock.get_logger.return_value = Mock()
    return mock

@pytest.fixture
def sample_target_profile() -> TargetProfile:
    """Sample target profile for testing."""
    return TargetProfile(
        target="example.com",
        target_type=TargetType.WEB_APPLICATION,
        ip_addresses=["192.168.1.100"],
        open_ports=[80, 443, 22],
        services={80: "http", 443: "https", 22: "ssh"},
        technologies=["apache", "php", "mysql"],
        attack_surface_score=7.5,
        risk_level="MEDIUM",
        confidence_score=0.85
    )

@pytest.fixture
def mock_tool_registry() -> Mock:
    """Mock tool registry with sample tools."""
    mock = Mock(spec=ToolRegistry)
    mock.get_tool.return_value = Mock(
        name="nmap",
        category="network_scanner",
        command_template="nmap {target}",
        timeout=300
    )
    mock.get_tools_by_category.return_value = ["nmap", "rustscan"]
    return mock

@pytest.fixture
def mock_decision_service() -> Mock:
    """Mock decision service."""
    mock = Mock(spec=DecisionService)
    mock.select_optimal_tools.return_value = ["nmap", "gobuster", "nuclei"]
    mock.optimize_parameters.return_value = {"target": "example.com", "timeout": 300}
    return mock

@pytest.fixture
def mock_tool_execution_service() -> Mock:
    """Mock tool execution service."""
    mock = Mock(spec=ToolExecutionService)
    mock.execute_tool.return_value = Mock(
        success=True,
        stdout="Tool output",
        stderr="",
        return_code=0,
        execution_time=1.5,
        parsed_output={"vulnerabilities": []}
    )
    return mock

# Test data fixtures
@pytest.fixture
def sample_nmap_output() -> str:
    """Sample nmap output for testing."""
    return """
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for example.com (192.168.1.100)
Host is up (0.001s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0
80/tcp open  http    Apache httpd 2.4.41
443/tcp open https   Apache httpd 2.4.41

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
"""

@pytest.fixture
def sample_nuclei_output() -> str:
    """Sample nuclei output for testing."""
    return """
[2024-01-01 12:00:00] [INF] Using Nuclei Engine 2.9.0
[2024-01-01 12:00:01] [apache-version] [http] [info] http://example.com [Apache/2.4.41]
[2024-01-01 12:00:02] [ssl-dns-names] [ssl] [info] example.com [*.example.com,example.com]
"""

# Async fixtures
@pytest.fixture
async def async_mock_service():
    """Async mock service for testing."""
    mock = MagicMock()
    mock.async_method = AsyncMock(return_value="async_result")
    return mock

# Parametrized fixtures
@pytest.fixture(params=["nmap", "gobuster", "nuclei"])
def tool_name(request) -> str:
    """Parametrized tool names for testing."""
    return request.param

@pytest.fixture(params=[
    TargetType.WEB_APPLICATION,
    TargetType.NETWORK_HOST,
    TargetType.API_ENDPOINT
])
def target_type(request) -> TargetType:
    """Parametrized target types for testing."""
    return request.param

# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_logs():
    """Automatically cleanup log files after each test."""
    yield
    # Cleanup logic here
    log_files = Path(".").glob("*.log")
    for log_file in log_files:
        if log_file.name.startswith("test_"):
            log_file.unlink(missing_ok=True)

# Skip conditions
def pytest_configure(config):
    """Configure pytest with custom markers and skip conditions."""
    config.addinivalue_line(
        "markers", "requires_docker: mark test as requiring Docker"
    )
    config.addinivalue_line(
        "markers", "requires_network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "requires_tools: mark test as requiring external security tools"
    )

def pytest_collection_modifyitems(config, items):
    """Modify test collection to add skip markers."""
    import docker
    import subprocess
    
    # Check if Docker is available
    try:
        docker.from_env().ping()
        docker_available = True
    except:
        docker_available = False
    
    # Check if network is available
    try:
        subprocess.run(["ping", "-c", "1", "8.8.8.8"], 
                      capture_output=True, timeout=5)
        network_available = True
    except:
        network_available = False
    
    # Check if security tools are available
    tools_available = {}
    for tool in ["nmap", "gobuster", "nuclei"]:
        try:
            subprocess.run([tool, "--version"], 
                          capture_output=True, timeout=5)
            tools_available[tool] = True
        except:
            tools_available[tool] = False
    
    # Apply skip markers
    for item in items:
        if "requires_docker" in item.keywords and not docker_available:
            item.add_marker(pytest.mark.skip(reason="Docker not available"))
        
        if "requires_network" in item.keywords and not network_available:
            item.add_marker(pytest.mark.skip(reason="Network not available"))
        
        if "requires_tools" in item.keywords:
            for tool in ["nmap", "gobuster", "nuclei"]:
                if tool in item.name and not tools_available.get(tool, False):
                    item.add_marker(pytest.mark.skip(reason=f"{tool} not available"))
```

## Test Categories and Execution

### Unit Tests (Fast)
```bash
# Run only unit tests
pytest tests/unit/ -m "unit"

# Run unit tests with coverage
pytest tests/unit/ -m "unit" --cov=src/hexstrike --cov-report=html
```

### Integration Tests (Moderate)
```bash
# Run integration tests
pytest tests/integration/ -m "integration"

# Run integration tests excluding network-dependent tests
pytest tests/integration/ -m "integration and not network"
```

### End-to-End Tests (Slow)
```bash
# Run e2e tests
pytest tests/e2e/ -m "e2e"

# Run e2e tests with external tools
pytest tests/e2e/ -m "e2e and external_tools"
```

### Performance Tests
```bash
# Run performance tests
pytest tests/performance/ -m "performance"

# Run performance tests with profiling
pytest tests/performance/ -m "performance" --profile
```

### Security Tests
```bash
# Run security tests
pytest tests/security/ -m "security"

# Run privileged security tests (requires sudo)
sudo pytest tests/security/ -m "security and privileged"
```

## CI/CD Integration

### GitHub Actions Configuration
```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.10", "3.11"]
        test-category: ["unit", "integration", "e2e"]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        pip install -r requirements-dev.txt
        
    - name: Install security tools (for integration tests)
      if: matrix.test-category != 'unit'
      run: |
        sudo apt-get update
        sudo apt-get install -y nmap
        
    - name: Run ${{ matrix.test-category }} tests
      run: |
        pytest tests/${{ matrix.test-category }}/ -m "${{ matrix.test-category }}" \
          --junitxml=test-results-${{ matrix.test-category }}.xml \
          --cov=src/hexstrike \
          --cov-report=xml:coverage-${{ matrix.test-category }}.xml
          
    - name: Upload test results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results-${{ matrix.python-version }}-${{ matrix.test-category }}
        path: |
          test-results-*.xml
          coverage-*.xml
          
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: coverage-${{ matrix.test-category }}.xml
        flags: ${{ matrix.test-category }}
```

### Local Development Scripts

#### scripts/test.sh
```bash
#!/bin/bash
# Comprehensive test runner script

set -e

echo "Running HexStrike AI test suite..."

# Parse arguments
CATEGORY=${1:-"all"}
COVERAGE=${2:-"true"}
PARALLEL=${3:-"true"}

# Base pytest command
PYTEST_CMD="pytest"

# Add coverage if requested
if [ "$COVERAGE" = "true" ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=src/hexstrike --cov-report=html --cov-report=term"
fi

# Add parallel execution if requested
if [ "$PARALLEL" = "true" ]; then
    PYTEST_CMD="$PYTEST_CMD -n auto"
fi

# Run tests based on category
case $CATEGORY in
    "unit")
        echo "Running unit tests..."
        $PYTEST_CMD tests/unit/ -m "unit"
        ;;
    "integration")
        echo "Running integration tests..."
        $PYTEST_CMD tests/integration/ -m "integration"
        ;;
    "e2e")
        echo "Running end-to-end tests..."
        $PYTEST_CMD tests/e2e/ -m "e2e"
        ;;
    "security")
        echo "Running security tests..."
        $PYTEST_CMD tests/security/ -m "security"
        ;;
    "performance")
        echo "Running performance tests..."
        $PYTEST_CMD tests/performance/ -m "performance"
        ;;
    "all")
        echo "Running all tests..."
        $PYTEST_CMD tests/ --maxfail=10
        ;;
    *)
        echo "Unknown test category: $CATEGORY"
        echo "Available categories: unit, integration, e2e, security, performance, all"
        exit 1
        ;;
esac

echo "Test execution completed!"
```

## Coverage Configuration

### .coveragerc
```ini
[run]
source = src/hexstrike
omit = 
    */tests/*
    */test_*
    */conftest.py
    */legacy/*
    */__pycache__/*
    */venv/*
    */build/*
    */dist/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    if self.debug:
    if settings.DEBUG
    raise AssertionError
    raise NotImplementedError
    if 0:
    if __name__ == .__main__.:
    class .*\bProtocol\):
    @(abc\.)?abstractmethod

[html]
directory = htmlcov

[xml]
output = coverage.xml
```

---

**Note:** This pytest configuration provides comprehensive testing capabilities for the modularized HexStrike AI framework, supporting unit, integration, end-to-end, performance, and security testing with appropriate fixtures and CI integration.
