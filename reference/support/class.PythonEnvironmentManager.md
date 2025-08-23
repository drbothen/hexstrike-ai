---
title: class.PythonEnvironmentManager
kind: class
module: __main__
line_range: [5705, 5741]
discovered_in_chunk: 5
---

# PythonEnvironmentManager Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Manage Python virtual environments and dependencies

## Complete Signature & Definition
```python
class PythonEnvironmentManager:
    """Manage Python virtual environments and dependencies"""
    
    def __init__(self, base_dir: str = "/tmp/hexstrike_envs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
    
    def create_venv(self, env_name: str) -> Path:
        """Create a new virtual environment"""
    
    def install_package(self, env_name: str, package: str) -> bool:
        """Install a package in the specified environment"""
    
    def get_python_path(self, env_name: str) -> str:
        """Get Python executable path for environment"""
```

## Purpose & Behavior
Python virtual environment management system providing:
- **Virtual Environment Creation:** Automated venv creation with pip support
- **Package Management:** Install packages in isolated environments
- **Path Management:** Get Python executable paths for environments
- **Isolation:** Separate dependencies for different tools and workflows

## Dependencies & Usage
- **Depends on:**
  - pathlib.Path for path management
  - venv module for virtual environment creation
  - subprocess for package installation
  - logger for operation logging
- **Used by:**
  - Tool execution systems requiring isolated Python environments
  - Package dependency management
  - Python-based security tool execution

## Implementation Details

### Core Attributes
- **base_dir:** Base directory for virtual environments (default: "/tmp/hexstrike_envs")

### Key Methods

#### Environment Management
1. **create_venv(env_name: str) -> Path:** Create new virtual environment
2. **install_package(env_name: str, package: str) -> bool:** Install package in environment
3. **get_python_path(env_name: str) -> str:** Get Python executable path

### Virtual Environment Creation

#### Creation Process
1. **Path Construction:** Build environment path from base_dir and env_name
2. **Existence Check:** Only create if environment doesn't already exist
3. **Environment Creation:** Use venv.create() with pip support
4. **Path Return:** Return Path object for created environment

#### Creation Algorithm
```python
env_path = self.base_dir / env_name
if not env_path.exists():
    logger.info(f"🐍 Creating virtual environment: {env_name}")
    venv.create(env_path, with_pip=True)
return env_path
```

### Package Installation

#### Installation Process
1. **Environment Creation:** Ensure environment exists (create if needed)
2. **Pip Path Resolution:** Locate pip executable in environment
3. **Package Installation:** Execute pip install with timeout
4. **Result Validation:** Check return code and log results

#### Installation Algorithm
```python
env_path = self.create_venv(env_name)
pip_path = env_path / "bin" / "pip"

result = subprocess.run([str(pip_path), "install", package], 
                      capture_output=True, text=True, timeout=300)
if result.returncode == 0:
    logger.info(f"📦 Installed package {package} in {env_name}")
    return True
else:
    logger.error(f"❌ Failed to install {package}: {result.stderr}")
    return False
```

#### Installation Features
- **Timeout Protection:** 300-second timeout for package installation
- **Error Capture:** Capture and log stderr for failed installations
- **Success Validation:** Return boolean success status
- **Logging Integration:** Comprehensive installation logging

### Python Path Resolution

#### Path Resolution Process
1. **Environment Creation:** Ensure environment exists
2. **Executable Path:** Construct path to Python executable
3. **String Conversion:** Return string path for subprocess usage

#### Path Construction
```python
env_path = self.create_venv(env_name)
return str(env_path / "bin" / "python")
```

### Directory Management

#### Base Directory Initialization
- **Automatic Creation:** Create base directory if it doesn't exist
- **Path Object:** Use pathlib.Path for robust path operations
- **Default Location:** "/tmp/hexstrike_envs" for temporary environments

#### Environment Organization
- **Named Environments:** Each environment has unique name-based directory
- **Isolated Dependencies:** Complete isolation between environments
- **Standard Structure:** Standard venv directory structure

### Error Handling and Resilience

#### Installation Error Handling
- **Exception Catching:** Comprehensive exception handling for installation
- **Timeout Handling:** Graceful handling of installation timeouts
- **Error Logging:** Detailed error logging with package and environment context

#### Environment Creation Resilience
- **Existence Checking:** Avoid recreating existing environments
- **Directory Creation:** Automatic base directory creation
- **Path Validation:** Robust path handling with pathlib

### Integration with Tool Execution

#### Isolated Execution
- **Tool Isolation:** Run Python tools in isolated environments
- **Dependency Management:** Manage tool-specific dependencies
- **Version Control:** Control Python and package versions per tool

#### Execution Integration
- **Python Path:** Provide Python executable path for subprocess execution
- **Environment Activation:** Implicit environment activation through path usage
- **Package Availability:** Ensure required packages are installed

### Use Cases and Applications

#### Security Tool Management
- **Tool Dependencies:** Manage dependencies for Python security tools
- **Version Isolation:** Isolate different tool versions
- **Conflict Resolution:** Avoid dependency conflicts between tools

#### Development Environment
- **Testing Environments:** Create isolated testing environments
- **Dependency Testing:** Test different dependency versions
- **Clean Environments:** Fresh environments for testing

### Performance Considerations

#### Environment Reuse
- **Existence Checking:** Reuse existing environments to avoid recreation overhead
- **Lazy Creation:** Create environments only when needed
- **Path Caching:** Efficient path resolution

#### Installation Optimization
- **Timeout Management:** Reasonable timeout for package installation
- **Error Recovery:** Graceful handling of installation failures
- **Logging Efficiency:** Efficient logging without performance impact

## Testing & Validation
- Virtual environment creation testing
- Package installation success/failure validation
- Python path resolution verification
- Error handling and timeout testing

## Code Reproduction
Complete class implementation with 3 methods for Python virtual environment management, including environment creation, package installation, and path resolution. Essential for isolated Python tool execution and dependency management.
