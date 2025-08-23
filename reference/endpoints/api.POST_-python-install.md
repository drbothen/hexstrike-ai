---
title: POST /api/python/install
group: api
handler: install_python_package
module: __main__
line_range: [12599, 12628]
discovered_in_chunk: 12
---

# POST /api/python/install

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Install a Python package in a virtual environment

## Complete Signature & Definition
```python
@app.route("/api/python/install", methods=["POST"])
def install_python_package():
    """Install a Python package in a virtual environment"""
```

## Purpose & Behavior
Python package management endpoint providing:
- **Package Installation:** Install Python packages in isolated environments
- **Virtual Environment Management:** Manage virtual environments for package isolation
- **Dependency Resolution:** Handle package dependencies and conflicts
- **Enhanced Logging:** Detailed logging of installation progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/python/install
- **Content-Type:** application/json

### Request Body
```json
{
    "package": "string",              // Required: Package name to install
    "version": "string",              // Optional: Specific version to install
    "environment": "string",          // Optional: Virtual environment name (default: default)
    "upgrade": boolean,               // Optional: Upgrade if already installed (default: false)
    "force_reinstall": boolean,       // Optional: Force reinstall (default: false)
    "no_deps": boolean,               // Optional: Don't install dependencies (default: false)
    "index_url": "string",            // Optional: Custom PyPI index URL
    "extra_index_url": "string",      // Optional: Extra index URL
    "additional_args": "string"       // Optional: Additional pip arguments
}
```

### Parameters
- **package:** Package name to install (required) - "requests", "numpy==1.21.0"
- **version:** Specific version to install (optional) - "1.21.0"
- **environment:** Virtual environment name (optional, default: "default")
- **upgrade:** Upgrade if already installed flag (optional, default: false)
- **force_reinstall:** Force reinstall flag (optional, default: false)
- **no_deps:** Don't install dependencies flag (optional, default: false)
- **index_url:** Custom PyPI index URL (optional)
- **extra_index_url:** Extra index URL (optional)
- **additional_args:** Additional pip arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "pip install requests==2.28.1",
    "installation_results": {
        "package": "requests",
        "version_installed": "2.28.1",
        "environment": "default",
        "dependencies_installed": [
            "certifi==2022.9.24",
            "charset-normalizer==2.1.1",
            "idna==3.4",
            "urllib3==1.26.12"
        ],
        "installation_size": "1.2MB",
        "installation_time": 15.3,
        "already_satisfied": false
    },
    "raw_output": "Collecting requests==2.28.1\n  Downloading requests-2.28.1-py3-none-any.whl\n",
    "execution_time": 15.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Package (400 Bad Request)
```json
{
    "error": "Package parameter is required"
}
```

#### Installation Failed (500 Internal Server Error)
```json
{
    "error": "Package installation failed: {error_message}"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
package = params.get("package", "")
version = params.get("version", "")
environment = params.get("environment", "default")
upgrade = params.get("upgrade", False)
force_reinstall = params.get("force_reinstall", False)
no_deps = params.get("no_deps", False)
index_url = params.get("index_url", "")
extra_index_url = params.get("extra_index_url", "")
additional_args = params.get("additional_args", "")

if not package:
    return jsonify({"error": "Package parameter is required"}), 400
```

### Command Construction
```python
# Prepare package specification
package_spec = package
if version and "==" not in package:
    package_spec = f"{package}=={version}"

# Use environment manager to install package
result = env_manager.install_package(
    package_spec,
    environment=environment,
    upgrade=upgrade,
    force_reinstall=force_reinstall,
    no_deps=no_deps,
    index_url=index_url,
    extra_index_url=extra_index_url,
    additional_args=additional_args
)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Python package installation access required

## Error Handling
- **Missing Parameters:** 400 error for missing package
- **Installation Errors:** Handled by PythonEnvironmentManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Package Validation:** Validate package names to prevent malicious packages
- **Environment Isolation:** Use virtual environments for package isolation
- **Index URL Validation:** Validate custom index URLs for security

## Use Cases and Applications

#### Development Environment Setup
- **Dependency Installation:** Install required dependencies for projects
- **Environment Preparation:** Prepare environments for security testing
- **Tool Installation:** Install security tools and libraries

#### Security Testing
- **Tool Dependencies:** Install dependencies for security tools
- **Custom Tools:** Install custom security testing tools
- **Environment Management:** Manage testing environments

## Testing & Validation
- Package installation accuracy testing
- Parameter validation verification
- Virtual environment isolation testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/python/install", methods=["POST"])
def install_python_package():
    """Install a Python package in a virtual environment"""
    try:
        params = request.json
        package = params.get("package", "")
        version = params.get("version", "")
        environment = params.get("environment", "default")
        upgrade = params.get("upgrade", False)
        force_reinstall = params.get("force_reinstall", False)
        no_deps = params.get("no_deps", False)
        index_url = params.get("index_url", "")
        extra_index_url = params.get("extra_index_url", "")
        additional_args = params.get("additional_args", "")
        
        if not package:
            return jsonify({"error": "Package parameter is required"}), 400
        
        # Prepare package specification
        package_spec = package
        if version and "==" not in package:
            package_spec = f"{package}=={version}"
        
        logger.info(f"🐍 Installing Python package: {package_spec} in environment: {environment}")
        
        start_time = time.time()
        result = env_manager.install_package(
            package_spec,
            environment=environment,
            upgrade=upgrade,
            force_reinstall=force_reinstall,
            no_deps=no_deps,
            index_url=index_url,
            extra_index_url=extra_index_url,
            additional_args=additional_args
        )
        execution_time = time.time() - start_time
        
        logger.info(f"🐍 Package installation completed in {execution_time:.2f}s")
        
        return jsonify({
            "success": True,
            "command": result.get("command", ""),
            "installation_results": result.get("results", {}),
            "raw_output": result.get("output", ""),
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error installing Python package: {str(e)}")
        return jsonify({
            "error": f"Package installation failed: {str(e)}"
        }), 500
```
