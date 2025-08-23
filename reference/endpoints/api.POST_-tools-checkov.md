---
title: POST /api/tools/checkov
group: api
handler: checkov
module: __main__
line_range: [9017, 9052]
discovered_in_chunk: 9
---

# POST /api/tools/checkov

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Checkov for infrastructure as code security scanning

## Complete Signature & Definition
```python
@app.route("/api/tools/checkov", methods=["POST"])
def checkov():
    """Execute Checkov for infrastructure as code security scanning"""
```

## Purpose & Behavior
Checkov infrastructure as code security scanning endpoint providing:
- **IaC Security Scanning:** Scan Terraform, CloudFormation, Kubernetes, and other IaC files
- **Policy Compliance:** Check compliance with security policies and best practices
- **Multi-Framework Support:** Support for multiple IaC frameworks and cloud providers
- **Custom Checks:** Execute specific security checks or skip certain checks

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/checkov
- **Content-Type:** application/json

### Request Body
```json
{
    "directory": "string",          // Optional: Directory to scan (default: ".")
    "framework": "string",          // Optional: IaC framework (terraform, cloudformation, kubernetes, etc.)
    "check": "string",              // Optional: Specific checks to run
    "skip_check": "string",         // Optional: Checks to skip
    "output_format": "string",      // Optional: Output format (default: "json")
    "additional_args": "string"     // Optional: Additional Checkov arguments
}
```

### Parameters
- **directory:** Directory path to scan (optional, default: ".")
- **framework:** IaC framework to scan (optional)
- **check:** Specific security checks to run (optional)
- **skip_check:** Security checks to skip (optional)
- **output_format:** Output format for results (optional, default: "json")
- **additional_args:** Additional Checkov arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Checkov scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 45.7,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "checkov -d . --output json" // Actual command executed
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/checkov", methods=["POST"])
def checkov():
    """Execute Checkov for infrastructure as code security scanning"""
    try:
        params = request.json
        directory = params.get("directory", ".")
        framework = params.get("framework", "")  # terraform, cloudformation, kubernetes, etc.
        check = params.get("check", "")
        skip_check = params.get("skip_check", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")
        
        command = f"checkov -d {directory}"
        
        if framework:
            command += f" --framework {framework}"
        
        if check:
            command += f" --check {check}"
        
        if skip_check:
            command += f" --skip-check {skip_check}"
        
        if output_format:
            command += f" --output {output_format}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting Checkov IaC scan: {directory}")
        result = execute_command(command)
        logger.info(f"📊 Checkov scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in checkov endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
