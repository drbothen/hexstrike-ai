---
title: POST /api/tools/terrascan
group: api
handler: terrascan
module: __main__
line_range: [9054, 9086]
discovered_in_chunk: 9
---

# POST /api/tools/terrascan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Terrascan for infrastructure as code security scanning

## Complete Signature & Definition
```python
@app.route("/api/tools/terrascan", methods=["POST"])
def terrascan():
    """Execute Terrascan for infrastructure as code security scanning"""
```

## Purpose & Behavior
Terrascan infrastructure as code security scanning endpoint providing:
- **IaC Security Analysis:** Scan Terraform, Kubernetes, and other IaC configurations
- **Policy Enforcement:** Enforce security policies and compliance requirements
- **Multi-Cloud Support:** Support for AWS, Azure, GCP, and other cloud providers
- **Severity Filtering:** Filter results by security severity levels

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/terrascan
- **Content-Type:** application/json

### Request Body
```json
{
    "scan_type": "string",          // Optional: Scan type (default: "all")
    "iac_dir": "string",            // Optional: IaC directory to scan (default: ".")
    "policy_type": "string",        // Optional: Policy type to apply
    "output_format": "string",      // Optional: Output format (default: "json")
    "severity": "string",           // Optional: Minimum severity level
    "additional_args": "string"     // Optional: Additional Terrascan arguments
}
```

### Parameters
- **scan_type:** Type of scan to perform - all, terraform, k8s, etc. (optional, default: "all")
- **iac_dir:** Directory containing IaC files (optional, default: ".")
- **policy_type:** Policy type to apply during scanning (optional)
- **output_format:** Output format for results (optional, default: "json")
- **severity:** Minimum severity level to report (optional)
- **additional_args:** Additional Terrascan arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Terrascan scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 35.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "terrascan scan -t all -d . -o json" // Actual command executed
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
@app.route("/api/tools/terrascan", methods=["POST"])
def terrascan():
    """Execute Terrascan for infrastructure as code security scanning"""
    try:
        params = request.json
        scan_type = params.get("scan_type", "all")  # all, terraform, k8s, etc.
        iac_dir = params.get("iac_dir", ".")
        policy_type = params.get("policy_type", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")
        
        command = f"terrascan scan -t {scan_type} -d {iac_dir}"
        
        if policy_type:
            command += f" -p {policy_type}"
        
        if output_format:
            command += f" -o {output_format}"
        
        if severity:
            command += f" --severity {severity}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting Terrascan IaC scan: {iac_dir}")
        result = execute_command(command)
        logger.info(f"📊 Terrascan scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in terrascan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
