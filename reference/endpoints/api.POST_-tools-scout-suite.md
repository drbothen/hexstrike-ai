---
title: POST /api/tools/scout-suite
group: api
handler: scout_suite
module: __main__
line_range: [8712, 8750]
discovered_in_chunk: 9
---

# POST /api/tools/scout-suite

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Scout Suite for multi-cloud security assessment

## Complete Signature & Definition
```python
@app.route("/api/tools/scout-suite", methods=["POST"])
def scout_suite():
    """Execute Scout Suite for multi-cloud security assessment"""
```

## Purpose & Behavior
Scout Suite cloud security assessment endpoint providing:
- **Multi-Cloud Support:** Support for AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud
- **Security Assessment:** Comprehensive cloud security posture assessment
- **Report Generation:** HTML reports with detailed findings and recommendations
- **Service-Specific Scanning:** Optional targeting of specific cloud services

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/scout-suite
- **Content-Type:** application/json

### Request Body
```json
{
    "provider": "string",           // Optional: Cloud provider (default: "aws")
    "profile": "string",            // Optional: AWS profile (default: "default")
    "report_dir": "string",         // Optional: Report directory (default: "/tmp/scout-suite")
    "services": "string",           // Optional: Specific services to scan
    "exceptions": "string",         // Optional: Exceptions file path
    "additional_args": "string"     // Optional: Additional Scout Suite arguments
}
```

### Parameters
- **provider:** Cloud provider - aws, azure, gcp, aliyun, oci (optional, default: "aws")
- **profile:** AWS profile name (optional, default: "default")
- **report_dir:** Directory for HTML reports (optional, default: "/tmp/scout-suite")
- **services:** Comma-separated list of services to scan (optional)
- **exceptions:** Path to exceptions configuration file (optional)
- **additional_args:** Additional Scout Suite arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Scout Suite output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 120.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "report_directory": "/tmp/scout-suite", // Report output directory
    "command": "scout aws --profile default --report-dir /tmp/scout-suite" // Actual command executed
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
@app.route("/api/tools/scout-suite", methods=["POST"])
def scout_suite():
    """Execute Scout Suite for multi-cloud security assessment"""
    try:
        params = request.json
        provider = params.get("provider", "aws")  # aws, azure, gcp, aliyun, oci
        profile = params.get("profile", "default")
        report_dir = params.get("report_dir", "/tmp/scout-suite")
        services = params.get("services", "")
        exceptions = params.get("exceptions", "")
        additional_args = params.get("additional_args", "")
        
        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        
        command = f"scout {provider}"
        
        if profile and provider == "aws":
            command += f" --profile {profile}"
        
        if services:
            command += f" --services {services}"
        
        if exceptions:
            command += f" --exceptions {exceptions}"
        
        command += f" --report-dir {report_dir}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"☁️  Starting Scout Suite {provider} assessment")
        result = execute_command(command)
        result["report_directory"] = report_dir
        logger.info(f"📊 Scout Suite assessment completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in scout-suite endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
