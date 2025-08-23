---
title: POST /api/tools/nuclei
group: api
handler: nuclei
module: __main__
line_range: [8560, 8615]
discovered_in_chunk: 9
---

# POST /api/tools/nuclei

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling

## Complete Signature & Definition
```python
@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling"""
```

## Purpose & Behavior
Nuclei vulnerability scanning endpoint providing:
- **Comprehensive Vulnerability Detection:** Fast and customizable vulnerability scanner
- **Flexible Filtering:** Filter by severity, tags, and specific templates
- **Intelligent Error Handling:** Optional recovery system for failed scans
- **Template Support:** Support for custom and community templates

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/nuclei
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Required: Target URL or IP to scan
    "severity": "string",               // Optional: Filter by severity (info, low, medium, high, critical)
    "tags": "string",                   // Optional: Filter by tags (e.g., "xss,sqli")
    "template": "string",               // Optional: Specific template to use
    "additional_args": "string",        // Optional: Additional nuclei arguments
    "use_recovery": boolean             // Optional: Enable intelligent error handling - default: true
}
```

### Parameters
- **target:** Target URL or IP address to scan (required)
- **severity:** Filter vulnerabilities by severity level (optional)
- **tags:** Filter by specific vulnerability tags (optional)
- **template:** Use specific template file or directory (optional)
- **additional_args:** Additional command-line arguments (optional)
- **use_recovery:** Enable intelligent error handling and recovery (optional, default: true)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "output": "nuclei scan results with vulnerability findings...",
    "command": "nuclei -u https://example.com -severity high",
    "execution_time": 45.8,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Target (400 Bad Request)
```json
{
    "error": "Target parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        target = params.get("target", "")
        severity = params.get("severity", "")
        tags = params.get("tags", "")
        template = params.get("template", "")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)
        
        if not target:
            logger.warning("🎯 Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nuclei -u {target}"
        
        if severity:
            command += f" -severity {severity}"
            
        if tags:
            command += f" -tags {tags}"
            
        if template:
            command += f" -t {template}"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔬 Starting Nuclei vulnerability scan: {target}")
        
        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nuclei", command, tool_params)
        else:
            result = execute_command(command)
        
        logger.info(f"📊 Nuclei scan completed for {target}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in nuclei endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
