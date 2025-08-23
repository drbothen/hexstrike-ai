---
title: POST /api/tools/nikto
group: api
handler: nikto
module: __main__
line_range: [9118, 9145]
discovered_in_chunk: 10
---

# POST /api/tools/nikto

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute nikto with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with enhanced logging"""
```

## Purpose & Behavior
Nikto web vulnerability scanner endpoint providing:
- **Web Vulnerability Scanning:** Comprehensive web server vulnerability assessment
- **Plugin-Based Testing:** Extensive plugin library for various vulnerability checks
- **Server Fingerprinting:** Identify web server software and versions
- **Enhanced Logging:** Detailed logging of scan progress and findings

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/nikto
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",             // Required: Target URL or IP address
    "additional_args": "string"     // Optional: Additional nikto arguments
}
```

### Parameters
- **target:** Target URL or IP address to scan (required)
- **additional_args:** Additional nikto command arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Nikto scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 180.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "nikto -h http://example.com" // Actual command executed
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
@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Nikto scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nikto endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
