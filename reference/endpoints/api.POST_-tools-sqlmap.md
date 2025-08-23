---
title: POST /api/tools/sqlmap
group: api
handler: sqlmap
module: __main__
line_range: [9147, 9178]
discovered_in_chunk: 10
---

# POST /api/tools/sqlmap

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute sqlmap with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
```

## Purpose & Behavior
SQLMap SQL injection testing endpoint providing:
- **SQL Injection Detection:** Automated SQL injection vulnerability detection
- **Database Enumeration:** Extract database information, tables, and data
- **Multiple Database Support:** Support for various database management systems
- **Advanced Techniques:** Support for blind, time-based, and error-based SQL injection

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/sqlmap
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                // Required: Target URL to test
    "data": "string",               // Optional: POST data for testing
    "additional_args": "string"     // Optional: Additional sqlmap arguments
}
```

### Parameters
- **url:** Target URL to test for SQL injection (required)
- **data:** POST data parameters for testing (optional)
- **additional_args:** Additional sqlmap command arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // SQLMap scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 240.8,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "sqlmap -u http://example.com/page.php?id=1 --batch" // Actual command executed
}
```

### Error Responses

#### Missing URL (400 Bad Request)
```json
{
    "error": "URL parameter is required"
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
@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
