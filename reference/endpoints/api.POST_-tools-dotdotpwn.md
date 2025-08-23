---
title: POST /api/tools/dotdotpwn
group: api
handler: dotdotpwn
module: __main__
line_range: [10839, 10870]
discovered_in_chunk: 11
---

# POST /api/tools/dotdotpwn

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute DotDotPwn for directory traversal testing with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/dotdotpwn", methods=["POST"])
def dotdotpwn():
    """Execute DotDotPwn for directory traversal testing with enhanced logging"""
```

## Purpose & Behavior
DotDotPwn directory traversal testing endpoint providing:
- **Traversal Detection:** Comprehensive directory traversal vulnerability testing
- **Multiple Protocols:** Support for HTTP, FTP, TFTP, and other protocols
- **Payload Variations:** Various traversal payload patterns and encodings
- **Enhanced Logging:** Detailed logging of traversal attempts and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/dotdotpwn
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Required: Target host or URL
    "module": "string",                 // Optional: Protocol module (http, ftp, tftp, etc.)
    "additional_args": "string"         // Optional: Additional dotdotpwn arguments
}
```

### Parameters
- **target:** Target host or URL for traversal testing (required)
- **module:** Protocol module to use for testing (optional)
- **additional_args:** Additional command-line arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "output": "dotdotpwn traversal test results...",
    "command": "dotdotpwn -m http -h example.com",
    "execution_time": 12.3,
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
@app.route("/api/tools/dotdotpwn", methods=["POST"])
def dotdotpwn():
    """Execute DotDotPwn for directory traversal testing with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        module = params.get("module", "http")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 DotDotPwn called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"dotdotpwn -m {module} -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting DotDotPwn directory traversal test: {target}")
        result = execute_command(command)
        logger.info(f"📊 DotDotPwn test completed for {target}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in dotdotpwn endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
