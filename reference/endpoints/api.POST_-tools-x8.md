---
title: POST /api/tools/x8
group: api
handler: x8
module: __main__
line_range: [11151, 11184]
discovered_in_chunk: 11
---

# POST /api/tools/x8

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute x8 for hidden parameter discovery with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/x8", methods=["POST"])
def x8():
    """Execute x8 for hidden parameter discovery with enhanced logging"""
```

## Purpose & Behavior
x8 parameter discovery endpoint providing:
- **Hidden Parameter Discovery:** Find hidden parameters in web applications
- **Method Support:** Support for various HTTP methods
- **Custom Payloads:** Support for custom request bodies and headers
- **Enhanced Logging:** Detailed logging of parameter discovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/x8
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                 // Required: Target URL
    "wordlist": "string",            // Optional: Wordlist path (default: /usr/share/wordlists/x8/params.txt)
    "method": "string",              // Optional: HTTP method (default: GET)
    "body": "string",                // Optional: Request body
    "headers": "string",             // Optional: Custom headers
    "additional_args": "string"      // Optional: Additional x8 arguments
}
```

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string",
    "return_code": 0,
    "success": true,
    "execution_time": 15.7,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "x8 -u https://example.com -w /usr/share/wordlists/x8/params.txt -X GET"
}
```

## Code Reproduction
```python
@app.route("/api/tools/x8", methods=["POST"])
def x8():
    """Execute x8 for hidden parameter discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/x8/params.txt")
        method = params.get("method", "GET")
        body = params.get("body", "")
        headers = params.get("headers", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 x8 called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400
        
        command = f"x8 -u {url} -w {wordlist} -X {method}"
        
        if body:
            command += f" -b '{body}'"
        
        if headers:
            command += f" -H '{headers}'"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 x8 parameter discovery completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in x8 endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
