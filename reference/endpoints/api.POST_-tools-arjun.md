---
title: POST /api/tools/arjun
group: api
handler: arjun
module: __main__
line_range: [11078, 11118]
discovered_in_chunk: 11
---

# POST /api/tools/arjun

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Arjun for HTTP parameter discovery with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """Execute Arjun for HTTP parameter discovery with enhanced logging"""
```

## Purpose & Behavior
Arjun parameter discovery endpoint providing:
- **Parameter Discovery:** Find hidden HTTP parameters in web applications
- **Method Support:** Support for GET, POST, and other HTTP methods
- **Threading Control:** Configurable threading for performance optimization
- **Enhanced Logging:** Detailed logging of parameter discovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/arjun
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                 // Required: Target URL
    "method": "string",              // Optional: HTTP method (default: GET)
    "wordlist": "string",            // Optional: Custom wordlist path
    "delay": integer,                // Optional: Delay between requests (default: 0)
    "threads": integer,              // Optional: Number of threads (default: 25)
    "stable": boolean,               // Optional: Stable mode (default: false)
    "additional_args": "string"      // Optional: Additional arjun arguments
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
    "execution_time": 32.1,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "arjun -u https://example.com -m GET -t 25"
}
```

## Code Reproduction
```python
@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """Execute Arjun for HTTP parameter discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        method = params.get("method", "GET")
        wordlist = params.get("wordlist", "")
        delay = params.get("delay", 0)
        threads = params.get("threads", 25)
        stable = params.get("stable", False)
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 Arjun called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400
        
        command = f"arjun -u {url} -m {method} -t {threads}"
        
        if wordlist:
            command += f" -w {wordlist}"
        
        if delay > 0:
            command += f" -d {delay}"
        
        if stable:
            command += " --stable"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting Arjun parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 Arjun parameter discovery completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in arjun endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
