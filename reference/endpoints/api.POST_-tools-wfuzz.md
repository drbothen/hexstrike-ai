---
title: POST /api/tools/wfuzz
group: api
handler: wfuzz
module: __main__
line_range: [10904, 10934]
discovered_in_chunk: 11
---

# POST /api/tools/wfuzz

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Wfuzz for web application fuzzing with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz for web application fuzzing with enhanced logging"""
```

## Purpose & Behavior
Wfuzz web application fuzzing endpoint providing:
- **Comprehensive Fuzzing:** Advanced web application fuzzing capabilities
- **Flexible Payloads:** Support for multiple payload types and wordlists
- **Parameter Fuzzing:** Fuzz various HTTP parameters, headers, and data
- **Enhanced Logging:** Detailed logging of fuzzing progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/wfuzz
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                    // Required: Target URL to fuzz
    "wordlist": "string",               // Optional: Path to wordlist file
    "additional_args": "string"         // Optional: Additional wfuzz arguments
}
```

### Parameters
- **url:** Target URL for fuzzing (required)
- **wordlist:** Path to wordlist file for payloads (optional)
- **additional_args:** Additional command-line arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "output": "wfuzz fuzzing results...",
    "command": "wfuzz -w /path/to/wordlist.txt https://example.com/FUZZ",
    "execution_time": 25.4,
    "timestamp": "2024-01-01T12:00:00Z"
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
@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz for web application fuzzing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 Wfuzz called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wfuzz"
        
        if wordlist:
            command += f" -w {wordlist}"
        
        command += f" {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting Wfuzz fuzzing: {url}")
        result = execute_command(command)
        logger.info(f"📊 Wfuzz fuzzing completed for {url}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in wfuzz endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
