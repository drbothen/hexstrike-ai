---
title: POST /api/tools/dirb
group: api
handler: dirb
module: __main__
line_range: [9088, 9116]
discovered_in_chunk: 9
---

# POST /api/tools/dirb

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute dirb with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with enhanced logging"""
```

## Purpose & Behavior
Dirb web directory brute-forcing endpoint providing:
- **Directory Discovery:** Discover hidden directories and files on web servers
- **Wordlist-Based Scanning:** Use custom or default wordlists for brute-forcing
- **Recursive Scanning:** Recursively scan discovered directories
- **Enhanced Logging:** Comprehensive logging of scan progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/dirb
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                // Required: Target URL to scan
    "wordlist": "string",           // Optional: Wordlist file path (default: "/usr/share/wordlists/dirb/common.txt")
    "additional_args": "string"     // Optional: Additional dirb arguments
}
```

### Parameters
- **url:** Target URL to scan for directories (required)
- **wordlist:** Path to wordlist file (optional, default: "/usr/share/wordlists/dirb/common.txt")
- **additional_args:** Additional dirb command arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Dirb scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 120.8,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "dirb http://example.com /usr/share/wordlists/dirb/common.txt" // Actual command executed
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
@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"📁 Starting Dirb scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirb scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirb endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
