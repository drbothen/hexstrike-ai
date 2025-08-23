---
title: POST /api/tools/dirsearch
group: api
handler: dirsearch
module: __main__
line_range: [10938, 10969]
discovered_in_chunk: 11
---

# POST /api/tools/dirsearch

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Dirsearch for advanced directory and file discovery with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    """Execute Dirsearch for advanced directory and file discovery with enhanced logging"""
```

## Purpose & Behavior
Dirsearch directory enumeration endpoint providing:
- **Advanced Discovery:** Next-generation directory and file discovery
- **Intelligent Filtering:** Smart filtering of results and false positives
- **Multi-Threading:** High-performance concurrent scanning
- **Enhanced Logging:** Comprehensive logging of discovery progress

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/dirsearch
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                    // Required: Target URL to scan
    "extensions": "string",             // Optional: File extensions to search for
    "additional_args": "string"         // Optional: Additional dirsearch arguments
}
```

### Parameters
- **url:** Target URL for directory discovery (required)
- **extensions:** File extensions to search for (optional)
- **additional_args:** Additional command-line arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "output": "dirsearch discovery results...",
    "command": "dirsearch -u https://example.com -e php,html,js",
    "execution_time": 18.7,
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
@app.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    """Execute Dirsearch for advanced directory and file discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        extensions = params.get("extensions", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 Dirsearch called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirsearch -u {url}"
        
        if extensions:
            command += f" -e {extensions}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"📁 Starting Dirsearch directory discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirsearch scan completed for {url}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in dirsearch endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
