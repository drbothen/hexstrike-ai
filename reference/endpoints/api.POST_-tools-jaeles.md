---
title: POST /api/tools/jaeles
group: api
handler: jaeles
module: __main__
line_range: [11186, 11219]
discovered_in_chunk: 11
---

# POST /api/tools/jaeles

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Jaeles for advanced vulnerability scanning with custom signatures

## Complete Signature & Definition
```python
@app.route("/api/tools/jaeles", methods=["POST"])
def jaeles():
    """Execute Jaeles for advanced vulnerability scanning with custom signatures"""
```

## Purpose & Behavior
Jaeles vulnerability scanning endpoint providing:
- **Custom Signature Scanning:** Use custom vulnerability signatures
- **Advanced Detection:** Advanced vulnerability detection capabilities
- **Configurable Threading:** Adjustable thread count for performance
- **Enhanced Logging:** Detailed logging of vulnerability scanning operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/jaeles
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                 // Required: Target URL
    "signatures": "string",          // Optional: Signature path/pattern
    "config": "string",              // Optional: Configuration file
    "threads": integer,              // Optional: Thread count (default: 20)
    "timeout": integer,              // Optional: Timeout in seconds (default: 20)
    "additional_args": "string"      // Optional: Additional jaeles arguments
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
    "execution_time": 42.1,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "jaeles scan -u https://example.com -c 20 --timeout 20"
}
```

## Code Reproduction
```python
@app.route("/api/tools/jaeles", methods=["POST"])
def jaeles():
    """Execute Jaeles for advanced vulnerability scanning with custom signatures"""
    try:
        params = request.json
        url = params.get("url", "")
        signatures = params.get("signatures", "")
        config = params.get("config", "")
        threads = params.get("threads", 20)
        timeout = params.get("timeout", 20)
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 Jaeles called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400
        
        command = f"jaeles scan -u {url} -c {threads} --timeout {timeout}"
        
        if signatures:
            command += f" -s {signatures}"
        
        if config:
            command += f" --config {config}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Jaeles vulnerability scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in jaeles endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
