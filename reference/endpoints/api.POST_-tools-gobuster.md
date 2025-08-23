---
title: POST /api/tools/gobuster
group: api
handler: gobuster
module: __main__
line_range: [8508, 8559]
discovered_in_chunk: 9
---

# POST /api/tools/gobuster

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute gobuster with enhanced logging and intelligent error handling

## Complete Signature & Definition
```python
@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with enhanced logging and intelligent error handling"""
```

## Purpose & Behavior
Gobuster directory/DNS/vhost enumeration endpoint providing:
- **Multi-Mode Support:** Directory, DNS, fuzz, and vhost enumeration modes
- **Intelligent Error Handling:** Optional recovery system for failed scans
- **Flexible Wordlists:** Configurable wordlist selection with default fallback
- **Enhanced Logging:** Comprehensive logging of scan progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/gobuster
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                    // Required: Target URL to scan
    "mode": "string",                   // Optional: Scan mode (dir, dns, fuzz, vhost) - default: "dir"
    "wordlist": "string",               // Optional: Path to wordlist - default: "/usr/share/wordlists/dirb/common.txt"
    "additional_args": "string",        // Optional: Additional gobuster arguments
    "use_recovery": boolean             // Optional: Enable intelligent error handling - default: true
}
```

### Parameters
- **url:** Target URL to scan (required)
- **mode:** Gobuster scan mode - must be one of: dir, dns, fuzz, vhost (optional, default: "dir")
- **wordlist:** Path to wordlist file (optional, default: "/usr/share/wordlists/dirb/common.txt")
- **additional_args:** Additional command-line arguments (optional)
- **use_recovery:** Enable intelligent error handling and recovery (optional, default: true)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "output": "gobuster scan results...",
    "command": "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt",
    "execution_time": 15.2,
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

#### Invalid Mode (400 Bad Request)
```json
{
    "error": "Invalid mode: invalid_mode. Must be one of: dir, dns, fuzz, vhost"
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
@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)
        
        if not url:
            logger.warning("🌐 Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"❌ Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"📁 Starting Gobuster {mode} scan: {url}")
        
        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": url,
                "mode": mode,
                "wordlist": wordlist,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("gobuster", command, tool_params)
        else:
            result = execute_command(command)
        
        logger.info(f"📊 Gobuster scan completed for {url}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in gobuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
