---
title: POST /api/tools/nbtscan
group: api
handler: nbtscan
module: __main__
line_range: [9889, 9919]
discovered_in_chunk: 9
---

# POST /api/tools/nbtscan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute nbtscan for NetBIOS name scanning with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/nbtscan", methods=["POST"])
def nbtscan():
    """Execute nbtscan for NetBIOS name scanning with enhanced logging"""
```

## Purpose & Behavior
NetBIOS scanner execution endpoint providing:
- **NetBIOS Scanning:** Scan for NetBIOS names and services
- **Network Discovery:** Discover Windows systems on the network
- **Service Enumeration:** Enumerate NetBIOS services and shares
- **Enhanced Logging:** Detailed logging of scanning operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/nbtscan
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",              // Required: Target IP/network range
    "verbose": boolean,              // Optional: Verbose output (default: false)
    "timeout": integer,              // Optional: Timeout in seconds
    "additional_args": "string"      // Optional: Additional nbtscan arguments
}
```

### Parameters
- **target:** Target IP address or network range (required)
- **verbose:** Enable verbose output (optional, default: false)
- **timeout:** Timeout in seconds (optional)
- **additional_args:** Additional nbtscan arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string", 
    "return_code": 0,
    "success": true,
    "timed_out": false,
    "execution_time": 8.7,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "nbtscan 192.168.1.0/24"
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
@app.route("/api/tools/nbtscan", methods=["POST"])
def nbtscan():
    """Execute nbtscan for NetBIOS name scanning with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        verbose = params.get("verbose", False)
        timeout = params.get("timeout", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 NBTScan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nbtscan"
        
        if verbose:
            command += " -v"
        
        if timeout:
            command += f" -t {timeout}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target}"
        
        logger.info(f"🔍 Starting NBTScan: {target}")
        result = execute_command(command)
        logger.info(f"📊 NBTScan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nbtscan endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
