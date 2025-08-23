---
title: POST /api/tools/responder
group: api
handler: responder
module: __main__
line_range: [9958, 9998]
discovered_in_chunk: 9
---

# POST /api/tools/responder

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Responder for credential harvesting with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/responder", methods=["POST"])
def responder():
    """Execute Responder for credential harvesting with enhanced logging"""
```

## Purpose & Behavior
Responder execution endpoint providing:
- **Credential Harvesting:** Capture network credentials via poisoning attacks
- **Protocol Poisoning:** Poison LLMNR, NBT-NS, and mDNS protocols
- **Network Interception:** Intercept and analyze network authentication
- **Enhanced Logging:** Detailed logging of harvesting operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/responder
- **Content-Type:** application/json

### Request Body
```json
{
    "interface": "string",           // Required: Network interface to use
    "analyze": boolean,              // Optional: Analyze mode only (default: false)
    "wpad": boolean,                 // Optional: Enable WPAD rogue proxy (default: false)
    "force_wpad_auth": boolean,      // Optional: Force WPAD authentication (default: false)
    "fingerprint": boolean,          // Optional: Fingerprint mode (default: false)
    "additional_args": "string"      // Optional: Additional responder arguments
}
```

### Parameters
- **interface:** Network interface to use (required)
- **analyze:** Run in analyze mode only (optional, default: false)
- **wpad:** Enable WPAD rogue proxy server (optional, default: false)
- **force_wpad_auth:** Force WPAD authentication (optional, default: false)
- **fingerprint:** Run in fingerprint mode (optional, default: false)
- **additional_args:** Additional responder arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string",
    "return_code": 0,
    "success": true,
    "timed_out": false,
    "execution_time": 120.5,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "responder -I eth0"
}
```

### Error Responses

#### Missing Interface (400 Bad Request)
```json
{
    "error": "Interface parameter is required"
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
@app.route("/api/tools/responder", methods=["POST"])
def responder():
    """Execute Responder for credential harvesting with enhanced logging"""
    try:
        params = request.json
        interface = params.get("interface", "eth0")
        analyze = params.get("analyze", False)
        wpad = params.get("wpad", True)
        force_wpad_auth = params.get("force_wpad_auth", False)
        fingerprint = params.get("fingerprint", False)
        duration = params.get("duration", 300)  # 5 minutes default
        additional_args = params.get("additional_args", "")
        
        if not interface:
            logger.warning("🎯 Responder called without interface parameter")
            return jsonify({"error": "Interface parameter is required"}), 400
        
        command = f"timeout {duration} responder -I {interface}"
        
        if analyze:
            command += " -A"
        
        if wpad:
            command += " -w"
        
        if force_wpad_auth:
            command += " -F"
        
        if fingerprint:
            command += " -f"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting Responder on interface: {interface}")
        result = execute_command(command)
        logger.info(f"📊 Responder completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in responder endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
