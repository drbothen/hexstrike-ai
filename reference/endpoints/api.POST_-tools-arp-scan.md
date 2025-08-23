---
title: POST /api/tools/arp-scan
group: api
handler: arp_scan
module: __main__
line_range: [9921, 9956]
discovered_in_chunk: 9
---

# POST /api/tools/arp-scan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute arp-scan for network discovery with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/arp-scan", methods=["POST"])
def arp_scan():
    """Execute arp-scan for network discovery with enhanced logging"""
```

## Purpose & Behavior
ARP scanner execution endpoint providing:
- **Network Discovery:** Discover active hosts using ARP requests
- **MAC Address Detection:** Identify MAC addresses and vendors
- **Local Network Scanning:** Scan local network segments efficiently
- **Enhanced Logging:** Detailed logging of scanning operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/arp-scan
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",              // Required: Target network range
    "interface": "string",           // Optional: Network interface to use
    "local": boolean,                // Optional: Scan local network (default: false)
    "timeout": integer,              // Optional: Timeout in milliseconds
    "additional_args": "string"      // Optional: Additional arp-scan arguments
}
```

### Parameters
- **target:** Target network range (required)
- **interface:** Network interface to use (optional)
- **local:** Scan local network automatically (optional, default: false)
- **timeout:** Timeout in milliseconds (optional)
- **additional_args:** Additional arp-scan arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string",
    "return_code": 0,
    "success": true,
    "timed_out": false,
    "execution_time": 5.2,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "arp-scan 192.168.1.0/24"
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
@app.route("/api/tools/arp-scan", methods=["POST"])
def arp_scan():
    """Execute arp-scan for network discovery with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        interface = params.get("interface", "")
        local_network = params.get("local_network", False)
        timeout = params.get("timeout", 500)
        retry = params.get("retry", 3)
        additional_args = params.get("additional_args", "")
        
        if not target and not local_network:
            logger.warning("🎯 arp-scan called without target parameter")
            return jsonify({"error": "Target parameter or local_network flag is required"}), 400
        
        command = f"arp-scan -t {timeout} -r {retry}"
        
        if interface:
            command += f" -I {interface}"
        
        if local_network:
            command += " -l"
        else:
            command += f" {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = execute_command(command)
        logger.info(f"📊 arp-scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in arp-scan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
