---
title: POST /api/tools/msfvenom
group: api
handler: msfvenom
module: __main__
line_range: [10042, 10085]
discovered_in_chunk: 10
---

# POST /api/tools/msfvenom

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute MSFVenom to generate payloads with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/msfvenom", methods=["POST"])
def msfvenom():
    """Execute MSFVenom to generate payloads with enhanced logging"""
```

## Purpose & Behavior
MSFVenom payload generation endpoint providing:
- **Payload Generation:** Generate various types of payloads for penetration testing
- **Multi-Platform Support:** Support for Windows, Linux, macOS, and other platforms
- **Format Options:** Multiple output formats (exe, elf, raw, etc.)
- **Enhanced Logging:** Detailed logging of payload generation operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/msfvenom
- **Content-Type:** application/json

### Request Body
```json
{
    "payload": "string",             // Required: Payload type (e.g., windows/meterpreter/reverse_tcp)
    "format": "string",              // Optional: Output format (exe, elf, raw, etc.)
    "output_file": "string",         // Optional: Output file path
    "encoder": "string",             // Optional: Encoder to use
    "iterations": "string",          // Optional: Encoding iterations
    "additional_args": "string"      // Optional: Additional msfvenom arguments
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
    "execution_time": 12.5,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "msfvenom -p windows/meterpreter/reverse_tcp -f exe"
}
```

## Code Reproduction
```python
@app.route("/api/tools/msfvenom", methods=["POST"])
def msfvenom():
    """Execute MSFVenom to generate payloads with enhanced logging"""
    try:
        params = request.json
        payload = params.get("payload", "")
        format_type = params.get("format", "")
        output_file = params.get("output_file", "")
        encoder = params.get("encoder", "")
        iterations = params.get("iterations", "")
        additional_args = params.get("additional_args", "")
        
        if not payload:
            logger.warning("🚀 MSFVenom called without payload parameter")
            return jsonify({
                "error": "Payload parameter is required"
            }), 400
        
        command = f"msfvenom -p {payload}"
        
        if format_type:
            command += f" -f {format_type}"
            
        if output_file:
            command += f" -o {output_file}"
            
        if encoder:
            command += f" -e {encoder}"
            
        if iterations:
            command += f" -i {iterations}"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
        result = execute_command(command)
        logger.info(f"📊 MSFVenom payload generated")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in msfvenom endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
