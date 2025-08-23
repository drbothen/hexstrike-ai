---
title: POST /api/tools/hashpump
group: api
handler: hashpump
module: __main__
line_range: [13534, 13564]
discovered_in_chunk: 13
---

# POST /api/tools/hashpump

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute HashPump for hash length extension attacks with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/hashpump", methods=["POST"])
def hashpump():
    """Execute HashPump for hash length extension attacks with enhanced logging"""
```

## Purpose & Behavior
HashPump hash length extension attack endpoint providing:
- **Length Extension Attacks:** Perform hash length extension attacks on vulnerable hash functions
- **Multiple Hash Support:** Support for various hash algorithms (MD5, SHA1, SHA256, etc.)
- **Flexible Parameters:** Configurable signature, data, key length, and append data
- **Enhanced Logging:** Detailed logging of hash extension attack operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/hashpump
- **Content-Type:** application/json

### Request Body
```json
{
    "signature": "string",           // Required: Original hash signature
    "data": "string",                // Required: Original data
    "key_length": "string",          // Required: Key length for extension
    "append_data": "string",         // Required: Data to append
    "additional_args": "string"      // Optional: Additional hashpump arguments
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
    "execution_time": 2.1,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "hashpump -s abc123 -d 'original data' -k 16 -a 'appended data'"
}
```

## Code Reproduction
```python
@app.route("/api/tools/hashpump", methods=["POST"])
def hashpump():
    """Execute HashPump for hash length extension attacks with enhanced logging"""
    try:
        params = request.json
        signature = params.get("signature", "")
        data = params.get("data", "")
        key_length = params.get("key_length", "")
        append_data = params.get("append_data", "")
        additional_args = params.get("additional_args", "")
        
        if not all([signature, data, key_length, append_data]):
            logger.warning("🔐 HashPump called without required parameters")
            return jsonify({
                "error": "Signature, data, key_length, and append_data parameters are required"
            }), 400
        
        command = f"hashpump -s {signature} -d '{data}' -k {key_length} -a '{append_data}'"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔐 Starting HashPump attack")
        result = execute_command(command)
        logger.info(f"📊 HashPump attack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hashpump endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
