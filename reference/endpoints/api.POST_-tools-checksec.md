---
title: POST /api/tools/checksec
group: api
handler: checksec
module: __main__
line_range: [10251, 10274]
discovered_in_chunk: 10
---

# POST /api/tools/checksec

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Check security features of a binary with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """Check security features of a binary with enhanced logging"""
```

## Purpose & Behavior
Checksec binary security analysis endpoint providing:
- **Security Feature Detection:** Check for ASLR, DEP, Stack Canaries, PIE, etc.
- **Binary Hardening Analysis:** Analyze security mitigations in executables
- **Comprehensive Reporting:** Detailed security feature assessment
- **Enhanced Logging:** Detailed logging of security analysis operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/checksec
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string"               // Required: Path to binary file
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
    "execution_time": 1.2,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "checksec --file=/path/to/binary"
}
```

## Code Reproduction
```python
@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """Check security features of a binary with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        
        if not binary:
            logger.warning("🔧 Checksec called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400
        
        command = f"checksec --file={binary}"
        
        logger.info(f"🔧 Starting Checksec analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Checksec analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in checksec endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
