---
title: POST /api/tools/one-gadget
group: api
handler: one_gadget
module: __main__
line_range: [10500, 10524]
discovered_in_chunk: 10
---

# POST /api/tools/one-gadget

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute one_gadget to find one-shot RCE gadgets in libc

## Complete Signature & Definition
```python
@app.route("/api/tools/one-gadget", methods=["POST"])
def one_gadget():
    """Execute one_gadget to find one-shot RCE gadgets in libc"""
```

## Purpose & Behavior
One-gadget RCE discovery endpoint providing:
- **One-shot RCE Discovery:** Find gadgets that provide immediate shell access
- **Constraint Analysis:** Analyze different constraint levels for gadgets
- **Libc Analysis:** Analyze specific libc versions for exploitation primitives
- **Enhanced Logging:** Detailed logging of gadget discovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/one-gadget
- **Content-Type:** application/json

### Request Body
```json
{
    "libc_path": "string",           // Required: Path to libc file
    "level": integer,                // Optional: Constraint level 0,1,2 (default: 1)
    "additional_args": "string"      // Optional: Additional one_gadget arguments
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
    "execution_time": 3.7,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "one_gadget /lib/x86_64-linux-gnu/libc.so.6 --level 1"
}
```

## Code Reproduction
```python
@app.route("/api/tools/one-gadget", methods=["POST"])
def one_gadget():
    """Execute one_gadget to find one-shot RCE gadgets in libc"""
    try:
        params = request.json
        libc_path = params.get("libc_path", "")
        level = params.get("level", 1)  # 0, 1, 2 for different constraint levels
        additional_args = params.get("additional_args", "")
        
        if not libc_path:
            logger.warning("🔧 one_gadget called without libc_path parameter")
            return jsonify({"error": "libc_path parameter is required"}), 400
        
        command = f"one_gadget {libc_path} --level {level}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
        result = execute_command(command)
        logger.info(f"📊 one_gadget analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in one_gadget endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
