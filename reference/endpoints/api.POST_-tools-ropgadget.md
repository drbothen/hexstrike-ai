---
title: POST /api/tools/ropgadget
group: api
handler: ropgadget
module: __main__
line_range: [10218, 10249]
discovered_in_chunk: 10
---

# POST /api/tools/ropgadget

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Search for ROP gadgets in a binary using ROPgadget with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """Search for ROP gadgets in a binary using ROPgadget with enhanced logging"""
```

## Purpose & Behavior
ROPgadget search endpoint providing:
- **ROP Gadget Discovery:** Find Return-Oriented Programming gadgets in binaries
- **Gadget Filtering:** Filter gadgets by type (pop, ret, jmp, etc.)
- **Binary Analysis:** Analyze executable files for exploitation primitives
- **Enhanced Logging:** Detailed logging of ROP gadget search operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/ropgadget
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",              // Required: Path to binary file
    "gadget_type": "string",         // Optional: Type of gadgets to search for
    "additional_args": "string"      // Optional: Additional ROPgadget arguments
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
    "execution_time": 5.2,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "ROPgadget --binary /path/to/binary --only 'pop'"
}
```

## Code Reproduction
```python
@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """Search for ROP gadgets in a binary using ROPgadget with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "")
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 ROPgadget called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400
        
        command = f"ROPgadget --binary {binary}"
        
        if gadget_type:
            command += f" --only '{gadget_type}'"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting ROPgadget search: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ROPgadget search completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ropgadget endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
