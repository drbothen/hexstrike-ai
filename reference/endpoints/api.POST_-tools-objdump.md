---
title: POST /api/tools/objdump
group: api
handler: objdump
module: __main__
line_range: [10344, 10379]
discovered_in_chunk: 10
---

# POST /api/tools/objdump

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Analyze a binary using objdump with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/objdump", methods=["POST"])
def objdump():
    """Analyze a binary using objdump with enhanced logging"""
```

## Purpose & Behavior
Objdump binary analysis endpoint providing:
- **Disassembly Analysis:** Disassemble binary code sections
- **Header Analysis:** Analyze binary headers and sections
- **Symbol Information:** Extract symbol tables and debugging information
- **Enhanced Logging:** Detailed logging of binary analysis operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/objdump
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",              // Required: Path to binary file
    "disassemble": boolean,          // Optional: Disassemble code (default: true)
    "additional_args": "string"      // Optional: Additional objdump arguments
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
    "execution_time": 3.4,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "objdump -d /path/to/binary"
}
```

## Code Reproduction
```python
@app.route("/api/tools/objdump", methods=["POST"])
def objdump():
    """Analyze a binary using objdump with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        disassemble = params.get("disassemble", True)
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 Objdump called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400
        
        command = f"objdump"
        
        if disassemble:
            command += " -d"
        else:
            command += " -x"
            
        if additional_args:
            command += f" {additional_args}"
            
        command += f" {binary}"
        
        logger.info(f"🔧 Starting Objdump analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Objdump analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in objdump endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
