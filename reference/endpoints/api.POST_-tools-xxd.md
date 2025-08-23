---
title: POST /api/tools/xxd
group: api
handler: xxd
module: __main__
line_range: [10276, 10310]
discovered_in_chunk: 10
---

# POST /api/tools/xxd

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Create a hex dump of a file using xxd with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/xxd", methods=["POST"])
def xxd():
    """Create a hex dump of a file using xxd with enhanced logging"""
```

## Purpose & Behavior
XXD hex dump endpoint providing:
- **Hex Dump Generation:** Create hexadecimal dumps of binary files
- **Offset Control:** Start hex dump from specific byte offset
- **Length Control:** Limit hex dump to specific byte length
- **Enhanced Logging:** Detailed logging of hex dump operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/xxd
- **Content-Type:** application/json

### Request Body
```json
{
    "file_path": "string",           // Required: Path to file to dump
    "offset": "string",              // Optional: Starting offset (default: "0")
    "length": "string",              // Optional: Number of bytes to dump
    "additional_args": "string"      // Optional: Additional xxd arguments
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
    "execution_time": 0.8,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "xxd -s 0 -l 256 /path/to/file"
}
```

## Code Reproduction
```python
@app.route("/api/tools/xxd", methods=["POST"])
def xxd():
    """Create a hex dump of a file using xxd with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        offset = params.get("offset", "0")
        length = params.get("length", "")
        additional_args = params.get("additional_args", "")
        
        if not file_path:
            logger.warning("🔧 XXD called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400
        
        command = f"xxd -s {offset}"
        
        if length:
            command += f" -l {length}"
            
        if additional_args:
            command += f" {additional_args}"
            
        command += f" {file_path}"
        
        logger.info(f"🔧 Starting XXD hex dump: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 XXD hex dump completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xxd endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
