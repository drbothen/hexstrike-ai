---
title: POST /api/tools/ropper
group: api
handler: ropper
module: __main__
line_range: [10720, 10765]
discovered_in_chunk: 10
---

# POST /api/tools/ropper

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute ropper for advanced ROP/JOP gadget searching

## Complete Signature & Definition
```python
@app.route("/api/tools/ropper", methods=["POST"])
def ropper():
    """Execute ropper for advanced ROP/JOP gadget searching"""
```

## Purpose & Behavior
Ropper gadget discovery endpoint providing:
- **ROP Gadget Discovery:** Find Return-Oriented Programming gadgets
- **JOP Gadget Discovery:** Find Jump-Oriented Programming gadgets
- **System Call Gadgets:** Discover system call gadgets
- **Quality Filtering:** Filter gadgets by quality level (1-5)
- **Architecture Support:** Support for multiple architectures
- **Enhanced Logging:** Detailed logging of gadget discovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/ropper
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",              // Required: Path to binary file
    "gadget_type": "string",         // Optional: Gadget type (rop, jop, sys, all)
    "quality": integer,              // Optional: Quality level 1-5 (default: 1)
    "arch": "string",                // Optional: Architecture (x86, x86_64, arm, etc.)
    "search_string": "string",       // Optional: Search for specific gadget patterns
    "additional_args": "string"      // Optional: Additional ropper arguments
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
    "execution_time": 12.4,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "ropper --file /path/to/binary --rop --quality 2"
}
```

## Code Reproduction
```python
@app.route("/api/tools/ropper", methods=["POST"])
def ropper():
    """Execute ropper for advanced ROP/JOP gadget searching"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "rop")  # rop, jop, sys, all
        quality = params.get("quality", 1)  # 1-5, higher = better quality
        arch = params.get("arch", "")  # x86, x86_64, arm, etc.
        search_string = params.get("search_string", "")
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 ropper called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400
        
        command = f"ropper --file {binary}"
        
        if gadget_type == "rop":
            command += " --rop"
        elif gadget_type == "jop":
            command += " --jop"
        elif gadget_type == "sys":
            command += " --sys"
        elif gadget_type == "all":
            command += " --all"
        
        if quality > 1:
            command += f" --quality {quality}"
        
        if arch:
            command += f" --arch {arch}"
        
        if search_string:
            command += f" --search '{search_string}'"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting ropper analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ropper analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ropper endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
