---
title: POST /api/tools/pwninit
group: api
handler: pwninit
module: __main__
line_range: [10767, 10802]
discovered_in_chunk: 10
---

# POST /api/tools/pwninit

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute pwninit for CTF binary exploitation setup

## Complete Signature & Definition
```python
@app.route("/api/tools/pwninit", methods=["POST"])
def pwninit():
    """Execute pwninit for CTF binary exploitation setup"""
```

## Purpose & Behavior
Pwninit CTF setup endpoint providing:
- **Binary Setup:** Automated CTF binary exploitation environment setup
- **Libc Integration:** Integrate specific libc versions for exploitation
- **Loader Configuration:** Configure dynamic loader for binary execution
- **Template Generation:** Generate exploitation templates (Python/C)
- **Enhanced Logging:** Detailed logging of setup operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/pwninit
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",              // Required: Path to binary file
    "libc": "string",                // Optional: Path to libc file
    "ld": "string",                  // Optional: Path to dynamic loader
    "template_type": "string",       // Optional: Template type (python, c)
    "additional_args": "string"      // Optional: Additional pwninit arguments
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
    "command": "pwninit --bin /path/to/binary --libc /path/to/libc.so.6 --template python"
}
```

## Code Reproduction
```python
@app.route("/api/tools/pwninit", methods=["POST"])
def pwninit():
    """Execute pwninit for CTF binary exploitation setup"""
    try:
        params = request.json
        binary = params.get("binary", "")
        libc = params.get("libc", "")
        ld = params.get("ld", "")
        template_type = params.get("template_type", "python")  # python, c
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 pwninit called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400
        
        command = f"pwninit --bin {binary}"
        
        if libc:
            command += f" --libc {libc}"
        
        if ld:
            command += f" --ld {ld}"
        
        if template_type:
            command += f" --template {template_type}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting pwninit setup: {binary}")
        result = execute_command(command)
        logger.info(f"📊 pwninit setup completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pwninit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
