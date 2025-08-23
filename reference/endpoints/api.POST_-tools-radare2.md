---
title: POST /api/tools/radare2
group: api
handler: radare2
module: __main__
line_range: [10140, 10181]
discovered_in_chunk: 10
---

# POST /api/tools/radare2

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Radare2 for binary analysis and reverse engineering with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/radare2", methods=["POST"])
def radare2():
    """Execute Radare2 for binary analysis and reverse engineering with enhanced logging"""
```

## Purpose & Behavior
Radare2 binary analysis endpoint providing:
- **Binary Analysis:** Comprehensive binary analysis and reverse engineering
- **Script Support:** Execute custom r2 command scripts
- **Disassembly:** Advanced disassembly and code analysis
- **Enhanced Logging:** Detailed logging of binary analysis operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/radare2
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",              // Required: Path to binary file
    "commands": "string",            // Optional: R2 commands to execute
    "additional_args": "string"      // Optional: Additional radare2 arguments
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
    "execution_time": 15.3,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "r2 -i /tmp/r2_commands.txt -q /path/to/binary"
}
```

## Code Reproduction
```python
@app.route("/api/tools/radare2", methods=["POST"])
def radare2():
    """Execute Radare2 for binary analysis and reverse engineering with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 Radare2 called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400
        
        if commands:
            temp_script = "/tmp/r2_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command = f"r2 -i {temp_script} -q {binary}"
        else:
            command = f"r2 -q {binary}"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = execute_command(command)
        
        if commands and os.path.exists("/tmp/r2_commands.txt"):
            try:
                os.remove("/tmp/r2_commands.txt")
            except:
                pass
                
        logger.info(f"📊 Radare2 analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in radare2 endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
