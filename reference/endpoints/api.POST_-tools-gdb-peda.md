---
title: POST /api/tools/gdb-peda
group: api
handler: gdb_peda
module: __main__
line_range: [10567, 10627]
discovered_in_chunk: 10
---

# POST /api/tools/gdb-peda

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute GDB with PEDA for enhanced debugging and exploitation

## Complete Signature & Definition
```python
@app.route("/api/tools/gdb-peda", methods=["POST"])
def gdb_peda():
    """Execute GDB with PEDA for enhanced debugging and exploitation"""
```

## Purpose & Behavior
GDB-PEDA debugging endpoint providing:
- **Enhanced Debugging:** GDB with PEDA extensions for exploit development
- **Binary Analysis:** Debug binaries with advanced PEDA features
- **Process Attachment:** Attach to running processes for live debugging
- **Core File Analysis:** Analyze core dumps with PEDA enhancements
- **Enhanced Logging:** Detailed logging of debugging operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/gdb-peda
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",              // Optional: Path to binary file
    "commands": "string",            // Optional: GDB commands to execute
    "attach_pid": integer,           // Optional: Process ID to attach to
    "core_file": "string",           // Optional: Core file to analyze
    "additional_args": "string"      // Optional: Additional GDB arguments
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
    "execution_time": 8.3,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "gdb -q /path/to/binary -ex 'source ~/peda/peda.py' -ex 'quit'"
}
```

## Code Reproduction
```python
@app.route("/api/tools/gdb-peda", methods=["POST"])
def gdb_peda():
    """Execute GDB with PEDA for enhanced debugging and exploitation"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        attach_pid = params.get("attach_pid", 0)
        core_file = params.get("core_file", "")
        additional_args = params.get("additional_args", "")
        
        if not binary and not attach_pid and not core_file:
            logger.warning("🔧 GDB-PEDA called without binary, PID, or core file")
            return jsonify({"error": "Binary, PID, or core file parameter is required"}), 400
        
        # Base GDB command with PEDA
        command = "gdb -q"
        
        if binary:
            command += f" {binary}"
        
        if core_file:
            command += f" {core_file}"
        
        if attach_pid:
            command += f" -p {attach_pid}"
        
        # Create command script
        if commands:
            temp_script = "/tmp/gdb_peda_commands.txt"
            peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
            with open(temp_script, "w") as f:
                f.write(peda_commands)
            command += f" -x {temp_script}"
        else:
            # Default PEDA initialization
            command += " -ex 'source ~/peda/peda.py' -ex 'quit'"
        
        if additional_args:
            command += f" {additional_args}"
        
        target_info = binary or f'PID {attach_pid}' or core_file
        logger.info(f"🔧 Starting GDB-PEDA analysis: {target_info}")
        result = execute_command(command)
        
        # Cleanup
        if commands and os.path.exists("/tmp/gdb_peda_commands.txt"):
            try:
                os.remove("/tmp/gdb_peda_commands.txt")
            except:
                pass
        
        logger.info(f"📊 GDB-PEDA analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gdb-peda endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
