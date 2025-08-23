---
title: POST /api/tools/gdb
group: api
handler: gdb
module: __main__
line_range: [10091, 10138]
discovered_in_chunk: 10
---

# POST /api/tools/gdb

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute GDB for binary analysis and debugging with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/gdb", methods=["POST"])
def gdb():
    """Execute GDB for binary analysis and debugging with enhanced logging"""
```

## Purpose & Behavior
Binary analysis and debugging endpoint providing:
- **Binary Debugging:** Execute GDB for comprehensive binary analysis and debugging
- **Script Execution:** Support for GDB script files and command sequences
- **Automated Analysis:** Batch mode execution for automated binary analysis
- **Reverse Engineering:** Advanced debugging capabilities for reverse engineering

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/gdb
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",                 // Required: Path to binary file to analyze
    "commands": "string",               // Optional: GDB commands to execute
    "script_file": "string",            // Optional: Path to GDB script file
    "additional_args": "string"         // Optional: Additional GDB arguments
}
```

### Parameters
- **binary:** Path to binary file for analysis (required)
- **commands:** GDB commands to execute (optional)
- **script_file:** Path to existing GDB script file (optional)
- **additional_args:** Additional GDB arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // GDB analysis output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 45.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "gdb /path/to/binary -x /tmp/gdb_commands.txt -batch"
}
```

### Error Responses

#### Missing Binary (400 Bad Request)
```json
{
    "error": "Binary parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Command Construction Process
1. **Base Command:** Start with "gdb {binary}"
2. **Script Configuration:** Add script file if provided
3. **Command Execution:** Create temporary script for commands if provided
4. **Batch Mode:** Add -batch flag for automated execution
5. **Additional Arguments:** Append additional arguments

### Script File Handling

#### Existing Script File
```python
if script_file:
    command += f" -x {script_file}"
```

#### Dynamic Command Script
```python
if commands:
    temp_script = "/tmp/gdb_commands.txt"
    with open(temp_script, "w") as f:
        f.write(commands)
    command += f" -x {temp_script}"
```

### Batch Mode Execution
```python
command += " -batch"
```

### File Cleanup
```python
if commands and os.path.exists("/tmp/gdb_commands.txt"):
    try:
        os.remove("/tmp/gdb_commands.txt")
    except:
        pass
```

### Common GDB Commands

#### Basic Analysis
- **info functions:** List functions in binary
- **info variables:** List variables
- **disassemble main:** Disassemble main function
- **info registers:** Show register values

#### Advanced Analysis
- **x/20i $pc:** Examine instructions at program counter
- **bt:** Show backtrace
- **info proc mappings:** Show memory mappings
- **checksec:** Check security features

#### Debugging Commands
- **break main:** Set breakpoint at main
- **run:** Start program execution
- **continue:** Continue execution
- **step:** Step through instructions

### GDB Features
- **Binary Analysis:** Comprehensive binary analysis capabilities
- **Debugging:** Interactive and batch debugging
- **Disassembly:** Assembly code disassembly
- **Memory Analysis:** Memory layout and content analysis

## AuthN/AuthZ
- **File System Access:** Requires access to binary files
- **Debugging Tool:** Binary analysis and debugging tool

## Observability
- **Analysis Logging:** "🔧 Starting GDB analysis: {binary}"
- **Completion Logging:** "📊 GDB analysis completed for {binary}"
- **Warning Logging:** "🔧 GDB called without binary parameter"
- **Error Logging:** "💥 Error in gdb endpoint: {error}"

## Use Cases and Applications

#### Reverse Engineering
- **Binary Analysis:** Analyze binary structure and functionality
- **Function Analysis:** Analyze individual functions and their behavior
- **Control Flow Analysis:** Understand program control flow

#### Vulnerability Research
- **Exploit Development:** Develop and test exploits
- **Buffer Overflow Analysis:** Analyze buffer overflow vulnerabilities
- **ROP Chain Development:** Develop return-oriented programming chains

#### Malware Analysis
- **Dynamic Analysis:** Analyze malware behavior during execution
- **Anti-debugging Detection:** Detect anti-debugging techniques
- **Payload Analysis:** Analyze malware payloads

## Testing & Validation
- Binary file path validation
- Command execution verification
- Script file functionality testing
- Batch mode operation validation

## Code Reproduction
```python
# From line 10091: Complete Flask endpoint implementation
@app.route("/api/tools/gdb", methods=["POST"])
def gdb():
    """Execute GDB for binary analysis and debugging with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        script_file = params.get("script_file", "")
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 GDB called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400
        
        command = f"gdb {binary}"
        
        # Handle script file or commands
        if script_file:
            command += f" -x {script_file}"
        elif commands:
            # Create temporary script file for commands
            temp_script = "/tmp/gdb_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command += f" -x {temp_script}"
        
        # Add batch mode for automated execution
        command += " -batch"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting GDB analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 GDB analysis completed for {binary}")
        
        # Clean up temporary script file
        if commands and os.path.exists("/tmp/gdb_commands.txt"):
            try:
                os.remove("/tmp/gdb_commands.txt")
            except:
                pass
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gdb endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
