---
title: POST /api/tools/pacu
group: api
handler: pacu
module: __main__
line_range: [8785, 8835]
discovered_in_chunk: 9
---

# POST /api/tools/pacu

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Pacu for AWS exploitation framework

## Complete Signature & Definition
```python
@app.route("/api/tools/pacu", methods=["POST"])
def pacu():
    """Execute Pacu for AWS exploitation framework"""
```

## Purpose & Behavior
Pacu AWS exploitation framework endpoint providing:
- **AWS Exploitation:** Comprehensive AWS exploitation and post-exploitation framework
- **Module Execution:** Execute specific Pacu modules for AWS attacks
- **Session Management:** Manage Pacu sessions for organized testing
- **Data Collection:** Collect AWS environment data for analysis

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/pacu
- **Content-Type:** application/json

### Request Body
```json
{
    "session_name": "string",       // Optional: Pacu session name (default: "hexstrike_session")
    "modules": "string",            // Optional: Comma-separated list of modules to run
    "data_services": "string",      // Optional: Data services to enumerate
    "regions": "string",            // Optional: AWS regions to target
    "additional_args": "string"     // Optional: Additional Pacu arguments
}
```

### Parameters
- **session_name:** Pacu session name (optional, default: "hexstrike_session")
- **modules:** Comma-separated list of Pacu modules to execute (optional)
- **data_services:** Data services to enumerate (optional)
- **regions:** AWS regions to target (optional)
- **additional_args:** Additional Pacu arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Pacu output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 180.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "pacu < /tmp/pacu_commands.txt" // Actual command executed
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/pacu", methods=["POST"])
def pacu():
    """Execute Pacu for AWS exploitation framework"""
    try:
        params = request.json
        session_name = params.get("session_name", "hexstrike_session")
        modules = params.get("modules", "")
        data_services = params.get("data_services", "")
        regions = params.get("regions", "")
        additional_args = params.get("additional_args", "")
        
        # Create Pacu command sequence
        commands = []
        commands.append(f"set_session {session_name}")
        
        if data_services:
            commands.append(f"data {data_services}")
        
        if regions:
            commands.append(f"set_regions {regions}")
        
        if modules:
            for module in modules.split(","):
                commands.append(f"run {module.strip()}")
        
        commands.append("exit")
        
        # Create command file
        command_file = "/tmp/pacu_commands.txt"
        with open(command_file, "w") as f:
            f.write("\n".join(commands))
        
        command = f"pacu < {command_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"☁️  Starting Pacu AWS exploitation")
        result = execute_command(command)
        
        # Cleanup
        try:
            os.remove(command_file)
        except:
            pass
        
        logger.info(f"📊 Pacu exploitation completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pacu endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
