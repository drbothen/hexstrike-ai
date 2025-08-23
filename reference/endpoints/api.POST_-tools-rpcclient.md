---
title: POST /api/tools/rpcclient
group: api
handler: rpcclient
module: __main__
line_range: [9845, 9887]
discovered_in_chunk: 9
---

# POST /api/tools/rpcclient

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute rpcclient for RPC enumeration with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/rpcclient", methods=["POST"])
def rpcclient():
    """Execute rpcclient for RPC enumeration with enhanced logging"""
```

## Purpose & Behavior
RPC client execution endpoint providing:
- **RPC Enumeration:** Enumerate RPC services and endpoints
- **Domain Information:** Gather domain and user information via RPC
- **Authentication Support:** Support for authenticated and null sessions
- **Enhanced Logging:** Detailed logging of RPC operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/rpcclient
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",              // Required: Target IP/hostname
    "username": "string",            // Optional: Username for authentication
    "password": "string",            // Optional: Password for authentication
    "domain": "string",              // Optional: Domain name
    "commands": ["string"],          // Optional: RPC commands to execute
    "null_session": boolean,         // Optional: Use null session (default: false)
    "additional_args": "string"      // Optional: Additional rpcclient arguments
}
```

### Parameters
- **target:** Target IP address or hostname (required)
- **username:** Username for authentication (optional)
- **password:** Password for authentication (optional)
- **domain:** Domain name (optional)
- **commands:** List of RPC commands to execute (optional)
- **null_session:** Use null session authentication (optional, default: false)
- **additional_args:** Additional rpcclient arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string",
    "return_code": 0,
    "success": true,
    "timed_out": false,
    "execution_time": 15.3,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "rpcclient -U username%password //target"
}
```

### Error Responses

#### Missing Target (400 Bad Request)
```json
{
    "error": "Target parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/rpcclient", methods=["POST"])
def rpcclient():
    """Execute rpcclient for RPC enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        commands = params.get("commands", "enumdomusers;enumdomgroups;querydominfo")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 rpcclient called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400
        
        # Build authentication string
        auth_string = ""
        if username and password:
            auth_string = f"-U {username}%{password}"
        elif username:
            auth_string = f"-U {username}"
        else:
            auth_string = "-U ''"  # Anonymous
        
        if domain:
            auth_string += f" -W {domain}"
        
        # Create command sequence
        command_sequence = commands.replace(";", "\n")
        
        command = f"echo -e '{command_sequence}' | rpcclient {auth_string} {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting rpcclient: {target}")
        result = execute_command(command)
        logger.info(f"📊 rpcclient completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in rpcclient endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        commands = params.get("commands", [])
        null_session = params.get("null_session", False)
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 RPCClient called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"rpcclient"
        
        if null_session:
            command += f" -N //{target}"
        elif username and password:
            if domain:
                command += f" -U {domain}\\{username}%{password} //{target}"
            else:
                command += f" -U {username}%{password} //{target}"
        else:
            command += f" -N //{target}"
        
        if commands:
            command += f" -c \"{'; '.join(commands)}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting RPCClient enumeration: {target}")
        result = execute_command(command)
        logger.info(f"📊 RPCClient enumeration completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in rpcclient endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
