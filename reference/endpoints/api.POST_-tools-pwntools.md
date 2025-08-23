---
title: POST /api/tools/pwntools
group: api
handler: pwntools
module: __main__
line_range: [10425, 10498]
discovered_in_chunk: 10
---

# POST /api/tools/pwntools

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Pwntools for exploit development and automation

## Complete Signature & Definition
```python
@app.route("/api/tools/pwntools", methods=["POST"])
def pwntools():
    """Execute Pwntools for exploit development and automation"""
```

## Purpose & Behavior
Exploit development and automation endpoint providing:
- **Exploit Development:** Execute Pwntools for comprehensive exploit development
- **Script Execution:** Support for custom Pwntools scripts and templates
- **Target Configuration:** Support for local and remote target configurations
- **Automation Framework:** Automated exploit development and testing

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/pwntools
- **Content-Type:** application/json

### Request Body
```json
{
    "script_content": "string",         // Optional: Custom Pwntools script content
    "target_binary": "string",          // Optional: Path to target binary
    "target_host": "string",            // Optional: Remote target hostname
    "target_port": 0,                   // Optional: Remote target port
    "exploit_type": "string",           // Optional: Exploit type (default: "local")
    "additional_args": "string"         // Optional: Additional arguments
}
```

### Parameters
- **script_content:** Custom Pwntools script content (optional)
- **target_binary:** Path to target binary for local exploitation (optional)
- **target_host:** Remote target hostname (optional)
- **target_port:** Remote target port (optional)
- **exploit_type:** Type of exploit - "local", "remote", "format_string", "rop" (optional, default: "local")
- **additional_args:** Additional script arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Pwntools script output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 45.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "python3 /tmp/pwntools_exploit.py"
}
```

### Error Responses

#### Missing Parameters (400 Bad Request)
```json
{
    "error": "Script content or target binary is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Script Generation Process
1. **Custom Script:** Use provided script content if available
2. **Template Generation:** Generate basic exploit template if no script provided
3. **Target Configuration:** Configure local or remote targets
4. **Script Execution:** Execute Python script with Pwntools

### Custom Script Handling
```python
if script_content:
    with open(script_file, "w") as f:
        f.write(script_content)
```

### Template Generation
```python
template = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
```

### File Cleanup
```python
try:
    os.remove(script_file)
except:
    pass
```

### Exploit Types
- **local:** Local binary exploitation
- **remote:** Remote service exploitation
- **format_string:** Format string vulnerability exploitation
- **rop:** Return-oriented programming exploitation

### Pwntools Features
- **Binary Exploitation:** Comprehensive binary exploitation framework
- **Protocol Support:** Support for various network protocols
- **Shellcode Generation:** Automatic shellcode generation
- **ROP Chain Building:** Automated ROP chain construction

### Target Configuration
- **Local Targets:** Process spawning and interaction
- **Remote Targets:** Network connection and communication
- **Hybrid Targets:** Combined local and remote exploitation

## AuthN/AuthZ
- **File System Access:** Requires access to target binaries
- **Network Access:** May require network access for remote targets

## Observability
- **Exploit Logging:** "🔧 Starting Pwntools exploit: {exploit_type}"
- **Completion Logging:** "📊 Pwntools exploit completed"
- **Warning Logging:** "🔧 Pwntools called without script content or target binary"
- **Error Logging:** "💥 Error in pwntools endpoint: {error}"

## Use Cases and Applications

#### Exploit Development
- **Binary Exploitation:** Develop exploits for binary vulnerabilities
- **Remote Exploitation:** Develop exploits for remote services
- **Automation:** Automate exploit development and testing

#### CTF Competitions
- **Challenge Solving:** Solve CTF binary exploitation challenges
- **Script Development:** Develop reusable exploitation scripts
- **Team Collaboration:** Share and collaborate on exploit development

#### Security Research
- **Vulnerability Research:** Research and develop proof-of-concept exploits
- **Exploit Testing:** Test and validate exploit reliability
- **Security Assessment:** Assess exploitability of discovered vulnerabilities

## Testing & Validation
- Script content validation
- Target configuration testing
- Template generation verification
- Exploit execution functionality testing

## Code Reproduction
```python
# From line 10425: Complete Flask endpoint implementation
@app.route("/api/tools/pwntools", methods=["POST"])
def pwntools():
    """Execute Pwntools for exploit development and automation"""
    try:
        params = request.json
        script_content = params.get("script_content", "")
        target_binary = params.get("target_binary", "")
        target_host = params.get("target_host", "")
        target_port = params.get("target_port", 0)
        exploit_type = params.get("exploit_type", "local")  # local, remote, format_string, rop
        additional_args = params.get("additional_args", "")
        
        if not script_content and not target_binary:
            logger.warning("🔧 Pwntools called without script content or target binary")
            return jsonify({"error": "Script content or target binary is required"}), 400
        
        # Create temporary script file
        script_file = f"/tmp/pwntools_script_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
        
        if script_content:
            with open(script_file, 'w') as f:
                f.write(script_content)
        else:
            # Generate basic exploit template
            template = generate_pwntools_template(target_binary, exploit_type, target_host, target_port)
            with open(script_file, 'w') as f:
                f.write(template)
        
        command = f"python3 {script_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting Pwntools exploit: {exploit_type}")
        result = execute_command(command)
        logger.info(f"📊 Pwntools exploit completed")
        
        # Clean up temporary file
        os.remove(script_file)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pwntools endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
