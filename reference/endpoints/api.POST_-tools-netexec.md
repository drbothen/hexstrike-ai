---
title: POST /api/tools/netexec
group: api
handler: netexec
module: __main__
line_range: [9413, 9458]
discovered_in_chunk: 9
---

# POST /api/tools/netexec

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute NetExec (formerly CrackMapExec) with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/netexec", methods=["POST"])
def netexec():
    """Execute NetExec (formerly CrackMapExec) with enhanced logging"""
```

## Purpose & Behavior
Network execution and credential testing endpoint providing:
- **Network Credential Testing:** Test credentials across network services
- **Service Enumeration:** Enumerate network services and protocols
- **Command Execution:** Execute commands on remote systems
- **Enhanced Logging:** Detailed logging of execution progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/netexec
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",               // Required: Target to test
    "protocol": "string",             // Required: Protocol to use (smb, ssh, winrm, etc.)
    "username": "string",             // Optional: Username for authentication
    "password": "string",             // Optional: Password for authentication
    "hash": "string",                 // Optional: Hash for authentication
    "domain": "string",               // Optional: Domain for authentication
    "command": "string",              // Optional: Command to execute
    "module": "string",               // Optional: Module to execute
    "additional_args": "string"       // Optional: Additional netexec arguments
}
```

### Parameters
- **target:** Target to test (required) - IP address, hostname, or CIDR range
- **protocol:** Protocol to use (required) - smb, ssh, winrm, ldap, etc.
- **username:** Username for authentication (optional)
- **password:** Password for authentication (optional)
- **hash:** Hash for authentication (optional)
- **domain:** Domain for authentication (optional)
- **command:** Command to execute (optional)
- **module:** Module to execute (optional)
- **additional_args:** Additional netexec arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "netexec smb 192.168.1.100 -u admin -p password123",
    "execution_results": {
        "target": "192.168.1.100",
        "protocol": "smb",
        "authentication": {
            "username": "admin",
            "domain": "WORKGROUP",
            "status": "success"
        },
        "services": [
            {
                "port": 445,
                "service": "microsoft-ds",
                "version": "Windows Server 2019"
            }
        ],
        "shares": [
            {
                "name": "C$",
                "permissions": "READ,WRITE"
            }
        ],
        "command_output": "Directory of C:\\Users\\admin\\Desktop"
    },
    "raw_output": "SMB         192.168.1.100   445    DC01             [*] Windows Server 2019...",
    "execution_time": 15.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Parameters (400 Bad Request)
```json
{
    "error": "Missing required parameters: target, protocol"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
target = params.get("target", "")
protocol = params.get("protocol", "")
username = params.get("username", "")
password = params.get("password", "")
hash_value = params.get("hash", "")
domain = params.get("domain", "")
command = params.get("command", "")
module = params.get("module", "")
additional_args = params.get("additional_args", "")

# Validate required parameters
missing_params = []
if not target:
    missing_params.append("target")
if not protocol:
    missing_params.append("protocol")
if missing_params:
    return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
```

### Command Construction
```python
# Base command
command_list = ["netexec", protocol, target]

# Authentication
if username:
    command_list.extend(["-u", username])
if password:
    command_list.extend(["-p", password])
if hash_value:
    command_list.extend(["-H", hash_value])
if domain:
    command_list.extend(["-d", domain])

# Command execution
if command:
    command_list.extend(["-x", command])

# Module execution
if module:
    command_list.extend(["-M", module])

# Additional arguments
if additional_args:
    command_list.extend(additional_args.split())

# Convert to string
command_str = " ".join(command_list)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** NetExec execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing required parameters
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for testing
- **Credential Security:** Secure handling of authentication credentials
- **Command Validation:** Validate commands for security
- **Responsible Use:** Emphasize responsible use of network execution capabilities

## Use Cases and Applications

#### Network Security Testing
- **Credential Testing:** Test credentials across network services
- **Service Enumeration:** Enumerate network services and protocols
- **Access Verification:** Verify access to network resources

#### Penetration Testing
- **Lateral Movement:** Test lateral movement capabilities
- **Privilege Escalation:** Test privilege escalation opportunities
- **Command Execution:** Execute commands on remote systems

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/netexec", methods=["POST"])
def netexec():
    """Execute NetExec (formerly CrackMapExec) with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        protocol = params.get("protocol", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_value = params.get("hash", "")
        domain = params.get("domain", "")
        command = params.get("command", "")
        module = params.get("module", "")
        additional_args = params.get("additional_args", "")
        
        # Validate required parameters
        missing_params = []
        if not target:
            missing_params.append("target")
        if not protocol:
            missing_params.append("protocol")
        if missing_params:
            return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
        
        # Base command
        command_list = ["netexec", protocol, target]
        
        # Authentication
        if username:
            command_list.extend(["-u", username])
        if password:
            command_list.extend(["-p", password])
        if hash_value:
            command_list.extend(["-H", hash_value])
        if domain:
            command_list.extend(["-d", domain])
        
        # Command execution
        if command:
            command_list.extend(["-x", command])
        
        # Module execution
        if module:
            command_list.extend(["-M", module])
        
        # Additional arguments
        if additional_args:
            command_list.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command_list)
        
        logger.info(f"🔍 Executing netexec: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for execution results
        execution_results = parse_netexec_output(result["output"])
        
        logger.info(f"🔍 NetExec completed in {execution_time:.2f}s")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "execution_results": execution_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in netexec endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
