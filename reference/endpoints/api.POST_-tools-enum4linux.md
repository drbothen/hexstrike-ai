---
title: POST /api/tools/enum4linux
group: api
handler: enum4linux
module: __main__
line_range: [9344, 9369]
discovered_in_chunk: 9
---

# POST /api/tools/enum4linux

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute enum4linux with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with enhanced logging"""
```

## Purpose & Behavior
SMB enumeration endpoint providing:
- **SMB Enumeration:** Enumerate SMB shares and services
- **User Enumeration:** Enumerate users on target systems
- **Share Discovery:** Discover available SMB shares
- **Enhanced Logging:** Detailed logging of enumeration progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/enum4linux
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",               // Required: Target to enumerate
    "username": "string",             // Optional: Username for authentication
    "password": "string",             // Optional: Password for authentication
    "all": boolean,                   // Optional: Perform all enumeration (default: true)
    "users": boolean,                 // Optional: Enumerate users (default: false)
    "shares": boolean,                // Optional: Enumerate shares (default: false)
    "groups": boolean,                // Optional: Enumerate groups (default: false)
    "additional_args": "string"       // Optional: Additional enum4linux arguments
}
```

### Parameters
- **target:** Target to enumerate (required) - IP address or hostname
- **username:** Username for authentication (optional)
- **password:** Password for authentication (optional)
- **all:** Perform all enumeration (optional, default: true)
- **users:** Enumerate users (optional, default: false)
- **shares:** Enumerate shares (optional, default: false)
- **groups:** Enumerate groups (optional, default: false)
- **additional_args:** Additional enum4linux arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "enum4linux -a 192.168.1.100",
    "enumeration_results": {
        "target": "192.168.1.100",
        "users": [
            {
                "username": "administrator",
                "uid": "500",
                "description": "Built-in account for administering the computer/domain"
            }
        ],
        "shares": [
            {
                "name": "ADMIN$",
                "type": "Disk",
                "comment": "Remote Admin"
            }
        ],
        "groups": [
            {
                "name": "Administrators",
                "description": "Administrators have complete and unrestricted access"
            }
        ]
    },
    "raw_output": "Starting enum4linux v0.8.9...",
    "execution_time": 45.2,
    "timestamp": "2024-01-01T12:00:00Z"
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

## Implementation Details

### Parameter Validation
```python
params = request.json
target = params.get("target", "")
username = params.get("username", "")
password = params.get("password", "")
all_enum = params.get("all", True)
users = params.get("users", False)
shares = params.get("shares", False)
groups = params.get("groups", False)
additional_args = params.get("additional_args", "")

if not target:
    return jsonify({"error": "Target parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["enum4linux"]

# Authentication
if username:
    command.extend(["-u", username])
if password:
    command.extend(["-p", password])

# Enumeration options
if all_enum:
    command.append("-a")
else:
    if users:
        command.append("-U")
    if shares:
        command.append("-S")
    if groups:
        command.append("-G")

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Target
command.append(target)

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Enum4linux execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing target
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for enumeration
- **Credential Security:** Secure handling of authentication credentials
- **Responsible Use:** Emphasize responsible use of enumeration capabilities

## Use Cases and Applications

#### Network Enumeration
- **SMB Service Discovery:** Discover SMB services on target systems
- **User Enumeration:** Enumerate users for security assessment
- **Share Discovery:** Discover available network shares

#### Penetration Testing
- **Information Gathering:** Gather information about target systems
- **Attack Surface Mapping:** Map the attack surface of target networks
- **Credential Discovery:** Discover potential attack vectors

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("🎯 Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        logger.info(f"🔍 Starting Enum4linux: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in enum4linux endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
