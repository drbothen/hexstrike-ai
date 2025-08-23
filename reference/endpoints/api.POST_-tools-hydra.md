---
title: POST /api/tools/hydra
group: api
handler: hydra
module: __main__
line_range: [9224, 9274]
discovered_in_chunk: 9
---

# POST /api/tools/hydra

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute hydra with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with enhanced logging"""
```

## Purpose & Behavior
Hydra password attack endpoint providing:
- **Brute Force Attacks:** Execute password brute force attacks against various services
- **Dictionary Attacks:** Perform dictionary-based password attacks
- **Multi-service Support:** Support for multiple network services and protocols
- **Flexible Authentication:** Support for username/password files and individual credentials

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/hydra
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Required: Target IP/hostname
    "service": "string",                // Required: Service to attack (ssh, ftp, http, etc.)
    "username": "string",               // Optional: Single username
    "username_file": "string",          // Optional: Username wordlist file
    "password": "string",               // Optional: Single password
    "password_file": "string",          // Optional: Password wordlist file
    "additional_args": "string"         // Optional: Additional hydra arguments
}
```

### Parameters
- **target:** Target IP address or hostname (required)
- **service:** Network service to attack (required)
- **username:** Single username for attack (optional, mutually exclusive with username_file)
- **username_file:** Username wordlist file path (optional, mutually exclusive with username)
- **password:** Single password for attack (optional, mutually exclusive with password_file)
- **password_file:** Password wordlist file path (optional, mutually exclusive with password)
- **additional_args:** Additional hydra arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Hydra attack output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 120.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "hydra -t 4 -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 ssh"
}
```

### Error Responses

#### Missing Required Parameters (400 Bad Request)
```json
{
    "error": "Target and service parameters are required"
}
```

#### Missing Credentials (400 Bad Request)
```json
{
    "error": "Username/username_file and password/password_file are required"
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
1. **Base Command:** Start with "hydra -t 4" (4 threads)
2. **Username Configuration:** Add username or username file
3. **Password Configuration:** Add password or password file
4. **Additional Arguments:** Append additional arguments
5. **Target and Service:** Add target and service at the end

### Command Building Logic
```python
command = f"hydra -t 4"

if username:
    command += f" -l {username}"
elif username_file:
    command += f" -L {username_file}"

if password:
    command += f" -p {password}"
elif password_file:
    command += f" -P {password_file}"

if additional_args:
    command += f" {additional_args}"

command += f" {target} {service}"
```

### Parameter Validation

#### Required Parameters
```python
if not target or not service:
    return jsonify({"error": "Target and service parameters are required"}), 400
```

#### Credential Validation
```python
if not (username or username_file) or not (password or password_file):
    return jsonify({"error": "Username/username_file and password/password_file are required"}), 400
```

### Default Configuration
- **Thread Count:** 4 threads (-t 4) for balanced performance
- **Attack Mode:** Brute force or dictionary attack based on parameters
- **Service Support:** All services supported by Hydra

### Supported Services
- **SSH:** Secure Shell protocol
- **FTP:** File Transfer Protocol
- **HTTP:** HTTP basic authentication
- **HTTPS:** HTTPS basic authentication
- **Telnet:** Telnet protocol
- **SMB:** Server Message Block
- **RDP:** Remote Desktop Protocol
- **MySQL:** MySQL database
- **PostgreSQL:** PostgreSQL database
- **MSSQL:** Microsoft SQL Server

### Attack Types

#### Single Credential Attack
- **Username:** Single username (-l)
- **Password:** Single password (-p)
- **Use Case:** Test specific credential pairs

#### Dictionary Attack
- **Username File:** Username wordlist (-L)
- **Password File:** Password wordlist (-P)
- **Use Case:** Comprehensive credential testing

#### Hybrid Attack
- **Single Username:** Known username (-l)
- **Password File:** Password wordlist (-P)
- **Use Case:** Target specific user account

## AuthN/AuthZ
- **Network Access:** Requires network access to target systems
- **Attack Tool:** Password attack tool requiring authorized use

## Observability
- **Attack Logging:** "🔑 Starting Hydra attack: {target}:{service}"
- **Completion Logging:** "📊 Hydra attack completed for {target}"
- **Warning Logging:** "🎯 Hydra called without target or service parameter"
- **Credential Warning:** "🔑 Hydra called without username/password parameters"
- **Error Logging:** "💥 Error in hydra endpoint: {error}"

## Security Considerations
- **Password Attack Tool:** Hydra is a password cracking tool
- **Authorized Use:** Should only be used in authorized testing environments
- **Rate Limiting:** Consider rate limiting to prevent abuse
- **Legal Compliance:** Ensure compliance with applicable laws and regulations

## Use Cases and Applications

#### Penetration Testing
- **Password Testing:** Test password strength and policies
- **Authentication Testing:** Test authentication mechanisms
- **Security Assessment:** Assess password-based security controls

#### Security Assessment
- **Credential Validation:** Validate weak or default credentials
- **Password Policy Testing:** Test password policy effectiveness
- **Authentication Security:** Assess authentication security posture

#### Red Team Operations
- **Credential Attacks:** Simulate credential-based attacks
- **Lateral Movement:** Use discovered credentials for lateral movement
- **Access Validation:** Validate discovered credentials

## Testing & Validation
- Parameter validation accuracy testing
- Command construction verification
- Service support validation
- Credential configuration testing

## Code Reproduction
```python
# From line 9224: Complete Flask endpoint implementation
@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("🎯 Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("🔑 Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = execute_command(command)
        logger.info(f"📊 Hydra attack completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hydra endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
