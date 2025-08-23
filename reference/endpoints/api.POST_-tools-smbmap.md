---
title: POST /api/tools/smbmap
group: api
handler: smbmap
module: __main__
line_range: [9575, 9617]
discovered_in_chunk: 9
---

# POST /api/tools/smbmap

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute SMBMap for SMB share enumeration

## Complete Signature & Definition
```python
@app.route("/api/tools/smbmap", methods=["POST"])
def smbmap():
    """Execute SMBMap for SMB share enumeration with enhanced logging"""
```

## Purpose & Behavior
SMB share enumeration endpoint providing:
- **Share Discovery:** Discover and enumerate SMB shares
- **Permission Testing:** Test read/write permissions on shares
- **File Listing:** List files and directories in accessible shares
- **Enhanced Logging:** Detailed logging of enumeration progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/smbmap
- **Content-Type:** application/json

### Request Body
```json
{
    "host": "string",                 // Required: Target host
    "username": "string",             // Optional: Username for authentication
    "password": "string",             // Optional: Password for authentication
    "domain": "string",               // Optional: Domain for authentication
    "hash": "string",                 // Optional: Hash for authentication
    "share": "string",                // Optional: Specific share to enumerate
    "recursive": boolean,             // Optional: Recursive enumeration (default: false)
    "download": "string",             // Optional: File to download
    "upload": "string",               // Optional: File to upload
    "additional_args": "string"       // Optional: Additional smbmap arguments
}
```

### Parameters
- **host:** Target host (required) - IP address or hostname
- **username:** Username for authentication (optional)
- **password:** Password for authentication (optional)
- **domain:** Domain for authentication (optional)
- **hash:** Hash for authentication (optional)
- **share:** Specific share to enumerate (optional)
- **recursive:** Recursive enumeration flag (optional, default: false)
- **download:** File to download (optional)
- **upload:** File to upload (optional)
- **additional_args:** Additional smbmap arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "smbmap -H 192.168.1.100 -u admin -p password123",
    "enumeration_results": {
        "host": "192.168.1.100",
        "shares": [
            {
                "name": "ADMIN$",
                "permissions": "READ, WRITE",
                "type": "Disk",
                "comment": "Remote Admin"
            },
            {
                "name": "C$",
                "permissions": "READ, WRITE",
                "type": "Disk",
                "comment": "Default share"
            }
        ],
        "accessible_shares": 2,
        "total_shares": 2,
        "files": [
            {
                "share": "C$",
                "path": "Users/admin/Desktop/flag.txt",
                "size": 1024,
                "permissions": "READ"
            }
        ]
    },
    "raw_output": "[+] IP: 192.168.1.100:445\tName: unknown\n[+] Finding open SMB ports....",
    "execution_time": 15.7,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Host (400 Bad Request)
```json
{
    "error": "Host parameter is required"
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
host = params.get("host", "")
username = params.get("username", "")
password = params.get("password", "")
domain = params.get("domain", "")
hash_value = params.get("hash", "")
share = params.get("share", "")
recursive = params.get("recursive", False)
download = params.get("download", "")
upload = params.get("upload", "")
additional_args = params.get("additional_args", "")

if not host:
    return jsonify({"error": "Host parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["smbmap", "-H", host]

# Authentication
if username:
    command.extend(["-u", username])
if password:
    command.extend(["-p", password])
if domain:
    command.extend(["-d", domain])
if hash_value:
    command.extend(["--hash", hash_value])

# Share enumeration
if share:
    command.extend(["-s", share])

# Recursive enumeration
if recursive:
    command.append("-R")

# File operations
if download:
    command.extend(["--download", download])
if upload:
    command.extend(["--upload", upload])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** SMBMap execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing host
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure host is valid and authorized for enumeration
- **Credential Security:** Secure handling of authentication credentials
- **Responsible Use:** Emphasize responsible use of SMB enumeration capabilities

## Use Cases and Applications

#### SMB Security Assessment
- **Share Discovery:** Discover available SMB shares
- **Permission Testing:** Test share permissions and access controls
- **File Enumeration:** Enumerate files and directories in shares

#### Penetration Testing
- **Lateral Movement:** Identify potential lateral movement paths
- **Data Discovery:** Discover sensitive data in SMB shares
- **Access Verification:** Verify access to network resources

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/smbmap", methods=["POST"])
def smbmap():
    """Execute SMBMap for SMB share enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 SMBMap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"smbmap -H {target}"
        
        if username:
            command += f" -u {username}"
            
        if password:
            command += f" -p {password}"
            
        if domain:
            command += f" -d {domain}"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting SMBMap: {target}")
        result = execute_command(command)
        logger.info(f"📊 SMBMap completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in smbmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
