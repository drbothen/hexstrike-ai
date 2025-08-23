---
title: POST /api/tools/enum4linux-ng
group: api
handler: enum4linux_ng
module: __main__
line_range: [9790, 9843]
discovered_in_chunk: 10
---

# POST /api/tools/enum4linux-ng

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/enum4linux-ng", methods=["POST"])
def enum4linux_ng():
    """Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging"""
```

## Purpose & Behavior
Advanced SMB enumeration endpoint providing:
- **Enhanced SMB Enumeration:** Execute Enum4linux-ng for comprehensive SMB/NetBIOS enumeration
- **Configurable Authentication:** Support for username, password, and domain authentication
- **Selective Enumeration:** Configurable enumeration of shares, users, groups, and policies
- **Advanced Features:** Next-generation enum4linux with improved capabilities

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/enum4linux-ng
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Required: Target IP/hostname
    "username": "string",               // Optional: Username for authentication
    "password": "string",               // Optional: Password for authentication
    "domain": "string",                 // Optional: Domain for authentication
    "shares": boolean,                  // Optional: Enumerate shares (default: true)
    "users": boolean,                   // Optional: Enumerate users (default: true)
    "groups": boolean,                  // Optional: Enumerate groups (default: true)
    "policy": boolean,                  // Optional: Enumerate policies (default: true)
    "additional_args": "string"         // Optional: Additional enum4linux-ng arguments
}
```

### Parameters
- **target:** Target IP address or hostname (required)
- **username:** Username for SMB authentication (optional)
- **password:** Password for SMB authentication (optional)
- **domain:** Domain for SMB authentication (optional)
- **shares:** Enable share enumeration (optional, default: true)
- **users:** Enable user enumeration (optional, default: true)
- **groups:** Enable group enumeration (optional, default: true)
- **policy:** Enable policy enumeration (optional, default: true)
- **additional_args:** Additional enum4linux-ng arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Enum4linux-ng enumeration output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 60.5,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "enum4linux-ng 192.168.1.1 -u admin -p password -A S,U,G,P"
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

### Command Construction Process
1. **Base Command:** Start with "enum4linux-ng {target}"
2. **Authentication Configuration:** Add username, password, and domain if provided
3. **Enumeration Options:** Configure selective enumeration based on parameters
4. **Additional Arguments:** Append additional arguments

### Authentication Configuration
```python
if username:
    command += f" -u {username}"

if password:
    command += f" -p {password}"

if domain:
    command += f" -d {domain}"
```

### Selective Enumeration Logic
```python
enum_options = []
if shares:
    enum_options.append("S")
if users:
    enum_options.append("U")
if groups:
    enum_options.append("G")
if policy:
    enum_options.append("P")

if enum_options:
    command += f" -A {','.join(enum_options)}"
```

### Enumeration Categories
- **S (Shares):** SMB share enumeration
- **U (Users):** User account enumeration
- **G (Groups):** Group enumeration
- **P (Policy):** Password policy enumeration

### Default Configuration
- **All Enumeration Enabled:** shares, users, groups, policy all default to true
- **Comprehensive Enumeration:** -A flag with all categories by default
- **Anonymous Access:** No authentication required by default

### Enum4linux-ng Features
- **Next-generation Tool:** Improved version of classic enum4linux
- **Enhanced Performance:** Better performance and reliability
- **Modern Output:** Structured and improved output formatting
- **Extended Capabilities:** Additional enumeration capabilities

## AuthN/AuthZ
- **SMB Access:** Requires network access to SMB services
- **Authentication:** Optional SMB authentication with credentials

## Observability
- **Enumeration Logging:** "🔍 Starting Enum4linux-ng: {target}"
- **Completion Logging:** "📊 Enum4linux-ng completed for {target}"
- **Warning Logging:** "🎯 Enum4linux-ng called without target parameter"
- **Error Logging:** "💥 Error in enum4linux-ng endpoint: {error}"

## Use Cases and Applications

#### SMB Enumeration
- **Share Discovery:** Discover and enumerate SMB shares
- **User Enumeration:** Enumerate domain and local users
- **Group Enumeration:** Discover user groups and memberships
- **Policy Analysis:** Analyze password and security policies

#### Penetration Testing
- **Initial Enumeration:** Initial SMB/NetBIOS enumeration phase
- **Information Gathering:** Gather information about Windows environments
- **Attack Planning:** Plan attacks based on enumerated information

#### Security Assessment
- **SMB Security Assessment:** Assess SMB service security
- **Configuration Review:** Review SMB security configurations
- **Access Control Analysis:** Analyze SMB access controls

## Testing & Validation
- Target specification validation
- Authentication configuration testing
- Enumeration option functionality verification
- SMB service access testing

## Code Reproduction
Complete Flask endpoint implementation for Enum4linux-ng advanced SMB enumeration with configurable authentication, selective enumeration options, and comprehensive SMB/NetBIOS information gathering. Essential for Windows environment enumeration and security assessment workflows.
