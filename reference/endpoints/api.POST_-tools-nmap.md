---
title: POST /api/tools/nmap
group: api
handler: nmap
module: __main__
line_range: [8458, 8506]
discovered_in_chunk: 8
---

# POST /api/tools/nmap

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute nmap scan with enhanced logging, caching, and intelligent error handling

## Complete Signature & Definition
```python
@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with enhanced logging, caching, and intelligent error handling"""
```

## Purpose & Behavior
Nmap scanning endpoint providing:
- **Network Scanning:** Execute nmap for network discovery and port scanning
- **Intelligent Error Handling:** Optional recovery mechanisms for failed scans
- **Configurable Parameters:** Flexible scan types, port ranges, and additional arguments
- **Enhanced Logging:** Comprehensive logging of scan initiation and completion

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/nmap
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Required: Target IP/domain to scan
    "scan_type": "string",              // Optional: Nmap scan type (default: "-sCV")
    "ports": "string",                  // Optional: Port specification
    "additional_args": "string",        // Optional: Additional nmap arguments (default: "-T4 -Pn")
    "use_recovery": boolean             // Optional: Enable intelligent error handling (default: true)
}
```

### Parameters
- **target:** Target IP address or domain to scan (required)
- **scan_type:** Nmap scan type (optional, default: "-sCV")
- **ports:** Port specification (optional)
- **additional_args:** Additional nmap arguments (optional, default: "-T4 -Pn")
- **use_recovery:** Enable intelligent error handling (optional, default: true)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Nmap scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 45.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "nmap -sCV -T4 -Pn example.com" // Actual command executed
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
1. **Base Command:** Start with "nmap" and scan type
2. **Port Specification:** Add port range if provided
3. **Additional Arguments:** Append additional arguments
4. **Target Addition:** Add target at the end

### Command Building Logic
```python
command = f"nmap {scan_type}"

if ports:
    command += f" -p {ports}"

if additional_args:
    command += f" {additional_args}"

command += f" {target}"
```

### Default Configuration
- **Default Scan Type:** "-sCV" (Service/Version detection with default scripts)
- **Default Additional Args:** "-T4 -Pn" (Aggressive timing, no ping)
- **Recovery Enabled:** use_recovery defaults to true

### Intelligent Error Handling

#### Recovery Mode (use_recovery=true)
```python
tool_params = {
    "target": target,
    "scan_type": scan_type,
    "ports": ports,
    "additional_args": additional_args
}
result = execute_command_with_recovery("nmap", command, tool_params)
```

#### Standard Mode (use_recovery=false)
```python
result = execute_command(command)
```

### Parameter Validation
- **Target Validation:** Ensure target parameter is provided
- **Warning Logging:** Log warning for missing target parameter
- **Error Response:** Return 400 error for missing target

### Nmap Scan Types
- **-sCV:** Service/version detection with default scripts (default)
- **-sS:** SYN stealth scan
- **-sT:** TCP connect scan
- **-sU:** UDP scan
- **-sA:** ACK scan
- **Custom:** Any valid nmap scan type

### Port Specification Examples
- **Single Port:** "80"
- **Port Range:** "1-1000"
- **Multiple Ports:** "22,80,443"
- **Common Ports:** "1-65535"
- **Top Ports:** "--top-ports 1000"

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Network scanning access required

## Observability
- **Scan Logging:** "🔍 Starting Nmap scan: {target}"
- **Completion Logging:** "📊 Nmap scan completed for {target}"
- **Warning Logging:** "🎯 Nmap called without target parameter"
- **Error Logging:** "💥 Error in nmap endpoint: {error}"

## Security Considerations
- **Network Impact:** Nmap scans can be detected by network monitoring
- **Rate Limiting:** Consider rate limiting for scan frequency
- **Target Validation:** No apparent target validation beyond existence check

## Use Cases and Applications

#### Network Discovery
- **Host Discovery:** Discover active hosts on networks
- **Port Scanning:** Identify open ports and services
- **Service Detection:** Detect service versions and configurations

#### Security Assessment
- **Vulnerability Assessment:** Identify potential attack vectors
- **Network Mapping:** Map network topology and services
- **Compliance Scanning:** Verify security configurations

#### Penetration Testing
- **Reconnaissance:** Initial network reconnaissance phase
- **Service Enumeration:** Enumerate network services
- **Attack Surface Analysis:** Analyze potential attack surfaces

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Error handling behavior validation
- Recovery mechanism functionality testing

## Code Reproduction
Complete Flask endpoint implementation for nmap network scanning with intelligent error handling, configurable parameters, and comprehensive logging. Essential for network discovery and security assessment workflows.
