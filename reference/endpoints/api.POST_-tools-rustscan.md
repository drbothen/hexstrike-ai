---
title: POST /api/tools/rustscan
group: api
handler: rustscan
module: __main__
line_range: [9620, 9654]
discovered_in_chunk: 9
---

# POST /api/tools/rustscan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Rustscan for ultra-fast port scanning with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/rustscan", methods=["POST"])
def rustscan():
    """Execute Rustscan for ultra-fast port scanning with enhanced logging"""
```

## Purpose & Behavior
Ultra-fast port scanning endpoint providing:
- **High-Speed Port Scanning:** Execute Rustscan for extremely fast port discovery
- **Optimized Performance:** Configurable ulimit, batch size, and timeout settings
- **Script Integration:** Optional Nmap script execution for discovered ports
- **Enhanced Efficiency:** Rust-based implementation for maximum speed

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/rustscan
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Required: Target IP/hostname to scan
    "ports": "string",                  // Optional: Specific ports to scan
    "ulimit": 5000,                     // Optional: File descriptor limit (default: 5000)
    "batch_size": 4500,                 // Optional: Batch size (default: 4500)
    "timeout": 1500,                    // Optional: Timeout in milliseconds (default: 1500)
    "scripts": "string",                // Optional: Enable Nmap scripts
    "additional_args": "string"         // Optional: Additional rustscan arguments
}
```

### Parameters
- **target:** Target IP address or hostname to scan (required)
- **ports:** Specific ports to scan (optional)
- **ulimit:** File descriptor limit for performance (optional, default: 5000)
- **batch_size:** Batch size for scanning (optional, default: 4500)
- **timeout:** Timeout in milliseconds (optional, default: 1500)
- **scripts:** Enable Nmap script execution (optional)
- **additional_args:** Additional rustscan arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Rustscan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 15.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "rustscan -a 192.168.1.1 --ulimit 5000 -b 4500 -t 1500"
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
1. **Base Command:** Start with "rustscan -a {target}"
2. **Performance Configuration:** Add ulimit, batch size, and timeout
3. **Port Configuration:** Add specific ports if specified
4. **Script Integration:** Add Nmap script execution if enabled
5. **Additional Arguments:** Append additional arguments

### Command Building Logic
```python
command = f"rustscan -a {target} --ulimit {ulimit} -b {batch_size} -t {timeout}"

if ports:
    command += f" -p {ports}"

if scripts:
    command += f" -- -sC -sV"

if additional_args:
    command += f" {additional_args}"
```

### Performance Optimization

#### Default Performance Settings
- **ulimit:** 5000 file descriptors for high concurrency
- **batch_size:** 4500 for optimal batch processing
- **timeout:** 1500ms for balanced speed and accuracy

#### Script Integration
```python
if scripts:
    command += f" -- -sC -sV"
```

### Rustscan Features
- **Ultra-Fast Scanning:** Rust-based implementation for maximum speed
- **High Concurrency:** Support for thousands of concurrent connections
- **Nmap Integration:** Seamless integration with Nmap for detailed scanning
- **Adaptive Performance:** Configurable performance parameters

### Performance Parameters
- **ulimit:** File descriptor limit for concurrent connections
- **batch_size:** Number of ports to scan in each batch
- **timeout:** Connection timeout in milliseconds
- **concurrency:** Automatic concurrency optimization

## AuthN/AuthZ
- **Network Access:** Requires network access to target systems
- **Port Scanning Tool:** Network reconnaissance tool

## Observability
- **Scan Logging:** "⚡ Starting Rustscan: {target}"
- **Completion Logging:** "📊 Rustscan completed for {target}"
- **Warning Logging:** "🎯 Rustscan called without target parameter"
- **Error Logging:** "💥 Error in rustscan endpoint: {error}"

## Use Cases and Applications

#### Network Discovery
- **Fast Port Discovery:** Rapidly discover open ports on targets
- **Network Reconnaissance:** Initial network reconnaissance phase
- **Service Enumeration:** Quick service discovery and enumeration

#### Security Assessment
- **Attack Surface Analysis:** Analyze network attack surface
- **Port Scanning:** Comprehensive port scanning for security assessment
- **Performance Testing:** Test network scanning performance

## Testing & Validation
- Performance parameter configuration testing
- Target specification validation
- Script integration functionality verification
- Speed and accuracy benchmarking

## Code Reproduction
Complete Flask endpoint implementation for Rustscan ultra-fast port scanning with configurable performance parameters, Nmap script integration, and optimized scanning capabilities. Essential for high-speed network discovery and reconnaissance workflows.
