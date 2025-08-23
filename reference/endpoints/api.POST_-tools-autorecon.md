---
title: POST /api/tools/autorecon
group: api
handler: autorecon
module: __main__
line_range: [9754, 9789]
discovered_in_chunk: 9
---

# POST /api/tools/autorecon

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute AutoRecon for comprehensive automated reconnaissance

## Complete Signature & Definition
```python
@app.route("/api/tools/autorecon", methods=["POST"])
def autorecon():
    """Execute AutoRecon for comprehensive automated reconnaissance"""
```

## Purpose & Behavior
Comprehensive automated reconnaissance endpoint providing:
- **Multi-Stage Reconnaissance:** Automated multi-stage reconnaissance workflow
- **Service Enumeration:** Comprehensive service enumeration and analysis
- **Vulnerability Detection:** Automated vulnerability detection and analysis
- **Enhanced Logging:** Detailed logging of reconnaissance progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/autorecon
- **Content-Type:** application/json

### Request Body
```json
{
    "targets": ["string"],            // Required: Target hosts or IP addresses
    "output_dir": "string",           // Optional: Output directory (default: ./results)
    "port_scans": "string",           // Optional: Port scan types (default: top-ports)
    "service_scans": "string",        // Optional: Service scan types (default: default)
    "heartbeat": integer,             // Optional: Heartbeat interval (default: 60)
    "timeout": integer,               // Optional: Global timeout (default: 3600)
    "concurrent_targets": integer,    // Optional: Concurrent targets (default: 5)
    "concurrent_scans": integer,      // Optional: Concurrent scans per target (default: 10)
    "profile": "string",              // Optional: Scan profile (default: default)
    "additional_args": "string"       // Optional: Additional autorecon arguments
}
```

### Parameters
- **targets:** Target hosts or IP addresses (required) - ["192.168.1.100", "example.com"]
- **output_dir:** Output directory (optional, default: "./results")
- **port_scans:** Port scan types (optional) - "top-ports", "full", "quick"
- **service_scans:** Service scan types (optional) - "default", "safe", "aggressive"
- **heartbeat:** Heartbeat interval in seconds (optional, default: 60)
- **timeout:** Global timeout in seconds (optional, default: 3600)
- **concurrent_targets:** Number of concurrent targets (optional, default: 5)
- **concurrent_scans:** Number of concurrent scans per target (optional, default: 10)
- **profile:** Scan profile (optional) - "default", "quick", "full"
- **additional_args:** Additional autorecon arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "autorecon 192.168.1.100 --output ./results",
    "reconnaissance_results": {
        "targets": ["192.168.1.100"],
        "output_directory": "./results",
        "scan_summary": {
            "total_targets": 1,
            "completed_targets": 1,
            "failed_targets": 0,
            "total_services": 5,
            "vulnerable_services": 2
        },
        "target_results": [
            {
                "target": "192.168.1.100",
                "status": "completed",
                "open_ports": [22, 80, 443, 3389, 5985],
                "services": [
                    {
                        "port": 80,
                        "service": "http",
                        "version": "Apache 2.4.41",
                        "vulnerabilities": ["CVE-2021-41773"]
                    }
                ],
                "output_files": [
                    "./results/192.168.1.100/scans/tcp_80_http_feroxbuster.txt",
                    "./results/192.168.1.100/scans/tcp_80_http_nikto.txt"
                ]
            }
        ]
    },
    "raw_output": "[*] Scanning target 192.168.1.100...",
    "execution_time": 1800.5,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Targets (400 Bad Request)
```json
{
    "error": "Targets parameter is required"
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
targets = params.get("targets", [])
output_dir = params.get("output_dir", "./results")
port_scans = params.get("port_scans", "top-ports")
service_scans = params.get("service_scans", "default")
heartbeat = params.get("heartbeat", 60)
timeout = params.get("timeout", 3600)
concurrent_targets = params.get("concurrent_targets", 5)
concurrent_scans = params.get("concurrent_scans", 10)
profile = params.get("profile", "default")
additional_args = params.get("additional_args", "")

if not targets:
    return jsonify({"error": "Targets parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["autorecon"]

# Targets
command.extend(targets)

# Output directory
command.extend(["--output", output_dir])

# Port scans
if port_scans != "top-ports":
    command.extend(["--port-scans", port_scans])

# Service scans
if service_scans != "default":
    command.extend(["--service-scans", service_scans])

# Heartbeat
if heartbeat != 60:
    command.extend(["--heartbeat", str(heartbeat)])

# Timeout
if timeout != 3600:
    command.extend(["--timeout", str(timeout)])

# Concurrent targets
if concurrent_targets != 5:
    command.extend(["--concurrent-targets", str(concurrent_targets)])

# Concurrent scans
if concurrent_scans != 10:
    command.extend(["--concurrent-scans", str(concurrent_scans)])

# Profile
if profile != "default":
    command.extend(["--profile", profile])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** AutoRecon execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing targets
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure targets are valid and authorized for reconnaissance
- **Resource Management:** Manage system resources during intensive reconnaissance
- **Responsible Use:** Emphasize responsible use of automated reconnaissance capabilities

## Use Cases and Applications

#### Comprehensive Reconnaissance
- **Automated Enumeration:** Automated enumeration of target systems
- **Service Discovery:** Comprehensive service discovery and analysis
- **Vulnerability Assessment:** Automated vulnerability assessment

#### Penetration Testing
- **Initial Reconnaissance:** Initial reconnaissance phase of penetration testing
- **Attack Surface Mapping:** Comprehensive attack surface mapping
- **Intelligence Gathering:** Gather intelligence about target systems

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/autorecon", methods=["POST"])
def autorecon():
    """Execute AutoRecon for comprehensive automated reconnaissance"""
    try:
        params = request.json
        target = params.get("target", "")
        output_dir = params.get("output_dir", "/tmp/autorecon")
        port_scans = params.get("port_scans", "top-100-ports")
        service_scans = params.get("service_scans", "default")
        heartbeat = params.get("heartbeat", 60)
        timeout = params.get("timeout", 300)
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 AutoRecon called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400
        
        command = f"autorecon {target} -o {output_dir} --heartbeat {heartbeat} --timeout {timeout}"
        
        if port_scans != "default":
            command += f" --port-scans {port_scans}"
        
        if service_scans != "default":
            command += f" --service-scans {service_scans}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔄 Starting AutoRecon: {target}")
        result = execute_command(command)
        logger.info(f"📊 AutoRecon completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in autorecon endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
