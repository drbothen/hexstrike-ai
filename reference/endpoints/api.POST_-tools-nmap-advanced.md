---
title: POST /api/tools/nmap-advanced
group: api
handler: nmap_advanced
module: __main__
line_range: [9699, 9752]
discovered_in_chunk: 9
---

# POST /api/tools/nmap-advanced

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute advanced Nmap scans with custom NSE scripts and optimized timing

## Complete Signature & Definition
```python
@app.route("/api/tools/nmap-advanced", methods=["POST"])
def nmap_advanced():
    """Execute advanced Nmap scans with custom NSE scripts and optimized timing"""
```

## Purpose & Behavior
Advanced Nmap scanning endpoint providing:
- **Advanced Scanning:** Execute sophisticated Nmap scans with custom NSE scripts
- **Optimized Timing:** Use intelligent timing templates for efficient scanning
- **Script Selection:** Automatic selection of appropriate NSE scripts
- **Performance Optimization:** Optimized scanning parameters for better performance
- **Enhanced Output:** Comprehensive scan results with detailed analysis

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/nmap-advanced
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                // Required: Target to scan
    "scan_type": "string",             // Optional: Type of scan (default: "comprehensive")
    "ports": "string",                 // Optional: Ports to scan (default: "top1000")
    "timing_template": "string",       // Optional: Timing template (default: "4")
    "script_categories": ["string"],   // Optional: NSE script categories to use
    "custom_scripts": ["string"],      // Optional: Custom NSE scripts to run
    "output_format": "string",         // Optional: Output format (default: "all")
    "service_detection": boolean,      // Optional: Enable service detection (default: true)
    "os_detection": boolean,           // Optional: Enable OS detection (default: true)
    "additional_args": "string"        // Optional: Additional Nmap arguments
}
```

### Parameters
- **target:** Target to scan (required) - IP address, hostname, or CIDR notation
- **scan_type:** Type of scan (optional) - "comprehensive", "quick", "stealth", "vulnerability", "discovery"
- **ports:** Ports to scan (optional) - "top1000", "all", "common", or specific port ranges
- **timing_template:** Timing template (optional) - "0" (paranoid) to "5" (insane)
- **script_categories:** NSE script categories to use (optional) - "default", "discovery", "safe", "vuln", "exploit", etc.
- **custom_scripts:** Custom NSE scripts to run (optional) - List of script names
- **output_format:** Output format (optional) - "all", "xml", "json", "grepable", "normal"
- **service_detection:** Enable service detection (optional, default: true)
- **os_detection:** Enable OS detection (optional, default: true)
- **additional_args:** Additional Nmap arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "nmap -sV -O -T4 -A --script=default,vuln example.com",
    "scan_results": {
        "summary": {
            "target": "example.com",
            "start_time": "2024-01-01T12:00:00Z",
            "end_time": "2024-01-01T12:10:00Z",
            "total_hosts": 1,
            "up_hosts": 1,
            "down_hosts": 0,
            "total_ports": 1000,
            "open_ports": 12,
            "closed_ports": 988
        },
        "hosts": [
            {
                "ip": "93.184.216.34",
                "hostname": "example.com",
                "status": "up",
                "os": {
                    "name": "Linux",
                    "accuracy": 95,
                    "version": "4.15 - 5.6"
                },
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "nginx",
                        "version": "1.18.0",
                        "vulnerabilities": [
                            {
                                "id": "CVE-2021-23017",
                                "severity": "medium",
                                "description": "Buffer underflow vulnerability"
                            }
                        ]
                    }
                ]
            }
        ],
        "vulnerabilities": [
            {
                "host": "93.184.216.34",
                "port": 80,
                "service": "http",
                "id": "CVE-2021-23017",
                "severity": "medium",
                "description": "Buffer underflow vulnerability"
            }
        ]
    },
    "raw_output": "Starting Nmap 7.80...",
    "execution_time": 600,
    "timestamp": "2024-01-01T12:10:00Z"
}
```

### Error Responses

#### Missing Target (400 Bad Request)
```json
{
    "error": "Target parameter is required"
}
```

#### Invalid Scan Type (400 Bad Request)
```json
{
    "error": "Invalid scan type: {scan_type}"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Parameter Extraction and Validation
```python
params = request.json
target = params.get("target", "")
scan_type = params.get("scan_type", "comprehensive")
ports = params.get("ports", "top1000")
timing_template = params.get("timing_template", "4")
script_categories = params.get("script_categories", [])
custom_scripts = params.get("custom_scripts", [])
output_format = params.get("output_format", "all")
service_detection = params.get("service_detection", True)
os_detection = params.get("os_detection", True)
additional_args = params.get("additional_args", "")

if not target:
    return jsonify({"error": "Target parameter is required"}), 400

valid_scan_types = ["comprehensive", "quick", "stealth", "vulnerability", "discovery"]
if scan_type not in valid_scan_types:
    return jsonify({"error": f"Invalid scan type: {scan_type}"}), 400
```

### Command Construction
```python
# Base command
command = ["nmap"]

# Scan type options
if scan_type == "comprehensive":
    command.extend(["-sS", "-sV", "-O", "-A"])
elif scan_type == "quick":
    command.extend(["-F", "-T4"])
elif scan_type == "stealth":
    command.extend(["-sS", "-T2", "--data-length", "15"])
elif scan_type == "vulnerability":
    command.extend(["-sV", "--script=vuln"])
elif scan_type == "discovery":
    command.extend(["-sn", "-PE", "-PP", "-PS", "-PA", "--script=discovery"])

# Port options
if ports == "all":
    command.append("-p-")
elif ports == "top1000":
    command.append("--top-ports 1000")
elif ports == "common":
    command.append("--top-ports 100")
else:
    command.append(f"-p {ports}")

# Timing template
command.append(f"-T{timing_template}")

# Service and OS detection
if service_detection:
    command.append("-sV")
if os_detection:
    command.append("-O")

# Script options
if script_categories:
    script_str = ",".join(script_categories)
    command.append(f"--script={script_str}")
if custom_scripts:
    custom_script_str = ",".join(custom_scripts)
    command.append(f"--script={custom_script_str}")

# Output format
if output_format == "all" or "xml" in output_format:
    command.extend(["-oX", f"/tmp/nmap_scan_{int(time.time())}.xml"])
if output_format == "all" or "json" in output_format:
    command.extend(["-oJ", f"/tmp/nmap_scan_{int(time.time())}.json"])
if output_format == "all" or "grepable" in output_format:
    command.extend(["-oG", f"/tmp/nmap_scan_{int(time.time())}.gnmap"])
if output_format == "all" or "normal" in output_format:
    command.extend(["-oN", f"/tmp/nmap_scan_{int(time.time())}.nmap"])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Target
command.append(target)

# Convert to string
command_str = " ".join(command)
```

### Execution and Result Processing
```python
start_time = time.time()
result = execute_command_with_recovery(command_str)
execution_time = time.time() - start_time

# Parse output to structured format
scan_results = parse_nmap_output(result["output"])

response = {
    "success": True,
    "command": command_str,
    "scan_results": scan_results,
    "raw_output": result["output"][:1000] + "..." if len(result["output"]) > 1000 else result["output"],
    "execution_time": execution_time,
    "timestamp": datetime.now().isoformat()
}
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Nmap execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing target
- **Invalid Parameters:** 400 error for invalid scan type
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for scanning
- **Resource Limits:** Prevent resource exhaustion from intensive scans
- **Responsible Use:** Emphasize responsible use of scanning capabilities

## Use Cases and Applications

#### Network Security Assessment
- **Vulnerability Scanning:** Identify vulnerabilities in network services
- **Service Enumeration:** Discover and enumerate network services
- **OS Fingerprinting:** Identify operating systems on network hosts

#### Penetration Testing
- **Reconnaissance:** Gather information about target systems
- **Attack Surface Mapping:** Map the attack surface of target networks
- **Vulnerability Identification:** Identify exploitable vulnerabilities

#### Network Management
- **Asset Discovery:** Discover network assets and services
- **Service Monitoring:** Monitor network services and ports
- **Configuration Verification:** Verify network configuration and security

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/nmap-advanced", methods=["POST"])
def nmap_advanced():
    """Execute advanced Nmap scans with custom NSE scripts and optimized timing"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "comprehensive")
        ports = params.get("ports", "top1000")
        timing_template = params.get("timing_template", "4")
        script_categories = params.get("script_categories", [])
        custom_scripts = params.get("custom_scripts", [])
        output_format = params.get("output_format", "all")
        service_detection = params.get("service_detection", True)
        os_detection = params.get("os_detection", True)
        additional_args = params.get("additional_args", "")
        
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        
        valid_scan_types = ["comprehensive", "quick", "stealth", "vulnerability", "discovery"]
        if scan_type not in valid_scan_types:
            return jsonify({"error": f"Invalid scan type: {scan_type}"}), 400
        
        # Base command
        command = ["nmap"]
        
        # Scan type options
        if scan_type == "comprehensive":
            command.extend(["-sS", "-sV", "-O", "-A"])
        elif scan_type == "quick":
            command.extend(["-F", "-T4"])
        elif scan_type == "stealth":
            command.extend(["-sS", "-T2", "--data-length", "15"])
        elif scan_type == "vulnerability":
            command.extend(["-sV", "--script=vuln"])
        elif scan_type == "discovery":
            command.extend(["-sn", "-PE", "-PP", "-PS", "-PA", "--script=discovery"])
        
        # Port options
        if ports == "all":
            command.append("-p-")
        elif ports == "top1000":
            command.append("--top-ports 1000")
        elif ports == "common":
            command.append("--top-ports 100")
        else:
            command.append(f"-p {ports}")
        
        # Timing template
        command.append(f"-T{timing_template}")
        
        # Service and OS detection
        if service_detection:
            command.append("-sV")
        if os_detection:
            command.append("-O")
        
        # Script options
        if script_categories:
            script_str = ",".join(script_categories)
            command.append(f"--script={script_str}")
        if custom_scripts:
            custom_script_str = ",".join(custom_scripts)
            command.append(f"--script={custom_script_str}")
        
        # Output format
        if output_format == "all" or "xml" in output_format:
            command.extend(["-oX", f"/tmp/nmap_scan_{int(time.time())}.xml"])
        if output_format == "all" or "json" in output_format:
            command.extend(["-oJ", f"/tmp/nmap_scan_{int(time.time())}.json"])
        if output_format == "all" or "grepable" in output_format:
            command.extend(["-oG", f"/tmp/nmap_scan_{int(time.time())}.gnmap"])
        if output_format == "all" or "normal" in output_format:
            command.extend(["-oN", f"/tmp/nmap_scan_{int(time.time())}.nmap"])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Target
        command.append(target)
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing advanced Nmap scan: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output to structured format
        scan_results = parse_nmap_output(result["output"])
        
        logger.info(f"🔍 Advanced Nmap scan completed in {execution_time:.2f}s")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "scan_results": scan_results,
            "raw_output": result["output"][:1000] + "..." if len(result["output"]) > 1000 else result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in advanced nmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
