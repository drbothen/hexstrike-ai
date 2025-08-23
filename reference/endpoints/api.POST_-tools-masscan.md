---
title: POST /api/tools/masscan
group: api
handler: masscan
module: __main__
line_range: [9656, 9698]
discovered_in_chunk: 9
---

# POST /api/tools/masscan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Masscan for high-speed Internet-scale port scanning

## Complete Signature & Definition
```python
@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting"""
```

## Purpose & Behavior
High-speed port scanning endpoint providing:
- **Internet-Scale Scanning:** Scan large IP ranges at high speed
- **Intelligent Rate Limiting:** Automatic rate limiting to prevent network overload
- **TCP/UDP Support:** Support for both TCP and UDP port scanning
- **Enhanced Logging:** Detailed logging of scanning progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/masscan
- **Content-Type:** application/json

### Request Body
```json
{
    "targets": "string",              // Required: Target IP ranges or hosts
    "ports": "string",                // Required: Ports to scan
    "rate": integer,                  // Optional: Scan rate (default: 1000)
    "protocol": "string",             // Optional: Protocol (tcp/udp, default: tcp)
    "output_format": "string",        // Optional: Output format (default: list)
    "output_file": "string",          // Optional: Output file path
    "exclude": "string",              // Optional: IPs to exclude
    "interface": "string",            // Optional: Network interface to use
    "source_ip": "string",            // Optional: Source IP address
    "additional_args": "string"       // Optional: Additional masscan arguments
}
```

### Parameters
- **targets:** Target IP ranges or hosts (required) - "192.168.1.0/24", "10.0.0.1-10.0.0.100"
- **ports:** Ports to scan (required) - "80,443,8080", "1-1000", "22,80,443"
- **rate:** Scan rate in packets per second (optional, default: 1000)
- **protocol:** Protocol to scan (optional) - "tcp", "udp", default: "tcp"
- **output_format:** Output format (optional) - "list", "xml", "json", default: "list"
- **output_file:** Output file path (optional)
- **exclude:** IPs to exclude from scan (optional)
- **interface:** Network interface to use (optional)
- **source_ip:** Source IP address (optional)
- **additional_args:** Additional masscan arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "masscan 192.168.1.0/24 -p80,443 --rate=1000",
    "scan_results": {
        "targets_scanned": "192.168.1.0/24",
        "ports_scanned": "80,443",
        "scan_rate": 1000,
        "open_ports": [
            {
                "ip": "192.168.1.100",
                "port": 80,
                "protocol": "tcp",
                "state": "open"
            },
            {
                "ip": "192.168.1.100",
                "port": 443,
                "protocol": "tcp",
                "state": "open"
            }
        ],
        "total_open_ports": 2,
        "hosts_with_open_ports": 1,
        "scan_statistics": {
            "packets_sent": 512,
            "packets_received": 2,
            "scan_duration": 15.3
        }
    },
    "raw_output": "Discovered open port 80/tcp on 192.168.1.100\nDiscovered open port 443/tcp on 192.168.1.100\n",
    "execution_time": 15.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Parameters (400 Bad Request)
```json
{
    "error": "Missing required parameters: targets, ports"
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
targets = params.get("targets", "")
ports = params.get("ports", "")
rate = params.get("rate", 1000)
protocol = params.get("protocol", "tcp")
output_format = params.get("output_format", "list")
output_file = params.get("output_file", "")
exclude = params.get("exclude", "")
interface = params.get("interface", "")
source_ip = params.get("source_ip", "")
additional_args = params.get("additional_args", "")

# Validate required parameters
missing_params = []
if not targets:
    missing_params.append("targets")
if not ports:
    missing_params.append("ports")
if missing_params:
    return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
```

### Command Construction
```python
# Base command
command = ["masscan", targets, "-p" + ports]

# Scan rate
command.extend(["--rate", str(rate)])

# Protocol
if protocol == "udp":
    command.append("--udp")

# Output format
if output_format != "list":
    command.extend(["-oX" if output_format == "xml" else "-oJ", output_file or "-"])

# Exclusions
if exclude:
    command.extend(["--exclude", exclude])

# Network interface
if interface:
    command.extend(["-e", interface])

# Source IP
if source_ip:
    command.extend(["--source-ip", source_ip])

# Output file
if output_file and output_format == "list":
    command.extend(["-oL", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Masscan execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing required parameters
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure targets are valid and authorized for scanning
- **Rate Limiting:** Implement intelligent rate limiting to prevent network overload
- **Responsible Use:** Emphasize responsible use of high-speed scanning capabilities

## Use Cases and Applications

#### Large-Scale Network Discovery
- **Internet Scanning:** Scan large IP ranges across the Internet
- **Network Reconnaissance:** Discover services on large networks
- **Asset Discovery:** Discover assets across multiple subnets

#### Security Assessment
- **Port Scanning:** High-speed port scanning for security assessment
- **Service Discovery:** Discover services running on target networks
- **Attack Surface Mapping:** Map the attack surface of large networks

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting"""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        rate = params.get("rate", 1000)
        interface = params.get("interface", "")
        router_mac = params.get("router_mac", "")
        source_ip = params.get("source_ip", "")
        banners = params.get("banners", False)
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("🎯 Masscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400
        
        command = f"masscan {target} -p{ports} --rate={rate}"
        
        if interface:
            command += f" -e {interface}"
        
        if router_mac:
            command += f" --router-mac {router_mac}"
        
        if source_ip:
            command += f" --source-ip {source_ip}"
        
        if banners:
            command += " --banners"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
        result = execute_command(command)
        logger.info(f"📊 Masscan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in masscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
