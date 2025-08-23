---
title: POST /api/tools/httpx
group: api
handler: httpx
module: __main__
line_range: [11266, 11315]
discovered_in_chunk: 11
---

# POST /api/tools/httpx

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute httpx for fast HTTP probing and technology detection

## Complete Signature & Definition
```python
@app.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """Execute httpx for fast HTTP probing and technology detection"""
```

## Purpose & Behavior
Fast HTTP probing endpoint providing:
- **HTTP Service Detection:** Fast detection of HTTP services
- **Technology Fingerprinting:** Identify web technologies and frameworks
- **Status Code Analysis:** Analyze HTTP status codes and responses
- **Enhanced Logging:** Detailed logging of probing progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/httpx
- **Content-Type:** application/json

### Request Body
```json
{
    "targets": ["string"],            // Required: Target URLs or hosts
    "ports": "string",                // Optional: Ports to probe (default: 80,443)
    "threads": integer,               // Optional: Number of threads (default: 50)
    "timeout": integer,               // Optional: Timeout in seconds (default: 10)
    "follow_redirects": boolean,      // Optional: Follow redirects (default: false)
    "status_code": boolean,           // Optional: Show status codes (default: true)
    "title": boolean,                 // Optional: Show page titles (default: true)
    "tech_detect": boolean,           // Optional: Technology detection (default: true)
    "content_length": boolean,        // Optional: Show content length (default: true)
    "output_file": "string",          // Optional: Output file path
    "additional_args": "string"       // Optional: Additional httpx arguments
}
```

### Parameters
- **targets:** Target URLs or hosts (required) - ["example.com", "192.168.1.100"]
- **ports:** Ports to probe (optional) - "80,443,8080,8443"
- **threads:** Number of threads (optional, default: 50)
- **timeout:** Timeout in seconds (optional, default: 10)
- **follow_redirects:** Follow redirects flag (optional, default: false)
- **status_code:** Show status codes flag (optional, default: true)
- **title:** Show page titles flag (optional, default: true)
- **tech_detect:** Technology detection flag (optional, default: true)
- **content_length:** Show content length flag (optional, default: true)
- **output_file:** Output file path (optional)
- **additional_args:** Additional httpx arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "httpx -l targets.txt -ports 80,443 -threads 50",
    "probing_results": {
        "targets_probed": ["example.com", "192.168.1.100"],
        "live_hosts": [
            {
                "url": "https://example.com",
                "status_code": 200,
                "title": "Example Domain",
                "content_length": 1256,
                "technologies": ["Apache", "PHP"],
                "server": "Apache/2.4.41",
                "response_time": 150
            }
        ],
        "total_targets": 2,
        "live_targets": 1,
        "response_codes": {
            "200": 1,
            "404": 0,
            "500": 0
        }
    },
    "raw_output": "https://example.com [200] [Example Domain] [1256] [Apache,PHP]\n",
    "execution_time": 5.2,
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
ports = params.get("ports", "80,443")
threads = params.get("threads", 50)
timeout = params.get("timeout", 10)
follow_redirects = params.get("follow_redirects", False)
status_code = params.get("status_code", True)
title = params.get("title", True)
tech_detect = params.get("tech_detect", True)
content_length = params.get("content_length", True)
output_file = params.get("output_file", "")
additional_args = params.get("additional_args", "")

if not targets:
    return jsonify({"error": "Targets parameter is required"}), 400
```

### Command Construction
```python
# Create targets file
targets_file = f"/tmp/httpx_targets_{int(time.time())}.txt"
with open(targets_file, "w") as f:
    for target in targets:
        f.write(f"{target}\n")

# Base command
command = ["httpx", "-l", targets_file]

# Ports
if ports:
    command.extend(["-ports", ports])

# Threads
command.extend(["-threads", str(threads)])

# Timeout
command.extend(["-timeout", str(timeout)])

# Follow redirects
if follow_redirects:
    command.append("-follow-redirects")

# Status code
if status_code:
    command.append("-status-code")

# Title
if title:
    command.append("-title")

# Technology detection
if tech_detect:
    command.append("-tech-detect")

# Content length
if content_length:
    command.append("-content-length")

# Output file
if output_file:
    command.extend(["-o", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Httpx execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing targets
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure targets are valid and authorized for probing
- **Rate Limiting:** Respect rate limits to avoid overwhelming targets
- **Responsible Use:** Emphasize responsible use of HTTP probing capabilities

## Use Cases and Applications

#### Web Service Discovery
- **HTTP Service Detection:** Detect HTTP services on target hosts
- **Technology Identification:** Identify web technologies and frameworks
- **Service Enumeration:** Enumerate web services and applications

#### Security Assessment
- **Web Application Discovery:** Discover web applications for security testing
- **Technology Stack Analysis:** Analyze technology stacks for vulnerabilities
- **Attack Surface Mapping:** Map web-based attack surface

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """Execute httpx for fast HTTP probing and technology detection"""
    try:
        params = request.json
        targets = params.get("targets", [])
        ports = params.get("ports", "80,443")
        threads = params.get("threads", 50)
        timeout = params.get("timeout", 10)
        follow_redirects = params.get("follow_redirects", False)
        status_code = params.get("status_code", True)
        title = params.get("title", True)
        tech_detect = params.get("tech_detect", True)
        content_length = params.get("content_length", True)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not targets:
            return jsonify({"error": "Targets parameter is required"}), 400
        
        # Create targets file
        targets_file = f"/tmp/httpx_targets_{int(time.time())}.txt"
        with open(targets_file, "w") as f:
            for target in targets:
                f.write(f"{target}\n")
        
        # Base command
        command = ["httpx", "-l", targets_file]
        
        # Ports
        if ports:
            command.extend(["-ports", ports])
        
        # Threads
        command.extend(["-threads", str(threads)])
        
        # Timeout
        command.extend(["-timeout", str(timeout)])
        
        # Follow redirects
        if follow_redirects:
            command.append("-follow-redirects")
        
        # Status code
        if status_code:
            command.append("-status-code")
        
        # Title
        if title:
            command.append("-title")
        
        # Technology detection
        if tech_detect:
            command.append("-tech-detect")
        
        # Content length
        if content_length:
            command.append("-content-length")
        
        # Output file
        if output_file:
            command.extend(["-o", output_file])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing httpx: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for probing results
        probing_results = parse_httpx_output(result["output"], targets)
        
        logger.info(f"🔍 Httpx completed in {execution_time:.2f}s | Live hosts: {probing_results.get('live_targets', 0)}")
        
        # Cleanup targets file
        if os.path.exists(targets_file):
            os.remove(targets_file)
        
        return jsonify({
            "success": True,
            "command": command_str,
            "probing_results": probing_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in httpx endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
