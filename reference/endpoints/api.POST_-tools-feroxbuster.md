---
title: POST /api/tools/feroxbuster
group: api
handler: feroxbuster
module: __main__
line_range: [10808, 10837]
discovered_in_chunk: 10
---

# POST /api/tools/feroxbuster

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Feroxbuster for recursive content discovery with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
```

## Purpose & Behavior
Feroxbuster content discovery endpoint providing:
- **Recursive Content Discovery:** Discover hidden directories and files on web servers
- **Parallel Scanning:** Perform high-speed parallel scanning
- **Filter Control:** Filter results based on status codes, sizes, and words
- **Recursive Depth Control:** Control recursion depth for thorough scanning
- **Enhanced Logging:** Detailed logging of scan progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/feroxbuster
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                   // Required: Target URL
    "wordlist": "string",              // Optional: Path to wordlist (default: built-in)
    "threads": integer,                // Optional: Number of threads (default: 50)
    "depth": integer,                  // Optional: Recursion depth (default: 4)
    "status_codes": "string",          // Optional: Status codes to include (default: all)
    "filter_status": "string",         // Optional: Status codes to exclude
    "extensions": "string",            // Optional: File extensions to scan
    "timeout": integer,                // Optional: Request timeout in seconds (default: 7)
    "user_agent": "string",            // Optional: Custom User-Agent
    "proxy": "string",                 // Optional: Proxy URL
    "additional_args": "string"        // Optional: Additional Feroxbuster arguments
}
```

### Parameters
- **url:** Target URL to scan (required)
- **wordlist:** Path to wordlist (optional, default: built-in)
- **threads:** Number of threads (optional, default: 50)
- **depth:** Recursion depth (optional, default: 4)
- **status_codes:** Status codes to include (optional, default: all)
- **filter_status:** Status codes to exclude (optional)
- **extensions:** File extensions to scan (optional)
- **timeout:** Request timeout in seconds (optional, default: 7)
- **user_agent:** Custom User-Agent (optional)
- **proxy:** Proxy URL (optional)
- **additional_args:** Additional Feroxbuster arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "feroxbuster -u https://example.com -w /usr/share/wordlists/dirb/common.txt -t 50 -d 4",
    "scan_results": {
        "target_url": "https://example.com",
        "start_time": "2024-01-01T12:00:00Z",
        "end_time": "2024-01-01T12:05:00Z",
        "total_requests": 1500,
        "status_code_count": {
            "200": 42,
            "301": 15,
            "403": 8,
            "404": 1435
        },
        "discovered_urls": [
            {
                "url": "https://example.com/admin",
                "status_code": 301,
                "content_length": 0,
                "redirect_location": "https://example.com/admin/"
            },
            {
                "url": "https://example.com/admin/",
                "status_code": 200,
                "content_length": 1234,
                "content_type": "text/html"
            }
        ]
    },
    "raw_output": "...",
    "execution_time": 300,
    "timestamp": "2024-01-01T12:05:00Z"
}
```

### Error Responses

#### Missing URL (400 Bad Request)
```json
{
    "error": "URL parameter is required"
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
url = params.get("url", "")
wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
threads = params.get("threads", 50)
depth = params.get("depth", 4)
status_codes = params.get("status_codes", "")
filter_status = params.get("filter_status", "")
extensions = params.get("extensions", "")
timeout = params.get("timeout", 7)
user_agent = params.get("user_agent", "")
proxy = params.get("proxy", "")
additional_args = params.get("additional_args", "")

if not url:
    return jsonify({"error": "URL parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["feroxbuster", "-u", url, "-w", wordlist, "-t", str(threads), "-d", str(depth)]

# Optional parameters
if status_codes:
    command.extend(["-s", status_codes])
if filter_status:
    command.extend(["-f", filter_status])
if extensions:
    command.extend(["-x", extensions])
if timeout:
    command.extend(["--timeout", str(timeout)])
if user_agent:
    command.extend(["-a", user_agent])
if proxy:
    command.extend(["--proxy", proxy])

# Output file
output_file = f"/tmp/feroxbuster_{int(time.time())}.json"
command.extend(["--json", "-o", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

### Execution and Result Processing
```python
start_time = time.time()
result = execute_command_with_recovery(command_str)
execution_time = time.time() - start_time

# Parse output file to structured format
scan_results = {}
if os.path.exists(output_file):
    with open(output_file, "r") as f:
        try:
            scan_data = json.load(f)
            scan_results = parse_feroxbuster_json(scan_data)
        except json.JSONDecodeError:
            scan_results = {"warning": "Failed to parse JSON output"}
            scan_results.update(parse_feroxbuster_raw_output(result["output"]))
else:
    scan_results = {"warning": "Output file not generated, using raw output"}
    scan_results.update(parse_feroxbuster_raw_output(result["output"]))

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
- **Authorization:** Feroxbuster execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing URL
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target URL is valid and authorized for scanning
- **Resource Limits:** Prevent resource exhaustion from intensive scans
- **Responsible Use:** Emphasize responsible use of scanning capabilities

## Use Cases and Applications

#### Web Application Security
- **Content Discovery:** Discover hidden directories and files
- **Attack Surface Mapping:** Map the attack surface of web applications
- **Security Assessment:** Assess web application security posture

#### Penetration Testing
- **Reconnaissance:** Gather information about target web applications
- **Vulnerability Discovery:** Discover potential vulnerabilities
- **Access Control Testing:** Test access controls on web resources

#### Bug Bounty Hunting
- **Target Enumeration:** Enumerate target web applications
- **Hidden Content Discovery:** Discover hidden or forgotten content
- **Vulnerability Research:** Research potential vulnerabilities

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", 50)
        depth = params.get("depth", 4)
        status_codes = params.get("status_codes", "")
        filter_status = params.get("filter_status", "")
        extensions = params.get("extensions", "")
        timeout = params.get("timeout", 7)
        user_agent = params.get("user_agent", "")
        proxy = params.get("proxy", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        
        # Base command
        command = ["feroxbuster", "-u", url, "-w", wordlist, "-t", str(threads), "-d", str(depth)]
        
        # Optional parameters
        if status_codes:
            command.extend(["-s", status_codes])
        if filter_status:
            command.extend(["-f", filter_status])
        if extensions:
            command.extend(["-x", extensions])
        if timeout:
            command.extend(["--timeout", str(timeout)])
        if user_agent:
            command.extend(["-a", user_agent])
        if proxy:
            command.extend(["--proxy", proxy])
        
        # Output file
        output_file = f"/tmp/feroxbuster_{int(time.time())}.json"
        command.extend(["--json", "-o", output_file])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing Feroxbuster scan: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output file to structured format
        scan_results = {}
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                try:
                    scan_data = json.load(f)
                    scan_results = parse_feroxbuster_json(scan_data)
                except json.JSONDecodeError:
                    scan_results = {"warning": "Failed to parse JSON output"}
                    scan_results.update(parse_feroxbuster_raw_output(result["output"]))
        else:
            scan_results = {"warning": "Output file not generated, using raw output"}
            scan_results.update(parse_feroxbuster_raw_output(result["output"]))
        
        logger.info(f"🔍 Feroxbuster scan completed in {execution_time:.2f}s")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "scan_results": scan_results,
            "raw_output": result["output"][:1000] + "..." if len(result["output"]) > 1000 else result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in feroxbuster endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
