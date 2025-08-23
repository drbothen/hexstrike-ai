---
title: POST /api/tools/api_fuzzer
group: api
handler: api_fuzzer
module: __main__
line_range: [13403, 13445]
discovered_in_chunk: 13
---

# POST /api/tools/api_fuzzer

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute API fuzzer for API security testing

## Complete Signature & Definition
```python
@app.route("/api/tools/api_fuzzer", methods=["POST"])
def api_fuzzer():
    """Execute API fuzzer for API security testing with enhanced logging"""
```

## Purpose & Behavior
API security testing endpoint providing:
- **API Fuzzing:** Comprehensive API fuzzing and security testing
- **Parameter Testing:** Test API parameters for vulnerabilities
- **Authentication Testing:** Test API authentication mechanisms
- **Enhanced Logging:** Detailed logging of fuzzing progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/api_fuzzer
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",               // Required: Target API endpoint
    "method": "string",               // Optional: HTTP method (default: GET)
    "headers": "object",              // Optional: Custom headers
    "parameters": "object",           // Optional: API parameters
    "payloads": ["string"],           // Optional: Custom payloads
    "auth_token": "string",           // Optional: Authentication token
    "rate_limit": integer,            // Optional: Rate limit (default: 10)
    "timeout": integer,               // Optional: Request timeout (default: 30)
    "wordlist": "string",             // Optional: Wordlist file path
    "additional_args": "string"       // Optional: Additional fuzzer arguments
}
```

### Parameters
- **target:** Target API endpoint (required)
- **method:** HTTP method (optional, default: "GET") - "GET", "POST", "PUT", etc.
- **headers:** Custom headers (optional) - {"Authorization": "Bearer token"}
- **parameters:** API parameters (optional) - {"param1": "value1"}
- **payloads:** Custom payloads (optional) - ["<script>", "' OR 1=1--"]
- **auth_token:** Authentication token (optional)
- **rate_limit:** Rate limit in requests per second (optional, default: 10)
- **timeout:** Request timeout in seconds (optional, default: 30)
- **wordlist:** Wordlist file path (optional)
- **additional_args:** Additional fuzzer arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "api_fuzzer --target https://api.example.com/users --method GET",
    "fuzzing_results": {
        "target": "https://api.example.com/users",
        "method": "GET",
        "total_requests": 1000,
        "successful_requests": 950,
        "failed_requests": 50,
        "vulnerabilities": [
            {
                "type": "SQL Injection",
                "parameter": "id",
                "payload": "' OR 1=1--",
                "response_code": 200,
                "evidence": "Database error in response"
            }
        ],
        "response_codes": {
            "200": 800,
            "400": 100,
            "401": 30,
            "500": 20
        },
        "average_response_time": 250,
        "rate_limited": false
    },
    "raw_output": "Starting API fuzzing...\nTesting parameter: id\nVulnerability found: SQL Injection\n",
    "execution_time": 120.5,
    "timestamp": "2024-01-01T12:00:00Z"
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

### Parameter Validation
```python
params = request.json
target = params.get("target", "")
method = params.get("method", "GET")
headers = params.get("headers", {})
parameters = params.get("parameters", {})
payloads = params.get("payloads", [])
auth_token = params.get("auth_token", "")
rate_limit = params.get("rate_limit", 10)
timeout = params.get("timeout", 30)
wordlist = params.get("wordlist", "")
additional_args = params.get("additional_args", "")

if not target:
    return jsonify({"error": "Target parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["api_fuzzer", "--target", target]

# HTTP method
command.extend(["--method", method])

# Headers
if headers:
    for key, value in headers.items():
        command.extend(["--header", f"{key}: {value}"])

# Parameters
if parameters:
    for key, value in parameters.items():
        command.extend(["--param", f"{key}={value}"])

# Payloads
if payloads:
    command.extend(["--payloads", ",".join(payloads)])

# Authentication
if auth_token:
    command.extend(["--auth", auth_token])

# Rate limit
command.extend(["--rate-limit", str(rate_limit)])

# Timeout
command.extend(["--timeout", str(timeout)])

# Wordlist
if wordlist:
    command.extend(["--wordlist", wordlist])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** API fuzzer execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing target
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for testing
- **Rate Limiting:** Respect rate limits to avoid overwhelming targets
- **Responsible Use:** Emphasize responsible use of API fuzzing capabilities

## Use Cases and Applications

#### API Security Testing
- **Vulnerability Discovery:** Discover API vulnerabilities through fuzzing
- **Parameter Testing:** Test API parameters for security issues
- **Authentication Testing:** Test API authentication mechanisms

#### Penetration Testing
- **API Assessment:** Comprehensive API security assessment
- **Attack Vector Discovery:** Discover potential attack vectors
- **Security Validation:** Validate API security controls

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Fuzzing result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/api_fuzzer", methods=["POST"])
def api_fuzzer():
    """Execute API fuzzer for API security testing with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        method = params.get("method", "GET")
        headers = params.get("headers", {})
        parameters = params.get("parameters", {})
        payloads = params.get("payloads", [])
        auth_token = params.get("auth_token", "")
        rate_limit = params.get("rate_limit", 10)
        timeout = params.get("timeout", 30)
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        
        # Base command
        command = ["api_fuzzer", "--target", target]
        
        # HTTP method
        command.extend(["--method", method])
        
        # Headers
        if headers:
            for key, value in headers.items():
                command.extend(["--header", f"{key}: {value}"])
        
        # Parameters
        if parameters:
            for key, value in parameters.items():
                command.extend(["--param", f"{key}={value}"])
        
        # Payloads
        if payloads:
            command.extend(["--payloads", ",".join(payloads)])
        
        # Authentication
        if auth_token:
            command.extend(["--auth", auth_token])
        
        # Rate limit
        command.extend(["--rate-limit", str(rate_limit)])
        
        # Timeout
        command.extend(["--timeout", str(timeout)])
        
        # Wordlist
        if wordlist:
            command.extend(["--wordlist", wordlist])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing API fuzzer: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for fuzzing results
        fuzzing_results = parse_api_fuzzer_output(result["output"], target, method)
        
        logger.info(f"🔍 API fuzzer completed in {execution_time:.2f}s | Vulnerabilities: {len(fuzzing_results.get('vulnerabilities', []))}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "fuzzing_results": fuzzing_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in API fuzzer endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
