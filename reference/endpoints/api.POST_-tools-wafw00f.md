---
title: POST /api/tools/wafw00f
group: api
handler: wafw00f
module: __main__
line_range: [12499, 12527]
discovered_in_chunk: 12
---

# POST /api/tools/wafw00f

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute wafw00f to identify and fingerprint WAF products

## Complete Signature & Definition
```python
@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
```

## Purpose & Behavior
Web Application Firewall detection endpoint providing:
- **WAF Detection:** Identify Web Application Firewalls protecting targets
- **WAF Fingerprinting:** Fingerprint specific WAF products and versions
- **Evasion Planning:** Plan evasion techniques based on WAF detection
- **Enhanced Logging:** Detailed logging of detection progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/wafw00f
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",               // Required: Target URL to test
    "list_wafs": boolean,             // Optional: List all detectable WAFs (default: false)
    "verbose": boolean,               // Optional: Verbose output (default: false)
    "proxy": "string",                // Optional: Proxy URL
    "headers": "object",              // Optional: Custom headers
    "timeout": integer,               // Optional: Request timeout (default: 7)
    "additional_args": "string"       // Optional: Additional wafw00f arguments
}
```

### Parameters
- **target:** Target URL to test (required)
- **list_wafs:** List all detectable WAFs flag (optional, default: false)
- **verbose:** Verbose output flag (optional, default: false)
- **proxy:** Proxy URL (optional) - "http://proxy:8080"
- **headers:** Custom headers (optional) - {"User-Agent": "custom"}
- **timeout:** Request timeout in seconds (optional, default: 7)
- **additional_args:** Additional wafw00f arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "wafw00f https://example.com",
    "detection_results": {
        "target": "https://example.com",
        "waf_detected": true,
        "waf_name": "Cloudflare",
        "waf_manufacturer": "Cloudflare Inc.",
        "confidence": "High",
        "detection_method": "Response headers analysis",
        "evasion_techniques": [
            "HTTP parameter pollution",
            "Case variation",
            "Encoding techniques"
        ],
        "response_analysis": {
            "status_codes": [403, 200],
            "headers_detected": ["cf-ray", "server: cloudflare"],
            "response_time": 150
        }
    },
    "raw_output": "Checking https://example.com\nThe site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.",
    "execution_time": 5.3,
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
list_wafs = params.get("list_wafs", False)
verbose = params.get("verbose", False)
proxy = params.get("proxy", "")
headers = params.get("headers", {})
timeout = params.get("timeout", 7)
additional_args = params.get("additional_args", "")

if not target:
    return jsonify({"error": "Target parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["wafw00f"]

# List WAFs
if list_wafs:
    command.append("-l")
    # Don't add target if listing WAFs
else:
    # Target
    command.append(target)

# Verbose
if verbose:
    command.append("-v")

# Proxy
if proxy:
    command.extend(["-p", proxy])

# Timeout
if timeout != 7:
    command.extend(["-t", str(timeout)])

# Headers
if headers:
    for key, value in headers.items():
        command.extend(["-H", f"{key}: {value}"])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Wafw00f execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing target
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for testing
- **Request Rate:** Control request rate to avoid triggering WAF blocks
- **Responsible Use:** Emphasize responsible use of WAF detection capabilities

## Use Cases and Applications

#### Web Application Testing
- **WAF Detection:** Detect WAF presence before security testing
- **Evasion Planning:** Plan evasion techniques based on WAF type
- **Testing Strategy:** Adapt testing strategy based on WAF detection

#### Penetration Testing
- **Reconnaissance:** WAF reconnaissance for penetration testing
- **Attack Planning:** Plan attacks based on WAF capabilities
- **Bypass Techniques:** Identify potential WAF bypass techniques

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- WAF detection accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        list_wafs = params.get("list_wafs", False)
        verbose = params.get("verbose", False)
        proxy = params.get("proxy", "")
        headers = params.get("headers", {})
        timeout = params.get("timeout", 7)
        additional_args = params.get("additional_args", "")
        
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        
        # Base command
        command = ["wafw00f"]
        
        # List WAFs
        if list_wafs:
            command.append("-l")
            # Don't add target if listing WAFs
        else:
            # Target
            command.append(target)
        
        # Verbose
        if verbose:
            command.append("-v")
        
        # Proxy
        if proxy:
            command.extend(["-p", proxy])
        
        # Timeout
        if timeout != 7:
            command.extend(["-t", str(timeout)])
        
        # Headers
        if headers:
            for key, value in headers.items():
                command.extend(["-H", f"{key}: {value}"])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing wafw00f: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for detection results
        detection_results = parse_wafw00f_output(result["output"], target)
        
        logger.info(f"🔍 Wafw00f completed in {execution_time:.2f}s | WAF detected: {detection_results.get('waf_detected', False)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "detection_results": detection_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in wafw00f endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
