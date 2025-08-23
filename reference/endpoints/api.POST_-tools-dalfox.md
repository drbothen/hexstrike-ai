---
title: POST /api/tools/dalfox
group: api
handler: dalfox
module: __main__
line_range: [11221, 11264]
discovered_in_chunk: 11
---

# POST /api/tools/dalfox

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/dalfox", methods=["POST"])
def dalfox():
    """Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging"""
```

## Purpose & Behavior
Advanced XSS vulnerability scanning endpoint providing:
- **Advanced XSS Detection:** Execute Dalfox for comprehensive XSS vulnerability scanning
- **Multiple Scanning Modes:** Support for URL and pipe mode scanning
- **Blind XSS Detection:** Advanced blind XSS detection capabilities
- **DOM and Dictionary Mining:** Enhanced payload discovery and testing

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/dalfox
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                    // Required: Target URL to scan (unless pipe_mode)
    "pipe_mode": boolean,               // Optional: Enable pipe mode scanning (default: false)
    "blind": boolean,                   // Optional: Enable blind XSS detection (default: false)
    "mining_dom": boolean,              // Optional: Enable DOM mining (default: true)
    "mining_dict": boolean,             // Optional: Enable dictionary mining (default: true)
    "custom_payload": "string",         // Optional: Custom XSS payload
    "additional_args": "string"         // Optional: Additional dalfox arguments
}
```

### Parameters
- **url:** Target URL to scan (required unless pipe_mode is true)
- **pipe_mode:** Enable pipe mode for input from stdin (optional, default: false)
- **blind:** Enable blind XSS detection (optional, default: false)
- **mining_dom:** Enable DOM mining for payload discovery (optional, default: true)
- **mining_dict:** Enable dictionary mining for payload discovery (optional, default: true)
- **custom_payload:** Custom XSS payload for testing (optional)
- **additional_args:** Additional dalfox arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Dalfox XSS scan output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 90.5,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "dalfox url https://example.com --mining-dom --mining-dict"
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

### Scanning Mode Configuration

#### URL Mode (default)
```python
if pipe_mode:
    command = "dalfox pipe"
else:
    command = f"dalfox url {url}"
```

### Command Building Logic
```python
if blind:
    command += " --blind"

if mining_dom:
    command += " --mining-dom"

if mining_dict:
    command += " --mining-dict"

if custom_payload:
    command += f" --custom-payload '{custom_payload}'"

if additional_args:
    command += f" {additional_args}"
```

### Default Configuration
- **DOM Mining:** Enabled by default for comprehensive payload discovery
- **Dictionary Mining:** Enabled by default for enhanced testing
- **Blind XSS:** Disabled by default (can be enabled for advanced testing)
- **URL Mode:** Default scanning mode (pipe mode available for advanced workflows)

### Dalfox Features
- **Advanced XSS Detection:** State-of-the-art XSS vulnerability detection
- **Multiple Payload Types:** Support for various XSS payload types
- **DOM Analysis:** Advanced DOM-based XSS detection
- **Blind XSS:** Out-of-band XSS detection capabilities
- **Custom Payloads:** Support for custom XSS payloads

### Scanning Capabilities
- **Reflected XSS:** Detection of reflected XSS vulnerabilities
- **Stored XSS:** Detection of stored XSS vulnerabilities
- **DOM XSS:** Detection of DOM-based XSS vulnerabilities
- **Blind XSS:** Detection of blind/out-of-band XSS vulnerabilities

## AuthN/AuthZ
- **Network Access:** Requires network access to target URLs
- **XSS Testing Tool:** Advanced XSS vulnerability scanner

## Observability
- **Scan Logging:** "🎯 Starting Dalfox XSS scan: {url if url else 'pipe mode'}"
- **Completion Logging:** "📊 Dalfox XSS scan completed"
- **Warning Logging:** "🌐 Dalfox called without URL parameter"
- **Error Logging:** "💥 Error in dalfox endpoint: {error}"

## Use Cases and Applications

#### Web Application Security Testing
- **XSS Vulnerability Assessment:** Comprehensive XSS vulnerability testing
- **Security Code Review:** Validate XSS prevention measures
- **Penetration Testing:** XSS testing during penetration tests

#### Bug Bounty Hunting
- **XSS Discovery:** Discover XSS vulnerabilities for bug bounty programs
- **Advanced Testing:** Use advanced features for thorough testing
- **Payload Customization:** Test with custom XSS payloads

#### Security Research
- **XSS Research:** Research new XSS attack vectors
- **Payload Development:** Develop and test new XSS payloads
- **Vulnerability Analysis:** Analyze XSS vulnerability patterns

## Testing & Validation
- URL parameter validation
- Scanning mode configuration testing
- Mining feature functionality verification
- Custom payload functionality testing

## Code Reproduction
```python
# From line 11221: Complete Flask endpoint implementation
@app.route("/api/tools/dalfox", methods=["POST"])
def dalfox():
    """Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        pipe_mode = params.get("pipe_mode", False)
        blind = params.get("blind", False)
        mining_dom = params.get("mining_dom", True)
        mining_dict = params.get("mining_dict", True)
        custom_payload = params.get("custom_payload", "")
        additional_args = params.get("additional_args", "")
        
        if not url and not pipe_mode:
            logger.warning("🌐 Dalfox called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400
        
        if pipe_mode:
            command = "dalfox pipe"
        else:
            command = f"dalfox url {url}"
        
        if blind:
            command += " --blind"
        
        if mining_dom:
            command += " --mining-dom"
        
        if mining_dict:
            command += " --mining-dict"
        
        if custom_payload:
            command += f" --custom-payload '{custom_payload}'"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🎯 Starting Dalfox XSS scan: {url if url else 'pipe mode'}")
        result = execute_command(command)
        logger.info(f"📊 Dalfox XSS scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dalfox endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
