---
title: POST /api/tools/zap
group: api
handler: zap
module: __main__
line_range: [12449, 12498]
discovered_in_chunk: 12
---

# POST /api/tools/zap

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute OWASP ZAP with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP with enhanced logging"""
```

## Purpose & Behavior
Web application security scanning endpoint providing:
- **Automated Security Scanning:** Comprehensive web application security scanning
- **Vulnerability Detection:** Detect common web application vulnerabilities
- **Spider and Scan:** Automated spidering and active scanning
- **Enhanced Logging:** Detailed logging of scanning progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/zap
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",               // Required: Target URL to scan
    "scan_type": "string",            // Optional: Scan type (quick/full/baseline, default: quick)
    "spider": boolean,                // Optional: Enable spidering (default: true)
    "active_scan": boolean,           // Optional: Enable active scanning (default: true)
    "passive_scan": boolean,          // Optional: Enable passive scanning (default: true)
    "auth_script": "string",          // Optional: Authentication script
    "context": "string",              // Optional: ZAP context name
    "output_format": "string",        // Optional: Output format (html/xml/json, default: html)
    "output_file": "string",          // Optional: Output file path
    "additional_args": "string"       // Optional: Additional ZAP arguments
}
```

### Parameters
- **target:** Target URL to scan (required)
- **scan_type:** Scan type (optional) - "quick", "full", "baseline", default: "quick"
- **spider:** Enable spidering flag (optional, default: true)
- **active_scan:** Enable active scanning flag (optional, default: true)
- **passive_scan:** Enable passive scanning flag (optional, default: true)
- **auth_script:** Authentication script path (optional)
- **context:** ZAP context name (optional)
- **output_format:** Output format (optional) - "html", "xml", "json", default: "html"
- **output_file:** Output file path (optional)
- **additional_args:** Additional ZAP arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "zap-baseline.py -t https://example.com -r zap_report.html",
    "scan_results": {
        "target": "https://example.com",
        "scan_type": "baseline",
        "vulnerabilities": [
            {
                "name": "Cross Site Scripting (Reflected)",
                "risk": "High",
                "confidence": "Medium",
                "url": "https://example.com/search?q=<script>",
                "description": "Reflected XSS vulnerability found"
            }
        ],
        "total_vulnerabilities": 5,
        "high_risk": 1,
        "medium_risk": 2,
        "low_risk": 2,
        "informational": 0,
        "urls_scanned": 25,
        "scan_duration": 300
    },
    "raw_output": "ZAP Baseline Scan Report\n======================\n",
    "execution_time": 305.2,
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
scan_type = params.get("scan_type", "quick")
spider = params.get("spider", True)
active_scan = params.get("active_scan", True)
passive_scan = params.get("passive_scan", True)
auth_script = params.get("auth_script", "")
context = params.get("context", "")
output_format = params.get("output_format", "html")
output_file = params.get("output_file", "")
additional_args = params.get("additional_args", "")

if not target:
    return jsonify({"error": "Target parameter is required"}), 400
```

### Command Construction
```python
# Determine ZAP script based on scan type
if scan_type == "baseline":
    command = ["zap-baseline.py"]
elif scan_type == "full":
    command = ["zap-full-scan.py"]
else:
    command = ["zap-baseline.py"]  # Default to baseline

# Target
command.extend(["-t", target])

# Output file
if not output_file:
    output_file = f"/tmp/zap_report_{int(time.time())}.{output_format}"
command.extend(["-r", output_file])

# Authentication script
if auth_script:
    command.extend(["-z", auth_script])

# Context
if context:
    command.extend(["-n", context])

# Scan options
if not spider:
    command.append("-s")
if not active_scan:
    command.append("-p")

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** ZAP execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing target
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for scanning
- **Scan Scope:** Limit scan scope to authorized targets only
- **Responsible Use:** Emphasize responsible use of web application scanning

## Use Cases and Applications

#### Web Application Security Testing
- **Vulnerability Assessment:** Comprehensive vulnerability assessment
- **Security Scanning:** Automated security scanning of web applications
- **Compliance Testing:** Security compliance testing and reporting

#### Penetration Testing
- **Web Application Testing:** Web application penetration testing
- **Vulnerability Discovery:** Discover web application vulnerabilities
- **Security Analysis:** Analyze web application security posture

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Scan result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "quick")
        spider = params.get("spider", True)
        active_scan = params.get("active_scan", True)
        passive_scan = params.get("passive_scan", True)
        auth_script = params.get("auth_script", "")
        context = params.get("context", "")
        output_format = params.get("output_format", "html")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            return jsonify({"error": "Target parameter is required"}), 400
        
        # Determine ZAP script based on scan type
        if scan_type == "baseline":
            command = ["zap-baseline.py"]
        elif scan_type == "full":
            command = ["zap-full-scan.py"]
        else:
            command = ["zap-baseline.py"]  # Default to baseline
        
        # Target
        command.extend(["-t", target])
        
        # Output file
        if not output_file:
            output_file = f"/tmp/zap_report_{int(time.time())}.{output_format}"
        command.extend(["-r", output_file])
        
        # Authentication script
        if auth_script:
            command.extend(["-z", auth_script])
        
        # Context
        if context:
            command.extend(["-n", context])
        
        # Scan options
        if not spider:
            command.append("-s")
        if not active_scan:
            command.append("-p")
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing ZAP: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for scan results
        scan_results = parse_zap_output(result["output"], output_file, target)
        
        logger.info(f"🔍 ZAP completed in {execution_time:.2f}s | Vulnerabilities: {scan_results.get('total_vulnerabilities', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "scan_results": scan_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in ZAP endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
