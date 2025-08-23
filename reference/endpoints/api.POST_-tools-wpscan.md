---
title: POST /api/tools/wpscan
group: api
handler: wpscan
module: __main__
line_range: [9315, 9351]
discovered_in_chunk: 9
---

# POST /api/tools/wpscan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute WPScan for WordPress vulnerability scanning

## Complete Signature & Definition
```python
@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with enhanced logging"""
```

## Purpose & Behavior
WPScan execution endpoint providing:
- **WordPress Scanning:** Comprehensive WordPress vulnerability scanning
- **Plugin Detection:** Detect WordPress plugins and themes
- **User Enumeration:** Enumerate WordPress users
- **Enhanced Logging:** Detailed logging of WPScan operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/wpscan
- **Content-Type:** application/json

### Request Body
```json
{
    "target": {
        "url": "string",              // Required: Target WordPress URL
        "username": "string",         // Optional: Username for authentication
        "password": "string",         // Optional: Password for authentication
        "cookie": "string"            // Optional: Authentication cookie
    },
    "scan_options": {
        "enumerate": ["string"],      // Optional: Enumeration options
        "plugins_detection": "string", // Optional: Plugin detection mode
        "themes_detection": "string", // Optional: Theme detection mode
        "users": boolean,             // Optional: Enumerate users (default: true)
        "vulnerable_plugins": boolean, // Optional: Check for vulnerable plugins
        "vulnerable_themes": boolean, // Optional: Check for vulnerable themes
        "timthumbs": boolean,         // Optional: Enumerate timthumbs
        "config_backups": boolean,    // Optional: Check for config backups
        "db_exports": boolean         // Optional: Check for database exports
    },
    "output_options": {
        "format": "string",           // Optional: Output format (default: json)
        "output_file": "string",      // Optional: Output file path
        "verbose": boolean            // Optional: Verbose output (default: false)
    }
}
```

### Parameters
- **target:** Target WordPress site information (required)
- **scan_options:** Scanning configuration options (optional)
- **output_options:** Output formatting options (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "scan_info": {
        "target_url": "https://example.com",
        "scan_duration": 245.7,
        "wordpress_version": "6.3.1",
        "vulnerabilities_found": 5
    },
    "scan_results": {
        "wordpress_version": {
            "number": "6.3.1",
            "status": "insecure",
            "vulnerabilities": [
                {
                    "title": "WordPress Core Vulnerability",
                    "type": "XSS",
                    "fixed_in": "6.3.2"
                }
            ]
        },
        "plugins": [
            {
                "name": "contact-form-7",
                "version": "5.7.7",
                "status": "vulnerable",
                "vulnerabilities": [
                    {
                        "title": "Contact Form 7 XSS",
                        "type": "XSS",
                        "cvss": 6.1
                    }
                ]
            }
        ],
        "themes": [
            {
                "name": "twentytwentythree",
                "version": "1.2",
                "status": "secure"
            }
        ],
        "users": [
            {
                "id": 1,
                "login": "admin",
                "display_name": "Administrator"
            }
        ]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Invalid URL (400 Bad Request)
```json
{
    "error": "Invalid or unreachable WordPress URL"
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
target = params.get("target", {})
scan_options = params.get("scan_options", {})
output_options = params.get("output_options", {})

url = target.get("url", "")
if not url:
    return jsonify({"error": "Target URL is required"}), 400
```

### WPScan Execution Logic
```python
# Build WPScan command
cmd = ["wpscan", "--url", url]

# Add enumeration options
if scan_options.get("enumerate"):
    cmd.extend(["--enumerate", ",".join(scan_options["enumerate"])])

# Add authentication if provided
if target.get("username") and target.get("password"):
    cmd.extend(["--username", target["username"]])
    cmd.extend(["--password", target["password"]])

# Execute WPScan
result = execute_command_with_recovery(cmd)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** WPScan execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing URL
- **Execution Errors:** Handle WPScan execution failures
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Authorization:** Verify authorization for scanning target sites
- **Credential Security:** Secure handling of authentication credentials
- **Rate Limiting:** Implement rate limiting for scan requests

## Use Cases and Applications

#### WordPress Security Assessment
- **Vulnerability Scanning:** Scan WordPress sites for known vulnerabilities
- **Plugin Analysis:** Analyze installed plugins for security issues
- **User Enumeration:** Enumerate WordPress users for security testing

#### Penetration Testing
- **WordPress Pentesting:** Include in WordPress penetration testing workflows
- **Automated Scanning:** Automate WordPress vulnerability detection
- **Security Auditing:** Audit WordPress installations for security compliance

## Testing & Validation
- Parameter validation accuracy testing
- WPScan execution verification testing
- Output parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", {})
        scan_options = params.get("scan_options", {})
        output_options = params.get("output_options", {})
        
        url = target.get("url", "")
        if not url:
            return jsonify({"error": "Target URL is required"}), 400
        
        logger.info(f"🔍 Starting WPScan for: {url}")
        
        start_time = time.time()
        
        # Build WPScan command
        cmd = ["wpscan", "--url", url, "--format", "json"]
        
        # Add enumeration options
        if scan_options.get("enumerate"):
            cmd.extend(["--enumerate", ",".join(scan_options["enumerate"])])
        
        # Add authentication if provided
        if target.get("username") and target.get("password"):
            cmd.extend(["--username", target["username"]])
            cmd.extend(["--password", target["password"]])
        
        # Execute WPScan
        result = execute_command_with_recovery(cmd)
        
        scan_duration = time.time() - start_time
        
        # Parse WPScan output
        scan_results = json.loads(result.stdout) if result.stdout else {}
        
        scan_info = {
            "target_url": url,
            "scan_duration": scan_duration,
            "wordpress_version": scan_results.get("version", {}).get("number", "Unknown"),
            "vulnerabilities_found": len(scan_results.get("vulnerabilities", []))
        }
        
        logger.info(f"🔍 WPScan completed in {scan_duration:.2f}s | Vulnerabilities: {scan_info['vulnerabilities_found']}")
        
        return jsonify({
            "success": True,
            "scan_info": scan_info,
            "scan_results": scan_results,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error executing WPScan: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
