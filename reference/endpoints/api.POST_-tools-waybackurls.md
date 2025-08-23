---
title: POST /api/tools/waybackurls
group: api
handler: waybackurls
module: __main__
line_range: [11045, 11076]
discovered_in_chunk: 11
---

# POST /api/tools/waybackurls

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Waybackurls for historical URL discovery with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    """Execute Waybackurls for historical URL discovery with enhanced logging"""
```

## Purpose & Behavior
Waybackurls historical URL discovery endpoint providing:
- **Historical URL Discovery:** Find URLs from Wayback Machine archives
- **Version Control:** Get different versions of URLs over time
- **Subdomain Control:** Option to include or exclude subdomains
- **Enhanced Logging:** Detailed logging of URL discovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/waybackurls
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",              // Required: Target domain
    "get_versions": boolean,         // Optional: Get URL versions (default: false)
    "no_subs": boolean,              // Optional: Exclude subdomains (default: false)
    "additional_args": "string"      // Optional: Additional waybackurls arguments
}
```

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",
    "stderr": "string",
    "return_code": 0,
    "success": true,
    "execution_time": 18.4,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "waybackurls example.com"
}
```

## Code Reproduction
```python
@app.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    """Execute Waybackurls for historical URL discovery with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        get_versions = params.get("get_versions", False)
        no_subs = params.get("no_subs", False)
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("🌐 Waybackurls called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400
        
        command = f"waybackurls {domain}"
        
        if get_versions:
            command += " --get-versions"
        
        if no_subs:
            command += " --no-subs"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Waybackurls discovery completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in waybackurls endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
