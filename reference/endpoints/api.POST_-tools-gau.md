---
title: POST /api/tools/gau
group: api
handler: gau
module: __main__
line_range: [11008, 11043]
discovered_in_chunk: 11
---

# POST /api/tools/gau

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/gau", methods=["POST"])
def gau():
    """Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging"""
```

## Purpose & Behavior
Gau URL discovery endpoint providing:
- **Multi-Source Discovery:** Gather URLs from wayback, commoncrawl, otx, urlscan
- **Subdomain Support:** Include subdomains in URL discovery
- **Content Filtering:** Filter out unwanted file types
- **Enhanced Logging:** Detailed logging of URL discovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/gau
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",              // Required: Target domain
    "providers": "string",           // Optional: Data providers (default: wayback,commoncrawl,otx,urlscan)
    "include_subs": boolean,         // Optional: Include subdomains (default: true)
    "blacklist": "string",           // Optional: File extensions to blacklist
    "additional_args": "string"      // Optional: Additional gau arguments
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
    "execution_time": 25.7,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "gau example.com --subs --blacklist png,jpg,gif"
}
```

## Code Reproduction
```python
@app.route("/api/tools/gau", methods=["POST"])
def gau():
    """Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        providers = params.get("providers", "wayback,commoncrawl,otx,urlscan")
        include_subs = params.get("include_subs", True)
        blacklist = params.get("blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("🌐 Gau called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400
        
        command = f"gau {domain}"
        
        if providers != "wayback,commoncrawl,otx,urlscan":
            command += f" --providers {providers}"
        
        if include_subs:
            command += " --subs"
        
        if blacklist:
            command += f" --blacklist {blacklist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"📡 Starting Gau URL discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Gau URL discovery completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gau endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
