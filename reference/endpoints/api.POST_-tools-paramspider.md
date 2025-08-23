---
title: POST /api/tools/paramspider
group: api
handler: paramspider
module: __main__
line_range: [11117, 11149]
discovered_in_chunk: 11
---

# POST /api/tools/paramspider

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute ParamSpider for parameter mining from web archives with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    """Execute ParamSpider for parameter mining from web archives with enhanced logging"""
```

## Purpose & Behavior
ParamSpider parameter mining endpoint providing:
- **Archive Mining:** Extract parameters from web archive sources
- **Level Control:** Configurable crawling depth levels
- **Content Filtering:** Filter out unwanted file extensions
- **Enhanced Logging:** Detailed logging of parameter mining operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/paramspider
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",              // Required: Target domain
    "level": integer,                // Optional: Crawling level (default: 2)
    "exclude": "string",             // Optional: File extensions to exclude
    "output": "string",              // Optional: Output file path
    "additional_args": "string"      // Optional: Additional paramspider arguments
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
    "execution_time": 28.3,
    "timestamp": "2024-01-01T12:00:00Z",
    "command": "paramspider -d example.com -l 2 --exclude png,jpg,gif"
}
```

## Code Reproduction
```python
@app.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    """Execute ParamSpider for parameter mining from web archives with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        level = params.get("level", 2)
        exclude = params.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        output = params.get("output", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("🌐 ParamSpider called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400
        
        command = f"paramspider -d {domain} -l {level}"
        
        if exclude:
            command += f" --exclude {exclude}"
        
        if output:
            command += f" -o {output}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = execute_command(command)
        logger.info(f"📊 ParamSpider mining completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in paramspider endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
