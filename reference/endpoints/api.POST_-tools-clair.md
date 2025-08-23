---
title: POST /api/tools/clair
group: api
handler: clair
module: __main__
line_range: [8950, 8982]
discovered_in_chunk: 9
---

# POST /api/tools/clair

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Clair for container vulnerability analysis

## Complete Signature & Definition
```python
@app.route("/api/tools/clair", methods=["POST"])
def clair():
    """Execute Clair for container vulnerability analysis"""
```

## Purpose & Behavior
Clair container vulnerability analysis endpoint providing:
- **Container Scanning:** Analyze container images for known vulnerabilities
- **CVE Detection:** Identify Common Vulnerabilities and Exposures in containers
- **Layer Analysis:** Analyze individual container layers for security issues
- **Report Generation:** Generate detailed vulnerability reports

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/clair
- **Content-Type:** application/json

### Request Body
```json
{
    "image": "string",              // Required: Container image to analyze
    "config": "string",             // Optional: Clair configuration file (default: "/etc/clair/config.yaml")
    "output_format": "string",      // Optional: Output format (default: "json")
    "additional_args": "string"     // Optional: Additional Clair arguments
}
```

### Parameters
- **image:** Container image name/tag to analyze (required)
- **config:** Path to Clair configuration file (optional, default: "/etc/clair/config.yaml")
- **output_format:** Output format for results (optional, default: "json")
- **additional_args:** Additional Clair arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Clair analysis output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 90.3,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "clairctl analyze nginx:latest --config /etc/clair/config.yaml --format json" // Actual command executed
}
```

### Error Responses

#### Missing Image (400 Bad Request)
```json
{
    "error": "Image parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/clair", methods=["POST"])
def clair():
    """Execute Clair for container vulnerability analysis"""
    try:
        params = request.json
        image = params.get("image", "")
        config = params.get("config", "/etc/clair/config.yaml")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")
        
        if not image:
            logger.warning("🐳 Clair called without image parameter")
            return jsonify({"error": "Image parameter is required"}), 400
        
        # Use clairctl for scanning
        command = f"clairctl analyze {image}"
        
        if config:
            command += f" --config {config}"
        
        if output_format:
            command += f" --format {output_format}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🐳 Starting Clair vulnerability scan: {image}")
        result = execute_command(command)
        logger.info(f"📊 Clair scan completed for {image}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in clair endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
