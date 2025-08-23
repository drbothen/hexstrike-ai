---
title: POST /api/tools/api_schema_analyzer
group: api
handler: api_schema_analyzer
module: __main__
line_range: [13486, 13525]
discovered_in_chunk: 13
---

# POST /api/tools/api_schema_analyzer

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute API schema analyzer for API documentation analysis

## Complete Signature & Definition
```python
@app.route("/api/tools/api_schema_analyzer", methods=["POST"])
def api_schema_analyzer():
    """Execute API schema analyzer for API documentation analysis with enhanced logging"""
```

## Purpose & Behavior
API schema analysis endpoint providing:
- **Schema Analysis:** Comprehensive API schema and documentation analysis
- **Endpoint Discovery:** Discover API endpoints from schema documentation
- **Parameter Analysis:** Analyze API parameters and data types
- **Enhanced Logging:** Detailed logging of analysis progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/api_schema_analyzer
- **Content-Type:** application/json

### Request Body
```json
{
    "schema_url": "string",           // Required: URL to API schema/documentation
    "schema_file": "string",          // Optional: Local schema file path
    "schema_type": "string",          // Optional: Schema type (openapi, swagger, etc.)
    "output_format": "string",        // Optional: Output format (json, yaml, etc.)
    "extract_endpoints": boolean,     // Optional: Extract endpoints (default: true)
    "analyze_parameters": boolean,    // Optional: Analyze parameters (default: true)
    "security_analysis": boolean,     // Optional: Security analysis (default: true)
    "output_file": "string",          // Optional: Output file path
    "additional_args": "string"       // Optional: Additional analyzer arguments
}
```

### Parameters
- **schema_url:** URL to API schema/documentation (required if schema_file not provided)
- **schema_file:** Local schema file path (optional, alternative to schema_url)
- **schema_type:** Schema type (optional) - "openapi", "swagger", "postman", "raml"
- **output_format:** Output format (optional) - "json", "yaml", "xml"
- **extract_endpoints:** Extract endpoints flag (optional, default: true)
- **analyze_parameters:** Analyze parameters flag (optional, default: true)
- **security_analysis:** Security analysis flag (optional, default: true)
- **output_file:** Output file path (optional)
- **additional_args:** Additional analyzer arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "api_schema_analyzer --url https://api.example.com/swagger.json",
    "analysis_results": {
        "schema_url": "https://api.example.com/swagger.json",
        "schema_type": "openapi",
        "api_info": {
            "title": "Example API",
            "version": "1.0.0",
            "description": "Example API for testing"
        },
        "endpoints": [
            {
                "path": "/users",
                "method": "GET",
                "parameters": ["limit", "offset"],
                "responses": ["200", "400", "500"]
            },
            {
                "path": "/users/{id}",
                "method": "GET",
                "parameters": ["id"],
                "responses": ["200", "404", "500"]
            }
        ],
        "security_schemes": [
            {
                "type": "bearer",
                "scheme": "JWT"
            }
        ],
        "vulnerabilities": [
            {
                "type": "Missing Rate Limiting",
                "endpoints": ["/users"],
                "severity": "Medium"
            }
        ],
        "total_endpoints": 25,
        "authenticated_endpoints": 20,
        "public_endpoints": 5
    },
    "raw_output": "Analyzing API schema...\nFound 25 endpoints\nSecurity analysis complete\n",
    "execution_time": 8.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Schema Source (400 Bad Request)
```json
{
    "error": "Schema URL or schema file is required"
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
schema_url = params.get("schema_url", "")
schema_file = params.get("schema_file", "")
schema_type = params.get("schema_type", "")
output_format = params.get("output_format", "json")
extract_endpoints = params.get("extract_endpoints", True)
analyze_parameters = params.get("analyze_parameters", True)
security_analysis = params.get("security_analysis", True)
output_file = params.get("output_file", "")
additional_args = params.get("additional_args", "")

if not schema_url and not schema_file:
    return jsonify({"error": "Schema URL or schema file is required"}), 400
```

### Command Construction
```python
# Base command
command = ["api_schema_analyzer"]

# Schema source
if schema_url:
    command.extend(["--url", schema_url])
elif schema_file:
    command.extend(["--file", schema_file])

# Schema type
if schema_type:
    command.extend(["--type", schema_type])

# Output format
command.extend(["--format", output_format])

# Extract endpoints
if extract_endpoints:
    command.append("--extract-endpoints")

# Analyze parameters
if analyze_parameters:
    command.append("--analyze-params")

# Security analysis
if security_analysis:
    command.append("--security")

# Output file
if output_file:
    command.extend(["--output", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** API schema analyzer execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing schema source
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **URL Validation:** Validate schema URLs to prevent SSRF attacks
- **File Path Validation:** Validate file paths to prevent directory traversal
- **Responsible Use:** Emphasize responsible use of schema analysis capabilities

## Use Cases and Applications

#### API Security Testing
- **Endpoint Discovery:** Discover API endpoints for security testing
- **Parameter Analysis:** Analyze API parameters for testing
- **Security Assessment:** Assess API security from schema documentation

#### API Documentation Analysis
- **Schema Validation:** Validate API schema documentation
- **Endpoint Mapping:** Map API endpoints and functionality
- **Security Review:** Review API security configurations

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Schema analysis accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/api_schema_analyzer", methods=["POST"])
def api_schema_analyzer():
    """Execute API schema analyzer for API documentation analysis with enhanced logging"""
    try:
        params = request.json
        schema_url = params.get("schema_url", "")
        schema_file = params.get("schema_file", "")
        schema_type = params.get("schema_type", "")
        output_format = params.get("output_format", "json")
        extract_endpoints = params.get("extract_endpoints", True)
        analyze_parameters = params.get("analyze_parameters", True)
        security_analysis = params.get("security_analysis", True)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not schema_url and not schema_file:
            return jsonify({"error": "Schema URL or schema file is required"}), 400
        
        # Base command
        command = ["api_schema_analyzer"]
        
        # Schema source
        if schema_url:
            command.extend(["--url", schema_url])
        elif schema_file:
            command.extend(["--file", schema_file])
        
        # Schema type
        if schema_type:
            command.extend(["--type", schema_type])
        
        # Output format
        command.extend(["--format", output_format])
        
        # Extract endpoints
        if extract_endpoints:
            command.append("--extract-endpoints")
        
        # Analyze parameters
        if analyze_parameters:
            command.append("--analyze-params")
        
        # Security analysis
        if security_analysis:
            command.append("--security")
        
        # Output file
        if output_file:
            command.extend(["--output", output_file])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing API schema analyzer: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for analysis results
        analysis_results = parse_api_schema_analyzer_output(result["output"], schema_url or schema_file)
        
        logger.info(f"🔍 API schema analyzer completed in {execution_time:.2f}s | Endpoints: {analysis_results.get('total_endpoints', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "analysis_results": analysis_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in API schema analyzer endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
