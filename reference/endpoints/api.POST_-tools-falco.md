---
title: POST /api/tools/falco
group: api
handler: falco
module: __main__
line_range: [8984, 9015]
discovered_in_chunk: 9
---

# POST /api/tools/falco

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Falco for runtime security monitoring

## Complete Signature & Definition
```python
@app.route("/api/tools/falco", methods=["POST"])
def falco():
    """Execute Falco for runtime security monitoring"""
```

## Purpose & Behavior
Falco runtime security monitoring endpoint providing:
- **Runtime Monitoring:** Monitor container and host runtime behavior
- **Threat Detection:** Detect anomalous activities and security threats
- **Rule-Based Analysis:** Apply custom security rules for threat detection
- **Real-Time Alerts:** Generate real-time security alerts and notifications

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/falco
- **Content-Type:** application/json

### Request Body
```json
{
    "config_file": "string",        // Optional: Falco configuration file (default: "/etc/falco/falco.yaml")
    "rules_file": "string",         // Optional: Custom rules file path
    "output_format": "string",      // Optional: Output format (default: "json")
    "duration": integer,            // Optional: Monitoring duration in seconds (default: 60)
    "additional_args": "string"     // Optional: Additional Falco arguments
}
```

### Parameters
- **config_file:** Path to Falco configuration file (optional, default: "/etc/falco/falco.yaml")
- **rules_file:** Path to custom rules file (optional)
- **output_format:** Output format - json or text (optional, default: "json")
- **duration:** Monitoring duration in seconds (optional, default: 60)
- **additional_args:** Additional Falco arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Falco monitoring output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 60.1,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "timeout 60 falco --config /etc/falco/falco.yaml --json" // Actual command executed
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/falco", methods=["POST"])
def falco():
    """Execute Falco for runtime security monitoring"""
    try:
        params = request.json
        config_file = params.get("config_file", "/etc/falco/falco.yaml")
        rules_file = params.get("rules_file", "")
        output_format = params.get("output_format", "json")
        duration = params.get("duration", 60)  # seconds
        additional_args = params.get("additional_args", "")
        
        command = f"timeout {duration} falco"
        
        if config_file:
            command += f" --config {config_file}"
        
        if rules_file:
            command += f" --rules {rules_file}"
        
        if output_format == "json":
            command += " --json"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = execute_command(command)
        logger.info(f"📊 Falco monitoring completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in falco endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
