---
title: POST /api/tools/cloudmapper
group: api
handler: cloudmapper
module: __main__
line_range: [8752, 8783]
discovered_in_chunk: 9
---

# POST /api/tools/cloudmapper

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute CloudMapper for AWS network visualization and security analysis

## Complete Signature & Definition
```python
@app.route("/api/tools/cloudmapper", methods=["POST"])
def cloudmapper():
    """Execute CloudMapper for AWS network visualization and security analysis"""
```

## Purpose & Behavior
CloudMapper AWS network analysis endpoint providing:
- **Network Visualization:** Generate network topology diagrams
- **Security Analysis:** Identify security issues in AWS networks
- **Data Collection:** Collect AWS network configuration data
- **Web Interface:** Optional web server for interactive visualization

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/cloudmapper
- **Content-Type:** application/json

### Request Body
```json
{
    "action": "string",             // Required: CloudMapper action (collect, prepare, webserver, etc.)
    "account": "string",            // Optional: AWS account name
    "config": "string",             // Optional: Configuration file path (default: "config.json")
    "additional_args": "string"     // Optional: Additional CloudMapper arguments
}
```

### Parameters
- **action:** CloudMapper action - collect, prepare, webserver, find_admins, etc. (required)
- **account:** AWS account name (optional, required for most actions except webserver)
- **config:** Path to configuration file (optional, default: "config.json")
- **additional_args:** Additional CloudMapper arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // CloudMapper output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 45.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "cloudmapper collect --account myaccount --config config.json" // Actual command executed
}
```

### Error Responses

#### Missing Account (400 Bad Request)
```json
{
    "error": "Account parameter is required for most actions"
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
@app.route("/api/tools/cloudmapper", methods=["POST"])
def cloudmapper():
    """Execute CloudMapper for AWS network visualization and security analysis"""
    try:
        params = request.json
        action = params.get("action", "collect")  # collect, prepare, webserver, find_admins, etc.
        account = params.get("account", "")
        config = params.get("config", "config.json")
        additional_args = params.get("additional_args", "")
        
        if not account and action != "webserver":
            logger.warning("☁️  CloudMapper called without account parameter")
            return jsonify({"error": "Account parameter is required for most actions"}), 400
        
        command = f"cloudmapper {action}"
        
        if account:
            command += f" --account {account}"
        
        if config:
            command += f" --config {config}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"☁️  Starting CloudMapper {action}")
        result = execute_command(command)
        logger.info(f"📊 CloudMapper {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in cloudmapper endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
