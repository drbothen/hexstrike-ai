---
title: POST /api/command
group: api
handler: generic_command
module: __main__
line_range: [7269, 7290]
discovered_in_chunk: 7
---

# POST /api/command

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute any command provided in the request with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request with enhanced logging"""
```

## Purpose & Behavior
Generic command execution endpoint providing:
- **Flexible Command Execution:** Execute any shell command via API
- **Cache Integration:** Optional caching for command results
- **Enhanced Logging:** Comprehensive logging of command execution
- **Error Handling:** Robust error handling with detailed error responses

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/command
- **Content-Type:** application/json

### Request Body
```json
{
    "command": "string",        // Required: Command to execute
    "use_cache": boolean        // Optional: Whether to use caching (default: true)
}
```

### Parameters
- **command:** Shell command to execute (required)
- **use_cache:** Enable/disable result caching (optional, default: true)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",             // Command stdout output
    "stderr": "string",             // Command stderr output
    "return_code": 0,               // Process exit code
    "success": true,                // Execution success flag
    "timed_out": false,             // Timeout flag
    "partial_results": false,       // Partial results flag
    "execution_time": 2.34,         // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z"  // ISO timestamp
}
```

### Error Responses

#### Missing Command (400 Bad Request)
```json
{
    "error": "Command parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Request Processing
1. **JSON Parsing:** Extract command and use_cache from request JSON
2. **Parameter Validation:** Ensure command parameter is provided
3. **Command Execution:** Execute command using execute_command function
4. **Response Generation:** Return execution results as JSON

### Parameter Extraction
```python
params = request.json
command = params.get("command", "")
use_cache = params.get("use_cache", True)
```

### Validation Logic
```python
if not command:
    logger.warning("⚠️  Command endpoint called without command parameter")
    return jsonify({"error": "Command parameter is required"}), 400
```

### Command Execution Integration
- **Function Call:** execute_command(command, use_cache=use_cache)
- **Result Passthrough:** Direct return of execution results
- **Cache Control:** Respect use_cache parameter for performance optimization

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Not specified (command execution access)

## Error Handling
- **Missing Parameters:** 400 error for missing command
- **Execution Errors:** Handled by execute_command function
- **Server Errors:** 500 error with exception details
- **Logging Integration:** Comprehensive error logging

## Observability
- **Request Logging:** Warning for missing command parameter
- **Error Logging:** Error logging with traceback for server errors
- **Execution Logging:** Handled by execute_command function

## Security Considerations
- **Command Injection:** No apparent input sanitization
- **Privilege Escalation:** Commands executed with server privileges
- **Resource Limits:** Relies on execute_command timeout handling

## Use Cases and Applications

#### Development and Testing
- **Command Testing:** Test shell commands via API
- **Automation:** Automate command execution through API calls
- **Integration Testing:** Test command integration in applications

#### Operations and Monitoring
- **Remote Execution:** Execute commands remotely via API
- **System Administration:** Perform system administration tasks
- **Monitoring:** Execute monitoring commands and collect results

#### Security Testing
- **Tool Execution:** Execute security tools via API
- **Payload Testing:** Test command payloads and responses
- **Automation:** Automate security testing workflows

## Testing & Validation
- Command execution accuracy testing
- Parameter validation verification
- Error handling behavior validation
- Cache integration functionality testing

## Code Reproduction
```python
@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request with enhanced logging"""
    try:
        params = request.json
        command = params.get("command", "")
        use_cache = params.get("use_cache", True)
        
        if not command:
            logger.warning("⚠️  Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command, use_cache=use_cache)
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
