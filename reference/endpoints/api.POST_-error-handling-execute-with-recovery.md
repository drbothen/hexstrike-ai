---
title: POST /api/error-handling/execute-with-recovery
group: api
handler: execute_with_recovery_endpoint
module: __main__
line_range: [15253, 15284]
discovered_in_chunk: 15
---

# POST /api/error-handling/execute-with-recovery

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute a command with intelligent error handling and recovery

## Complete Signature & Definition
```python
@app.route("/api/error-handling/execute-with-recovery", methods=["POST"])
def execute_with_recovery_endpoint():
    """Execute a command with intelligent error handling and recovery"""
```

## Purpose & Behavior
Command execution with recovery endpoint providing:
- **Intelligent Execution:** Execute commands with intelligent error handling
- **Automatic Recovery:** Automatically recover from execution failures
- **Fallback Strategies:** Apply fallback strategies when primary execution fails
- **Enhanced Logging:** Detailed logging of execution and recovery operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/error-handling/execute-with-recovery
- **Content-Type:** application/json

### Request Body
```json
{
    "command_config": {
        "command": "string",          // Required: Command to execute
        "arguments": ["string"],      // Optional: Command arguments
        "working_directory": "string", // Optional: Working directory
        "environment": "object",      // Optional: Environment variables
        "timeout": integer            // Optional: Command timeout (default: 300)
    },
    "recovery_options": {
        "max_retries": integer,       // Optional: Maximum retry attempts (default: 3)
        "retry_strategy": "string",   // Optional: Retry strategy (default: exponential_backoff)
        "fallback_enabled": boolean,  // Optional: Enable fallback tools (default: true)
        "recovery_timeout": integer,  // Optional: Recovery timeout (default: 600)
        "adaptive_parameters": boolean // Optional: Adapt parameters on retry (default: true)
    },
    "monitoring_config": {
        "track_performance": boolean, // Optional: Track performance metrics (default: true)
        "log_recovery_steps": boolean, // Optional: Log recovery steps (default: true)
        "alert_on_failure": boolean,  // Optional: Alert on failure (default: false)
        "save_diagnostics": boolean   // Optional: Save diagnostic data (default: true)
    }
}
```

### Parameters
- **command_config:** Command configuration (required)
  - **command:** Command to execute (required)
  - **arguments:** Command arguments (optional)
  - **working_directory:** Working directory (optional)
  - **environment:** Environment variables (optional)
  - **timeout:** Command timeout in seconds (optional, default: 300)
- **recovery_options:** Recovery configuration (optional)
- **monitoring_config:** Monitoring configuration (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "execution_info": {
        "command": "nmap -sV 192.168.1.1",
        "execution_id": "exec_1234567890",
        "total_execution_time": 45.7,
        "recovery_triggered": false,
        "fallback_used": false
    },
    "execution_result": {
        "return_code": 0,
        "stdout": "Starting Nmap 7.80...\nNmap scan report for 192.168.1.1\n",
        "stderr": "",
        "execution_time": 42.3,
        "output_size": 2048,
        "success": true
    },
    "recovery_details": {
        "recovery_attempts": 0,
        "recovery_strategies_used": [],
        "fallback_tools_tried": [],
        "parameter_adjustments": [],
        "total_recovery_time": 0
    },
    "performance_metrics": {
        "cpu_usage": 15.2,
        "memory_usage": 128.5,
        "network_usage": 45.8,
        "disk_io": 12.3,
        "efficiency_score": 0.92
    },
    "diagnostics": {
        "command_validation": "passed",
        "environment_check": "passed",
        "resource_availability": "sufficient",
        "network_connectivity": "stable",
        "potential_issues": []
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Success Response with Recovery (200 OK)
```json
{
    "success": true,
    "execution_info": {
        "command": "nuclei -t cves/ -u https://example.com",
        "execution_id": "exec_1234567891",
        "total_execution_time": 125.8,
        "recovery_triggered": true,
        "fallback_used": true
    },
    "execution_result": {
        "return_code": 0,
        "stdout": "Running nuclei scan...\nVulnerabilities found: 3\n",
        "stderr": "",
        "execution_time": 98.2,
        "output_size": 4096,
        "success": true
    },
    "recovery_details": {
        "recovery_attempts": 2,
        "recovery_strategies_used": ["parameter_adjustment", "fallback_tool"],
        "fallback_tools_tried": ["nikto"],
        "parameter_adjustments": [
            {
                "parameter": "rate_limit",
                "old_value": "150",
                "new_value": "50",
                "reason": "rate_limiting_detected"
            }
        ],
        "total_recovery_time": 27.6,
        "recovery_success": true
    },
    "performance_metrics": {
        "cpu_usage": 25.8,
        "memory_usage": 256.3,
        "network_usage": 78.2,
        "disk_io": 18.7,
        "efficiency_score": 0.78
    },
    "diagnostics": {
        "command_validation": "passed",
        "environment_check": "passed",
        "resource_availability": "sufficient",
        "network_connectivity": "intermittent",
        "potential_issues": ["rate_limiting_detected", "network_instability"]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Command (400 Bad Request)
```json
{
    "error": "Command is required"
}
```

#### Execution Failed (500 Internal Server Error)
```json
{
    "error": "Command execution failed after all recovery attempts"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
command_config = params.get("command_config", {})
recovery_options = params.get("recovery_options", {})
monitoring_config = params.get("monitoring_config", {})

command = command_config.get("command", "")
if not command:
    return jsonify({"error": "Command is required"}), 400
```

### Execution with Recovery Logic
```python
# Generate execution ID
execution_id = f"exec_{int(time.time() * 1000000)}"

# Use execute_command_with_recovery function
execution_request = {
    "command": command,
    "config": command_config,
    "recovery": recovery_options,
    "monitoring": monitoring_config,
    "execution_id": execution_id
}

# Execute command with recovery
execution_result = execute_command_with_recovery(execution_request)

# Collect performance metrics
performance_metrics = collect_execution_metrics(execution_result)

# Generate diagnostics
diagnostics = generate_execution_diagnostics(execution_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Command execution with recovery access required

## Error Handling
- **Missing Parameters:** 400 error for missing command
- **Execution Failures:** Handle command execution failures with recovery
- **Recovery Failures:** Handle recovery mechanism failures
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Command Validation:** Validate commands for security
- **Resource Limits:** Implement resource limits for execution
- **Access Control:** Control access to command execution capabilities
- **Audit Logging:** Log all command executions and recovery attempts

## Use Cases and Applications

#### Robust Command Execution
- **Reliable Operations:** Execute commands with automatic recovery
- **Fault Tolerance:** Provide fault tolerance for critical operations
- **Performance Optimization:** Optimize command execution performance

#### System Administration
- **Automated Recovery:** Automate recovery from execution failures
- **Diagnostic Collection:** Collect diagnostic data for troubleshooting
- **Performance Monitoring:** Monitor command execution performance

## Testing & Validation
- Parameter validation accuracy testing
- Command execution verification testing
- Recovery mechanism effectiveness testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/error-handling/execute-with-recovery", methods=["POST"])
def execute_with_recovery_endpoint():
    """Execute a command with intelligent error handling and recovery"""
    try:
        params = request.json
        command_config = params.get("command_config", {})
        recovery_options = params.get("recovery_options", {})
        monitoring_config = params.get("monitoring_config", {})
        
        command = command_config.get("command", "")
        if not command:
            return jsonify({"error": "Command is required"}), 400
        
        # Generate execution ID
        execution_id = f"exec_{int(time.time() * 1000000)}"
        
        logger.info(f"🔄 Executing command with recovery | ID: {execution_id} | Command: {command}")
        
        start_time = time.time()
        
        # Use execute_command_with_recovery function
        execution_request = {
            "command": command,
            "config": command_config,
            "recovery": recovery_options,
            "monitoring": monitoring_config,
            "execution_id": execution_id
        }
        
        # Execute command with recovery
        execution_result = execute_command_with_recovery(execution_request)
        
        # Collect performance metrics
        performance_metrics = collect_execution_metrics(execution_result)
        
        # Generate diagnostics
        diagnostics = generate_execution_diagnostics(execution_result)
        
        total_time = time.time() - start_time
        
        execution_info = {
            "command": command,
            "execution_id": execution_id,
            "total_execution_time": total_time,
            "recovery_triggered": execution_result.get("recovery_triggered", False),
            "fallback_used": execution_result.get("fallback_used", False)
        }
        
        logger.info(f"🔄 Command execution completed | ID: {execution_id} | Success: {execution_result.get('success', False)}")
        
        return jsonify({
            "success": execution_result.get("success", False),
            "execution_info": execution_info,
            "execution_result": execution_result["result"],
            "recovery_details": execution_result.get("recovery_details", {}),
            "performance_metrics": performance_metrics,
            "diagnostics": diagnostics,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error executing command with recovery: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
