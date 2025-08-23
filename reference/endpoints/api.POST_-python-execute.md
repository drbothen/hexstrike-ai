---
title: POST /api/python/execute
group: api
handler: execute_python_script
module: __main__
line_range: [12629, 12670]
discovered_in_chunk: 12
---

# POST /api/python/execute

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute a Python script in a virtual environment

## Complete Signature & Definition
```python
@app.route("/api/python/execute", methods=["POST"])
def execute_python_script():
    """Execute a Python script in a virtual environment"""
```

## Purpose & Behavior
Python script execution endpoint providing:
- **Script Execution:** Execute Python scripts in isolated environments
- **Virtual Environment Support:** Run scripts in specific virtual environments
- **Output Capture:** Capture script output and errors
- **Enhanced Logging:** Detailed logging of execution progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/python/execute
- **Content-Type:** application/json

### Request Body
```json
{
    "script": "string",               // Required: Python script code or file path
    "environment": "string",          // Optional: Virtual environment name (default: default)
    "script_file": "string",          // Optional: Script file path (alternative to script)
    "arguments": ["string"],          // Optional: Script arguments
    "timeout": integer,               // Optional: Execution timeout (default: 300)
    "capture_output": boolean,        // Optional: Capture output (default: true)
    "working_directory": "string",    // Optional: Working directory
    "environment_vars": "object",     // Optional: Environment variables
    "additional_args": "string"       // Optional: Additional python arguments
}
```

### Parameters
- **script:** Python script code (required if script_file not provided)
- **environment:** Virtual environment name (optional, default: "default")
- **script_file:** Script file path (optional, alternative to script)
- **arguments:** Script arguments (optional) - ["--verbose", "--output", "result.txt"]
- **timeout:** Execution timeout in seconds (optional, default: 300)
- **capture_output:** Capture output flag (optional, default: true)
- **working_directory:** Working directory (optional)
- **environment_vars:** Environment variables (optional) - {"DEBUG": "1"}
- **additional_args:** Additional python arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "python script.py --verbose",
    "execution_results": {
        "environment": "default",
        "script_executed": "script.py",
        "return_code": 0,
        "stdout": "Script executed successfully\nResult: 42\n",
        "stderr": "",
        "execution_time": 2.5,
        "working_directory": "/tmp/python_execution",
        "environment_vars_set": ["DEBUG"],
        "memory_usage": "15.2MB",
        "cpu_time": 1.8
    },
    "raw_output": "Script executed successfully\nResult: 42\n",
    "execution_time": 2.5,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Script (400 Bad Request)
```json
{
    "error": "Script parameter or script_file is required"
}
```

#### Execution Failed (500 Internal Server Error)
```json
{
    "error": "Script execution failed: {error_message}"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
script = params.get("script", "")
environment = params.get("environment", "default")
script_file = params.get("script_file", "")
arguments = params.get("arguments", [])
timeout = params.get("timeout", 300)
capture_output = params.get("capture_output", True)
working_directory = params.get("working_directory", "")
environment_vars = params.get("environment_vars", {})
additional_args = params.get("additional_args", "")

if not script and not script_file:
    return jsonify({"error": "Script parameter or script_file is required"}), 400
```

### Script Execution
```python
# Use environment manager to execute script
result = env_manager.execute_script(
    script=script,
    script_file=script_file,
    environment=environment,
    arguments=arguments,
    timeout=timeout,
    capture_output=capture_output,
    working_directory=working_directory,
    environment_vars=environment_vars,
    additional_args=additional_args
)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Python script execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing script or script_file
- **Execution Errors:** Handled by PythonEnvironmentManager
- **Timeout Errors:** Script execution timeout handling
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Script Validation:** Validate scripts to prevent malicious code execution
- **Environment Isolation:** Use virtual environments for script isolation
- **Resource Limits:** Implement resource limits for script execution
- **Timeout Protection:** Use timeouts to prevent infinite loops

## Use Cases and Applications

#### Security Testing Scripts
- **Custom Tools:** Execute custom security testing scripts
- **Automation Scripts:** Run automation scripts for security testing
- **Data Processing:** Process security testing data with Python scripts

#### Development and Testing
- **Script Testing:** Test Python scripts in isolated environments
- **Proof of Concepts:** Execute proof of concept scripts
- **Data Analysis:** Analyze security testing results with Python

## Testing & Validation
- Script execution accuracy testing
- Parameter validation verification
- Environment isolation testing
- Timeout handling testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/python/execute", methods=["POST"])
def execute_python_script():
    """Execute a Python script in a virtual environment"""
    try:
        params = request.json
        script = params.get("script", "")
        environment = params.get("environment", "default")
        script_file = params.get("script_file", "")
        arguments = params.get("arguments", [])
        timeout = params.get("timeout", 300)
        capture_output = params.get("capture_output", True)
        working_directory = params.get("working_directory", "")
        environment_vars = params.get("environment_vars", {})
        additional_args = params.get("additional_args", "")
        
        if not script and not script_file:
            return jsonify({"error": "Script parameter or script_file is required"}), 400
        
        logger.info(f"🐍 Executing Python script in environment: {environment}")
        
        start_time = time.time()
        result = env_manager.execute_script(
            script=script,
            script_file=script_file,
            environment=environment,
            arguments=arguments,
            timeout=timeout,
            capture_output=capture_output,
            working_directory=working_directory,
            environment_vars=environment_vars,
            additional_args=additional_args
        )
        execution_time = time.time() - start_time
        
        logger.info(f"🐍 Script execution completed in {execution_time:.2f}s | Return code: {result.get('return_code', 'unknown')}")
        
        return jsonify({
            "success": True,
            "command": result.get("command", ""),
            "execution_results": result.get("results", {}),
            "raw_output": result.get("output", ""),
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error executing Python script: {str(e)}")
        return jsonify({
            "error": f"Script execution failed: {str(e)}"
        }), 500
```
