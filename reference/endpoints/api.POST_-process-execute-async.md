---
title: POST /api/process/execute-async
group: api
handler: execute_async_process
module: __main__
line_range: [7503, 7528]
discovered_in_chunk: 7
---

# POST /api/process/execute-async

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute a command asynchronously and return task ID

## Complete Signature & Definition
```python
@app.route("/api/process/execute-async", methods=["POST"])
def execute_async_process():
    """Execute a command asynchronously and return task ID with enhanced logging"""
```

## Purpose & Behavior
Asynchronous process execution endpoint providing:
- **Async Execution:** Execute commands asynchronously without blocking
- **Task Management:** Return task ID for tracking execution status
- **Resource Management:** Manage system resources during async execution
- **Enhanced Logging:** Detailed logging of async execution operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/process/execute-async
- **Content-Type:** application/json

### Request Body
```json
{
    "command": "string",              // Required: Command to execute
    "args": ["string"],               // Optional: Command arguments
    "working_dir": "string",          // Optional: Working directory
    "environment": "object",          // Optional: Environment variables
    "timeout": integer,               // Optional: Execution timeout (default: 300)
    "priority": "string",             // Optional: Task priority (default: normal)
    "callback_url": "string",         // Optional: Callback URL for completion
    "metadata": "object"              // Optional: Additional metadata
}
```

### Parameters
- **command:** Command to execute (required)
- **args:** Command arguments (optional) - ["--verbose", "--output", "result.txt"]
- **working_dir:** Working directory (optional)
- **environment:** Environment variables (optional) - {"DEBUG": "1"}
- **timeout:** Execution timeout in seconds (optional, default: 300)
- **priority:** Task priority (optional, default: "normal") - "low", "normal", "high"
- **callback_url:** Callback URL for completion notification (optional)
- **metadata:** Additional metadata (optional) - {"user": "admin", "session": "123"}

## Response

### Success Response (202 Accepted)
```json
{
    "success": true,
    "task_id": "task_1234567890",
    "status": "queued",
    "task_info": {
        "command": "nmap -sV 192.168.1.1",
        "priority": "normal",
        "timeout": 300,
        "created_at": "2024-01-01T12:00:00Z",
        "estimated_duration": 120,
        "queue_position": 3
    },
    "tracking": {
        "status_url": "/api/process/get-task-result/task_1234567890",
        "callback_url": "https://example.com/callback",
        "progress_updates": true
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Command (400 Bad Request)
```json
{
    "error": "Command parameter is required"
}
```

#### Invalid Priority (400 Bad Request)
```json
{
    "error": "Invalid priority. Must be one of: low, normal, high"
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
command = params.get("command", "")
args = params.get("args", [])
working_dir = params.get("working_dir", "")
environment = params.get("environment", {})
timeout = params.get("timeout", 300)
priority = params.get("priority", "normal")
callback_url = params.get("callback_url", "")
metadata = params.get("metadata", {})

if not command:
    return jsonify({"error": "Command parameter is required"}), 400

if priority not in ["low", "normal", "high"]:
    return jsonify({"error": "Invalid priority. Must be one of: low, normal, high"}), 400
```

### Async Task Creation
```python
# Generate unique task ID
task_id = f"task_{int(time.time() * 1000000)}"

# Create task object
task = {
    "id": task_id,
    "command": command,
    "args": args,
    "working_dir": working_dir,
    "environment": environment,
    "timeout": timeout,
    "priority": priority,
    "callback_url": callback_url,
    "metadata": metadata,
    "status": "queued",
    "created_at": datetime.now().isoformat(),
    "started_at": None,
    "completed_at": None,
    "result": None,
    "error": None
}

# Submit to process pool
enhanced_process_manager.submit_async_task(task)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Async process execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing command
- **Invalid Parameters:** 400 error for invalid priority values
- **Task Creation Errors:** Handle errors during task creation
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Command Validation:** Validate commands to prevent command injection
- **Resource Limits:** Implement resource limits for async tasks
- **Task Isolation:** Ensure task isolation and security
- **Audit Logging:** Log all async task creation and execution

## Use Cases and Applications

#### Long-Running Operations
- **Security Scans:** Execute long-running security scans asynchronously
- **Data Processing:** Process large datasets without blocking
- **System Maintenance:** Perform maintenance tasks asynchronously

#### Batch Processing
- **Bulk Operations:** Execute bulk operations in background
- **Scheduled Tasks:** Schedule tasks for later execution
- **Workflow Automation:** Automate complex workflows

## Testing & Validation
- Command validation accuracy testing
- Task creation and queuing testing
- Priority handling verification testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/process/execute-async", methods=["POST"])
def execute_async_process():
    """Execute a command asynchronously and return task ID with enhanced logging"""
    try:
        params = request.json
        command = params.get("command", "")
        args = params.get("args", [])
        working_dir = params.get("working_dir", "")
        environment = params.get("environment", {})
        timeout = params.get("timeout", 300)
        priority = params.get("priority", "normal")
        callback_url = params.get("callback_url", "")
        metadata = params.get("metadata", {})
        
        if not command:
            return jsonify({"error": "Command parameter is required"}), 400
        
        if priority not in ["low", "normal", "high"]:
            return jsonify({"error": "Invalid priority. Must be one of: low, normal, high"}), 400
        
        # Generate unique task ID
        task_id = f"task_{int(time.time() * 1000000)}"
        
        logger.info(f"🔄 Creating async task {task_id} | Command: {command}")
        
        # Create task object
        task = {
            "id": task_id,
            "command": command,
            "args": args,
            "working_dir": working_dir,
            "environment": environment,
            "timeout": timeout,
            "priority": priority,
            "callback_url": callback_url,
            "metadata": metadata,
            "status": "queued",
            "created_at": datetime.now().isoformat(),
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None
        }
        
        # Submit to process pool
        queue_position = enhanced_process_manager.submit_async_task(task)
        
        task_info = {
            "command": f"{command} {' '.join(args)}" if args else command,
            "priority": priority,
            "timeout": timeout,
            "created_at": task["created_at"],
            "estimated_duration": enhanced_process_manager.estimate_duration(command),
            "queue_position": queue_position
        }
        
        tracking = {
            "status_url": f"/api/process/get-task-result/{task_id}",
            "callback_url": callback_url,
            "progress_updates": True
        }
        
        logger.info(f"🔄 Async task {task_id} created successfully | Priority: {priority}")
        
        return jsonify({
            "success": True,
            "task_id": task_id,
            "status": "queued",
            "task_info": task_info,
            "tracking": tracking,
            "timestamp": datetime.now().isoformat()
        }), 202
        
    except Exception as e:
        logger.error(f"💥 Error creating async task: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
