---
title: GET /api/process/get-task-result/<task_id>
group: api
handler: get_async_task_result
module: __main__
line_range: [14842, 14861]
discovered_in_chunk: 15
---

# GET /api/process/get-task-result/<task_id>

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get result of asynchronous task

## Complete Signature & Definition
```python
@app.route("/api/process/get-task-result/<task_id>", methods=["GET"])
def get_async_task_result(task_id):
    """Get result of asynchronous task"""
```

## Purpose & Behavior
Task result retrieval endpoint providing:
- **Result Retrieval:** Get execution results for completed tasks
- **Status Checking:** Check current status of running or completed tasks
- **Error Information:** Retrieve error details for failed tasks
- **Metadata Access:** Access task execution metadata and timing information

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/get-task-result/<task_id>
- **Parameters:** task_id in URL path

### URL Parameters
- **task_id:** Unique identifier of the task to retrieve results for (required)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "task_id": "task_12345678",
    "result": {
        "status": "completed",
        "exit_code": 0,
        "stdout": "Command output here...",
        "stderr": "",
        "execution_time": 45.2,
        "start_time": "2024-01-01T12:00:00Z",
        "end_time": "2024-01-01T12:00:45Z",
        "command": "nmap -sS target.com",
        "context": {},
        "success": true
    },
    "timestamp": "2024-01-01T12:01:00Z"
}
```

### Task Not Found (404 Not Found)
```json
{
    "error": "Task not found"
}
```

### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Task Result Retrieval
```python
# From line 14845: Get result of asynchronous task
result = enhanced_process_manager.get_task_result(task_id)

if result["status"] == "not_found":
    return jsonify({"error": "Task not found"}), 404

logger.info(f"📋 Task result retrieved | Task ID: {task_id} | Status: {result['status']}")
return jsonify({
    "success": True,
    "task_id": task_id,
    "result": result,
    "timestamp": datetime.now().isoformat()
})
```

## Key Features

### Result Status Types
- **pending:** Task is queued but not yet started
- **running:** Task is currently executing
- **completed:** Task completed successfully
- **failed:** Task failed with error
- **timeout:** Task exceeded timeout limit
- **cancelled:** Task was cancelled before completion

### Comprehensive Result Data
- **Execution Output:** Complete stdout and stderr from command execution
- **Timing Information:** Start time, end time, and total execution duration
- **Exit Status:** Command exit code and success/failure status
- **Context Data:** Original execution context and parameters
- **Error Details:** Detailed error information for failed tasks

## AuthN/AuthZ
- **Process Management:** Task result access capabilities
- **Asynchronous Operations:** Task tracking and monitoring access

## Observability
- **Result Logging:** "📋 Task result retrieved | Task ID: {task_id} | Status: {status}"
- **Error Logging:** "💥 Error getting task result: {error}"

## Testing & Validation
- Task ID parameter validation
- Result retrieval accuracy testing
- Status reporting correctness verification
- Error handling for non-existent tasks
- Performance testing for large result sets

## Code Reproduction
Complete Flask endpoint implementation for asynchronous task result retrieval with comprehensive status reporting, error handling, and integration with enhanced process management system. Essential for monitoring and collecting results from asynchronous security tool execution.
