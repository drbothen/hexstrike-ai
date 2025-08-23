---
title: GET /api/process/get-task-result/<task_id>
group: api
handler: get_task_result
module: __main__
line_range: [7529, 7554]
discovered_in_chunk: 7
---

# GET /api/process/get-task-result/<task_id>

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get the result of an asynchronous task

## Complete Signature & Definition
```python
@app.route("/api/process/get-task-result/<task_id>", methods=["GET"])
def get_task_result(task_id):
    """Get the result of an asynchronous task with enhanced logging"""
```

## Purpose & Behavior
Async task result retrieval endpoint providing:
- **Result Retrieval:** Get results of completed async tasks
- **Status Tracking:** Track task execution status and progress
- **Error Reporting:** Report task execution errors and failures
- **Enhanced Logging:** Detailed logging of result retrieval operations

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/get-task-result/<task_id>
- **Content-Type:** application/json

### Request Body
No request body required for GET request.

### Parameters
- **task_id:** Task ID to retrieve results for (required, from URL path)

## Response

### Success Response (200 OK) - Completed Task
```json
{
    "success": true,
    "task_id": "task_1234567890",
    "status": "completed",
    "task_info": {
        "command": "nmap -sV 192.168.1.1",
        "priority": "normal",
        "timeout": 300,
        "created_at": "2024-01-01T12:00:00Z",
        "started_at": "2024-01-01T12:00:05Z",
        "completed_at": "2024-01-01T12:02:15Z",
        "execution_time": 130.5
    },
    "result": {
        "return_code": 0,
        "stdout": "Starting Nmap 7.80...\nNmap scan report for 192.168.1.1\n",
        "stderr": "",
        "output_file": "/tmp/nmap_output_1234567890.txt",
        "parsed_results": {
            "hosts_scanned": 1,
            "ports_found": 5,
            "services_detected": ["ssh", "http", "https"]
        }
    },
    "metadata": {
        "user": "admin",
        "session": "123"
    },
    "timestamp": "2024-01-01T12:02:15Z"
}
```

### Success Response (200 OK) - Running Task
```json
{
    "success": true,
    "task_id": "task_1234567890",
    "status": "running",
    "task_info": {
        "command": "nmap -sV 192.168.1.1",
        "priority": "normal",
        "timeout": 300,
        "created_at": "2024-01-01T12:00:00Z",
        "started_at": "2024-01-01T12:00:05Z",
        "estimated_completion": "2024-01-01T12:02:00Z"
    },
    "progress": {
        "percentage": 65,
        "current_step": "Port scanning",
        "elapsed_time": 75.2,
        "estimated_remaining": 54.8
    },
    "partial_output": "Starting Nmap 7.80...\nScanning 192.168.1.1...\n",
    "timestamp": "2024-01-01T12:01:20Z"
}
```

### Error Responses

#### Task Not Found (404 Not Found)
```json
{
    "error": "Task with ID task_1234567890 not found"
}
```

#### Task Failed (200 OK)
```json
{
    "success": false,
    "task_id": "task_1234567890",
    "status": "failed",
    "task_info": {
        "command": "invalid_command",
        "created_at": "2024-01-01T12:00:00Z",
        "started_at": "2024-01-01T12:00:05Z",
        "failed_at": "2024-01-01T12:00:10Z"
    },
    "error": {
        "type": "CommandNotFound",
        "message": "Command 'invalid_command' not found",
        "return_code": 127,
        "stderr": "bash: invalid_command: command not found"
    },
    "timestamp": "2024-01-01T12:00:10Z"
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
if not task_id:
    return jsonify({"error": "Task ID is required"}), 400

# Validate task ID format
if not task_id.startswith("task_"):
    return jsonify({"error": "Invalid task ID format"}), 400
```

### Task Retrieval Logic
```python
try:
    # Get task from process manager
    task = enhanced_process_manager.get_task(task_id)
    
    if not task:
        return jsonify({"error": f"Task with ID {task_id} not found"}), 404
    
    # Build response based on task status
    response_data = {
        "success": task["status"] != "failed",
        "task_id": task_id,
        "status": task["status"],
        "task_info": {
            "command": f"{task['command']} {' '.join(task.get('args', []))}",
            "priority": task["priority"],
            "timeout": task["timeout"],
            "created_at": task["created_at"],
            "started_at": task.get("started_at"),
            "completed_at": task.get("completed_at")
        },
        "timestamp": datetime.now().isoformat()
    }
    
    # Add status-specific data
    if task["status"] == "completed":
        response_data["result"] = task["result"]
        response_data["task_info"]["execution_time"] = task.get("execution_time")
    elif task["status"] == "running":
        response_data["progress"] = task.get("progress", {})
        response_data["partial_output"] = task.get("partial_output", "")
    elif task["status"] == "failed":
        response_data["error"] = task["error"]
    
    # Add metadata if present
    if task.get("metadata"):
        response_data["metadata"] = task["metadata"]
    
    return jsonify(response_data)
    
except Exception as e:
    logger.error(f"💥 Error retrieving task {task_id}: {str(e)}")
    return jsonify({"error": f"Server error: {str(e)}"}), 500
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Task result access required
- **Task Ownership:** May require task ownership validation

## Error Handling
- **Task Not Found:** 404 error for non-existent tasks
- **Invalid Task ID:** 400 error for malformed task IDs
- **Access Denied:** Handle unauthorized task access
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Task Ownership:** Validate task ownership before returning results
- **Information Disclosure:** Limit sensitive information in task results
- **Result Sanitization:** Sanitize task output for security
- **Access Control:** Implement proper access controls for task results

## Use Cases and Applications

#### Task Monitoring
- **Progress Tracking:** Track progress of long-running tasks
- **Result Retrieval:** Retrieve results of completed tasks
- **Error Diagnosis:** Diagnose failed task execution

#### Workflow Management
- **Pipeline Coordination:** Coordinate multi-step workflows
- **Dependency Management:** Manage task dependencies
- **Status Reporting:** Report task status to external systems

## Testing & Validation
- Task ID validation testing
- Status tracking accuracy testing
- Result retrieval verification testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/process/get-task-result/<task_id>", methods=["GET"])
def get_task_result(task_id):
    """Get the result of an asynchronous task with enhanced logging"""
    try:
        if not task_id:
            return jsonify({"error": "Task ID is required"}), 400
        
        # Validate task ID format
        if not task_id.startswith("task_"):
            return jsonify({"error": "Invalid task ID format"}), 400
        
        logger.info(f"🔍 Retrieving task result for {task_id}")
        
        # Get task from process manager
        task = enhanced_process_manager.get_task(task_id)
        
        if not task:
            return jsonify({"error": f"Task with ID {task_id} not found"}), 404
        
        # Build response based on task status
        response_data = {
            "success": task["status"] != "failed",
            "task_id": task_id,
            "status": task["status"],
            "task_info": {
                "command": f"{task['command']} {' '.join(task.get('args', []))}",
                "priority": task["priority"],
                "timeout": task["timeout"],
                "created_at": task["created_at"],
                "started_at": task.get("started_at"),
                "completed_at": task.get("completed_at")
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Add status-specific data
        if task["status"] == "completed":
            response_data["result"] = task["result"]
            response_data["task_info"]["execution_time"] = task.get("execution_time")
        elif task["status"] == "running":
            response_data["progress"] = task.get("progress", {})
            response_data["partial_output"] = task.get("partial_output", "")
            response_data["task_info"]["estimated_completion"] = task.get("estimated_completion")
        elif task["status"] == "failed":
            response_data["error"] = task["error"]
            response_data["task_info"]["failed_at"] = task.get("failed_at")
        
        # Add metadata if present
        if task.get("metadata"):
            response_data["metadata"] = task["metadata"]
        
        logger.info(f"🔍 Task {task_id} status: {task['status']}")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"💥 Error retrieving task {task_id}: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
