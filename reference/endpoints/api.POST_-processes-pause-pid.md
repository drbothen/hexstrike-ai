---
title: POST /api/processes/pause/<int:pid>
group: api
handler: pause_process
module: __main__
line_range: [7425, 7450]
discovered_in_chunk: 7
---

# POST /api/processes/pause/<int:pid>

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Pause a running process by PID

## Complete Signature & Definition
```python
@app.route("/api/processes/pause/<int:pid>", methods=["POST"])
def pause_process(pid):
    """Pause a running process by PID with enhanced logging"""
```

## Purpose & Behavior
Process control endpoint providing:
- **Process Pausing:** Pause running processes by sending SIGSTOP signal
- **State Management:** Track process state changes
- **Safety Checks:** Validate process ownership and permissions
- **Enhanced Logging:** Detailed logging of process control operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/processes/pause/<int:pid>
- **Content-Type:** application/json

### Request Body
```json
{
    "force": boolean,                 // Optional: Force pause (default: false)
    "timeout": integer,               // Optional: Operation timeout (default: 30)
    "reason": "string"                // Optional: Reason for pausing
}
```

### Parameters
- **pid:** Process ID to pause (required, from URL path)
- **force:** Force pause flag (optional, default: false)
- **timeout:** Operation timeout in seconds (optional, default: 30)
- **reason:** Reason for pausing (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "process_id": 1234,
    "action": "pause",
    "process_info": {
        "pid": 1234,
        "name": "python3",
        "status": "stopped",
        "previous_status": "running",
        "cpu_percent": 0.0,
        "memory_percent": 2.5,
        "create_time": "2024-01-01T11:30:00Z",
        "pause_time": "2024-01-01T12:00:00Z"
    },
    "operation_details": {
        "signal_sent": "SIGSTOP",
        "force_used": false,
        "timeout": 30,
        "reason": "User requested pause",
        "operation_time": 0.1
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Process Not Found (404 Not Found)
```json
{
    "error": "Process with PID 1234 not found"
}
```

#### Permission Denied (403 Forbidden)
```json
{
    "error": "Permission denied: Cannot pause process 1234"
}
```

#### Process Already Paused (400 Bad Request)
```json
{
    "error": "Process 1234 is already paused"
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
params = request.json or {}
force = params.get("force", False)
timeout = params.get("timeout", 30)
reason = params.get("reason", "User requested pause")

# Validate PID
if not isinstance(pid, int) or pid <= 0:
    return jsonify({"error": "Invalid process ID"}), 400
```

### Process Control Logic
```python
try:
    # Check if process exists
    if not psutil.pid_exists(pid):
        return jsonify({"error": f"Process with PID {pid} not found"}), 404
    
    # Get process information
    process = psutil.Process(pid)
    
    # Check if process is already paused
    if process.status() == psutil.STATUS_STOPPED:
        return jsonify({"error": f"Process {pid} is already paused"}), 400
    
    # Store previous status
    previous_status = process.status()
    
    # Send SIGSTOP signal to pause the process
    process.suspend()
    
    # Wait for status change with timeout
    start_time = time.time()
    while time.time() - start_time < timeout:
        if process.status() == psutil.STATUS_STOPPED:
            break
        time.sleep(0.1)
    
    # Verify process is paused
    if process.status() != psutil.STATUS_STOPPED:
        return jsonify({"error": f"Failed to pause process {pid}"}), 500
        
except psutil.NoSuchProcess:
    return jsonify({"error": f"Process with PID {pid} not found"}), 404
except psutil.AccessDenied:
    return jsonify({"error": f"Permission denied: Cannot pause process {pid}"}), 403
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Process control access required
- **Process Ownership:** May require process ownership or elevated privileges

## Error Handling
- **Process Not Found:** 404 error for non-existent processes
- **Permission Denied:** 403 error for insufficient privileges
- **Already Paused:** 400 error for already paused processes
- **Operation Timeout:** Timeout handling for pause operation
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Process Ownership:** Validate process ownership before pausing
- **Privilege Escalation:** Prevent unauthorized process control
- **System Stability:** Avoid pausing critical system processes
- **Audit Logging:** Log all process control operations

## Use Cases and Applications

#### Process Management
- **Resource Control:** Control resource usage by pausing processes
- **Debugging:** Pause processes for debugging and analysis
- **System Maintenance:** Pause processes during maintenance operations

#### Security Operations
- **Incident Response:** Pause suspicious processes during investigation
- **Malware Analysis:** Pause processes for forensic analysis
- **System Protection:** Pause processes that may be causing issues

## Testing & Validation
- Process existence validation testing
- Permission checking accuracy testing
- Signal delivery verification testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/processes/pause/<int:pid>", methods=["POST"])
def pause_process(pid):
    """Pause a running process by PID with enhanced logging"""
    try:
        params = request.json or {}
        force = params.get("force", False)
        timeout = params.get("timeout", 30)
        reason = params.get("reason", "User requested pause")
        
        # Validate PID
        if not isinstance(pid, int) or pid <= 0:
            return jsonify({"error": "Invalid process ID"}), 400
        
        logger.info(f"🔄 Attempting to pause process {pid} | Reason: {reason}")
        
        # Check if process exists
        if not psutil.pid_exists(pid):
            return jsonify({"error": f"Process with PID {pid} not found"}), 404
        
        # Get process information
        process = psutil.Process(pid)
        
        # Check if process is already paused
        if process.status() == psutil.STATUS_STOPPED:
            return jsonify({"error": f"Process {pid} is already paused"}), 400
        
        # Store previous status and info
        previous_status = process.status()
        process_info = {
            "pid": pid,
            "name": process.name(),
            "previous_status": previous_status,
            "cpu_percent": process.cpu_percent(),
            "memory_percent": process.memory_percent(),
            "create_time": datetime.fromtimestamp(process.create_time()).isoformat()
        }
        
        start_time = time.time()
        
        # Send SIGSTOP signal to pause the process
        process.suspend()
        
        # Wait for status change with timeout
        operation_start = time.time()
        while time.time() - operation_start < timeout:
            if process.status() == psutil.STATUS_STOPPED:
                break
            time.sleep(0.1)
        
        operation_time = time.time() - start_time
        
        # Verify process is paused
        if process.status() != psutil.STATUS_STOPPED:
            return jsonify({"error": f"Failed to pause process {pid}"}), 500
        
        # Update process info
        process_info.update({
            "status": "stopped",
            "pause_time": datetime.now().isoformat()
        })
        
        operation_details = {
            "signal_sent": "SIGSTOP",
            "force_used": force,
            "timeout": timeout,
            "reason": reason,
            "operation_time": operation_time
        }
        
        logger.info(f"🔄 Process {pid} paused successfully in {operation_time:.2f}s")
        
        return jsonify({
            "success": True,
            "process_id": pid,
            "action": "pause",
            "process_info": process_info,
            "operation_details": operation_details,
            "timestamp": datetime.now().isoformat()
        })
        
    except psutil.NoSuchProcess:
        logger.error(f"💥 Process {pid} not found")
        return jsonify({"error": f"Process with PID {pid} not found"}), 404
    except psutil.AccessDenied:
        logger.error(f"💥 Permission denied for process {pid}")
        return jsonify({"error": f"Permission denied: Cannot pause process {pid}"}), 403
    except Exception as e:
        logger.error(f"💥 Error pausing process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
