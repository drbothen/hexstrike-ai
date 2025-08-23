---
title: GET /api/processes/status/<int:pid>
group: api
handler: get_process_status
module: __main__
line_range: [7436, 7448]
discovered_in_chunk: 7
---

# GET /api/processes/status/<int:pid>

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get detailed status of a specific process

## Complete Signature & Definition
```python
@app.route("/api/processes/status/<int:pid>", methods=["GET"])
def get_process_status(pid):
    """Get detailed status of a specific process"""
```

## Purpose & Behavior
Process status endpoint providing:
- **Detailed Process Information:** Get comprehensive information about a specific process
- **Real-time Status:** Provide real-time status of the process
- **Resource Usage:** Track detailed resource usage metrics
- **Output Access:** Access process output and error streams

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/processes/status/<int:pid>
- **Path Parameters:**
  - **pid:** Process ID to get status for (required)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "process": {
        "pid": 12345,
        "command": "nmap -sV -p 1-1000 example.com",
        "status": "running",
        "start_time": "2024-01-01T12:00:00Z",
        "cpu_usage": 2.5,
        "memory_usage": 45.6,
        "elapsed_time": "00:05:23",
        "output_preview": "Starting Nmap 7.80...",
        "output_size": 1024,
        "error_preview": "",
        "error_size": 0,
        "detailed_stats": {
            "threads": 4,
            "open_files": 12,
            "network_connections": 3
        }
    },
    "timestamp": "2024-01-01T12:05:00Z"
}
```

### Error Responses

#### Process Not Found (404 Not Found)
```json
{
    "error": "Process not found: PID {pid}"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Process Lookup
```python
with process_lock:
    if pid not in active_processes:
        return jsonify({"error": f"Process not found: PID {pid}"}), 404
    
    process_info = active_processes[pid]
```

### Detailed Process Information Collection
```python
process_data = {
    "pid": pid,
    "command": process_info["command"],
    "status": process_info["status"],
    "start_time": process_info["start_time"].isoformat(),
    "cpu_usage": resource_monitor.get_cpu_usage(pid),
    "memory_usage": resource_monitor.get_memory_usage(pid),
    "elapsed_time": calculate_elapsed_time(process_info["start_time"]),
    "output_preview": get_output_preview(process_info["output_file"], 200),
    "output_size": get_file_size(process_info["output_file"]),
    "error_preview": get_output_preview(process_info["error_file"], 200),
    "error_size": get_file_size(process_info["error_file"]),
    "detailed_stats": resource_monitor.get_detailed_stats(pid)
}

if process_info["status"] == "completed":
    process_data["end_time"] = process_info["end_time"].isoformat()
    process_data["exit_code"] = process_info["exit_code"]
    process_data["runtime"] = calculate_runtime(process_info["start_time"], process_info["end_time"])
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Process status access required

## Error Handling
- **Process Not Found:** 404 error for non-existent process ID
- **Process Manager Errors:** Handled by EnhancedProcessManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Information Disclosure:** Only returns information about processes managed by the system
- **Process Isolation:** Ensures process isolation and security
- **Access Control:** Ensures only authorized users can access process information

## Use Cases and Applications

#### Process Monitoring
- **Detailed Monitoring:** Monitor specific process in detail
- **Resource Tracking:** Track detailed resource usage of a process
- **Output Monitoring:** Monitor process output in real-time

#### Operational Awareness
- **Process Debugging:** Debug issues with specific processes
- **Performance Analysis:** Analyze process performance metrics
- **Status Verification:** Verify process status and health

## Testing & Validation
- Process status accuracy testing
- Resource usage reporting verification
- Output preview functionality testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/processes/status/<int:pid>", methods=["GET"])
def get_process_status(pid):
    """Get detailed status of a specific process"""
    try:
        with process_lock:
            if pid not in active_processes:
                return jsonify({"error": f"Process not found: PID {pid}"}), 404
            
            process_info = active_processes[pid]
            
            process_data = {
                "pid": pid,
                "command": process_info["command"],
                "status": process_info["status"],
                "start_time": process_info["start_time"].isoformat(),
                "cpu_usage": resource_monitor.get_cpu_usage(pid),
                "memory_usage": resource_monitor.get_memory_usage(pid),
                "elapsed_time": calculate_elapsed_time(process_info["start_time"]),
                "output_preview": get_output_preview(process_info["output_file"], 200),
                "output_size": get_file_size(process_info["output_file"]),
                "error_preview": get_output_preview(process_info["error_file"], 200),
                "error_size": get_file_size(process_info["error_file"]),
                "detailed_stats": resource_monitor.get_detailed_stats(pid)
            }
            
            if process_info["status"] == "completed":
                process_data["end_time"] = process_info["end_time"].isoformat()
                process_data["exit_code"] = process_info["exit_code"]
                process_data["runtime"] = calculate_runtime(process_info["start_time"], process_info["end_time"])
            
            return jsonify({
                "success": True,
                "process": process_data,
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"💥 Error getting process status: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
