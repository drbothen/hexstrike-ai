---
title: GET /api/processes/list
group: api
handler: list_processes
module: __main__
line_range: [7423, 7435]
discovered_in_chunk: 7
---

# GET /api/processes/list

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** List all running processes managed by the system

## Complete Signature & Definition
```python
@app.route("/api/processes/list", methods=["GET"])
def list_processes():
    """List all running processes managed by the system"""
```

## Purpose & Behavior
Process listing endpoint providing:
- **Process Enumeration:** List all running processes managed by the system
- **Process Details:** Provide detailed information about each process
- **Status Monitoring:** Monitor the status of running processes
- **Resource Usage:** Track resource usage of running processes

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/processes/list

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "processes": [
        {
            "pid": 12345,
            "command": "nmap -sV -p 1-1000 example.com",
            "status": "running",
            "start_time": "2024-01-01T12:00:00Z",
            "cpu_usage": 2.5,
            "memory_usage": 45.6,
            "elapsed_time": "00:05:23"
        },
        {
            "pid": 12346,
            "command": "gobuster dir -u https://example.com -w wordlist.txt",
            "status": "completed",
            "start_time": "2024-01-01T11:50:00Z",
            "end_time": "2024-01-01T11:55:00Z",
            "exit_code": 0,
            "elapsed_time": "00:05:00"
        }
    ],
    "total_count": 2,
    "running_count": 1,
    "completed_count": 1,
    "timestamp": "2024-01-01T12:05:00Z"
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Process Manager Integration
- **Manager Call:** enhanced_process_manager.list_processes()
- **Result Passthrough:** Direct return of process manager results
- **Process Filtering:** No filtering applied, returns all processes

### Process Information Collection
```python
processes = []
for pid, process_info in active_processes.items():
    process_data = {
        "pid": pid,
        "command": process_info["command"],
        "status": process_info["status"],
        "start_time": process_info["start_time"].isoformat(),
        "cpu_usage": resource_monitor.get_cpu_usage(pid),
        "memory_usage": resource_monitor.get_memory_usage(pid),
        "elapsed_time": calculate_elapsed_time(process_info["start_time"])
    }
    
    if process_info["status"] == "completed":
        process_data["end_time"] = process_info["end_time"].isoformat()
        process_data["exit_code"] = process_info["exit_code"]
    
    processes.append(process_data)
```

### Process Statistics Calculation
```python
running_count = sum(1 for p in processes if p["status"] == "running")
completed_count = sum(1 for p in processes if p["status"] == "completed")
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Process listing access required

## Error Handling
- **Process Manager Errors:** Handled by EnhancedProcessManager
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Information Disclosure:** Only returns information about processes managed by the system
- **Process Isolation:** Ensures process isolation and security

## Use Cases and Applications

#### Process Management
- **Process Monitoring:** Monitor running processes
- **Resource Tracking:** Track resource usage of processes
- **Status Checking:** Check status of long-running processes

#### Operational Awareness
- **System Status:** Understand current system load
- **Task Monitoring:** Monitor task execution status
- **Resource Planning:** Plan resource allocation based on current usage

## Testing & Validation
- Process listing accuracy testing
- Resource usage reporting verification
- Status reporting accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/processes/list", methods=["GET"])
def list_processes():
    """List all running processes managed by the system"""
    try:
        with process_lock:
            processes = []
            for pid, process_info in active_processes.items():
                process_data = {
                    "pid": pid,
                    "command": process_info["command"],
                    "status": process_info["status"],
                    "start_time": process_info["start_time"].isoformat(),
                    "cpu_usage": resource_monitor.get_cpu_usage(pid),
                    "memory_usage": resource_monitor.get_memory_usage(pid),
                    "elapsed_time": calculate_elapsed_time(process_info["start_time"])
                }
                
                if process_info["status"] == "completed":
                    process_data["end_time"] = process_info["end_time"].isoformat()
                    process_data["exit_code"] = process_info["exit_code"]
                
                processes.append(process_data)
            
            running_count = sum(1 for p in processes if p["status"] == "running")
            completed_count = sum(1 for p in processes if p["status"] == "completed")
            
            return jsonify({
                "success": True,
                "processes": processes,
                "total_count": len(processes),
                "running_count": running_count,
                "completed_count": completed_count,
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"💥 Error listing processes: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
