---
title: POST /api/process/terminate-gracefully/{pid}
group: api
handler: terminate_process_gracefully
module: __main__
line_range: [14966, 14993]
discovered_in_chunk: 16
---

# POST /api/process/terminate-gracefully/{pid}

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Terminate process with graceful degradation

## Complete Signature & Definition
```python
@app.route("/api/process/terminate-gracefully/<int:pid>", methods=["POST"])
def terminate_process_gracefully(pid):
    """Terminate process with graceful degradation"""
```

## Purpose & Behavior
Graceful process termination endpoint providing:
- **Safe Termination:** Gracefully terminate processes with proper cleanup
- **Timeout Management:** Configurable timeout for graceful shutdown
- **Status Reporting:** Report termination success or failure
- **Resource Cleanup:** Ensure proper resource cleanup during termination

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/process/terminate-gracefully/{pid}
- **Content-Type:** application/json

### Path Parameters
- **pid:** Process ID to terminate (integer, required)

### Request Body
```json
{
    "timeout": integer                  // Optional: Termination timeout in seconds (default: 30)
}
```

### Parameters
- **pid:** Process ID to terminate (path parameter, required)
- **timeout:** Timeout for graceful termination in seconds (optional, default: 30)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "message": "Process 1234 terminated successfully",
    "pid": 1234,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Termination Failed (400 Bad Request)
```json
{
    "success": false,
    "error": "Failed to terminate process 1234",
    "pid": 1234,
    "timestamp": "2024-01-01T12:00:00Z"
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
@app.route("/api/process/terminate-gracefully/<int:pid>", methods=["POST"])
def terminate_process_gracefully(pid):
    """Terminate process with graceful degradation"""
    try:
        params = request.json or {}
        timeout = params.get("timeout", 30)
        
        success = enhanced_process_manager.terminate_process_gracefully(pid, timeout)
        
        if success:
            logger.info(f"✅ Process {pid} terminated gracefully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} terminated successfully",
                "pid": pid,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to terminate process {pid}",
                "pid": pid,
                "timestamp": datetime.now().isoformat()
            }), 400
        
    except Exception as e:
        logger.error(f"💥 Error terminating process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
