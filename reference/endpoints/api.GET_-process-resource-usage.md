---
title: GET /api/process/resource-usage
group: api
handler: get_resource_usage
module: __main__
line_range: [14914, 14931]
discovered_in_chunk: 14
---

# GET /api/process/resource-usage

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get current system resource usage and trends with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/process/resource-usage", methods=["GET"])
def get_resource_usage():
    """Get current system resource usage and trends"""
```

## Purpose & Behavior
Resource monitoring endpoint providing:
- **Real-time Metrics:** Current CPU, memory, and disk usage statistics
- **Usage Trends:** Historical resource usage patterns and trends
- **Performance Analysis:** Resource utilization analysis and optimization insights
- **Enhanced Logging:** Detailed logging of resource monitoring operations

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/resource-usage
- **Content-Type:** None (GET request)

### Parameters
None - this is a GET endpoint with no parameters.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "current_usage": {
        "cpu_percent": 45.2,
        "memory_percent": 62.1,
        "disk_percent": 78.5,
        "network_io": {
            "bytes_sent": 1024000,
            "bytes_recv": 2048000
        },
        "process_count": 156,
        "load_average": [1.2, 1.5, 1.8]
    },
    "usage_trends": {
        "cpu_trend": "stable",
        "memory_trend": "increasing",
        "disk_trend": "stable",
        "peak_usage_times": ["14:00", "18:30"],
        "average_cpu_last_hour": 42.8,
        "average_memory_last_hour": 58.3
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/process/resource-usage", methods=["GET"])
def get_resource_usage():
    """Get current system resource usage and trends"""
    try:
        current_usage = enhanced_process_manager.resource_monitor.get_current_usage()
        usage_trends = enhanced_process_manager.resource_monitor.get_usage_trends()
        
        logger.info(f"📈 Resource usage retrieved | CPU: {current_usage['cpu_percent']:.1f}% | Memory: {current_usage['memory_percent']:.1f}%")
        return jsonify({
            "success": True,
            "current_usage": current_usage,
            "usage_trends": usage_trends,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error getting resource usage: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
