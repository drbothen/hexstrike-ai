---
title: GET /api/process/performance-dashboard
group: api
handler: get_performance_dashboard
module: __main__
line_range: [14933, 14964]
discovered_in_chunk: 16
---

# GET /api/process/performance-dashboard

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get performance dashboard data

## Complete Signature & Definition
```python
@app.route("/api/process/performance-dashboard", methods=["GET"])
def get_performance_dashboard():
    """Get performance dashboard data"""
```

## Purpose & Behavior
Performance dashboard endpoint providing:
- **Comprehensive Metrics:** Aggregate performance, process pool, and resource usage data
- **System Health Assessment:** Evaluate CPU, memory, and disk health status
- **Auto-Scaling Status:** Monitor auto-scaling configuration and status
- **Real-Time Monitoring:** Provide real-time system performance insights

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/performance-dashboard
- **Content-Type:** application/json

### Parameters
None - this is a GET endpoint with no parameters.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "dashboard": {
        "performance_summary": {
            "success_rate": 95.5,
            "average_execution_time": 2.3,
            "total_commands_executed": 1250
        },
        "process_pool": {
            "active_workers": 8,
            "max_workers": 16,
            "queue_size": 3,
            "completed_tasks": 1200
        },
        "resource_usage": {
            "cpu_percent": 45.2,
            "memory_percent": 62.8,
            "disk_percent": 78.1
        },
        "cache_stats": {
            "hit_rate": 85.3,
            "total_hits": 1024,
            "total_misses": 180
        },
        "auto_scaling_status": true,
        "system_health": {
            "cpu_status": "healthy",
            "memory_status": "healthy",
            "disk_status": "healthy"
        }
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
@app.route("/api/process/performance-dashboard", methods=["GET"])
def get_performance_dashboard():
    """Get performance dashboard data"""
    try:
        dashboard_data = enhanced_process_manager.performance_dashboard.get_summary()
        pool_stats = enhanced_process_manager.process_pool.get_pool_stats()
        resource_usage = enhanced_process_manager.resource_monitor.get_current_usage()
        
        # Create comprehensive dashboard
        dashboard = {
            "performance_summary": dashboard_data,
            "process_pool": pool_stats,
            "resource_usage": resource_usage,
            "cache_stats": enhanced_process_manager.cache.get_stats(),
            "auto_scaling_status": enhanced_process_manager.auto_scaling_enabled,
            "system_health": {
                "cpu_status": "healthy" if resource_usage["cpu_percent"] < 80 else "warning" if resource_usage["cpu_percent"] < 95 else "critical",
                "memory_status": "healthy" if resource_usage["memory_percent"] < 85 else "warning" if resource_usage["memory_percent"] < 95 else "critical",
                "disk_status": "healthy" if resource_usage["disk_percent"] < 90 else "warning" if resource_usage["disk_percent"] < 98 else "critical"
            }
        }
        
        logger.info(f"📊 Performance dashboard retrieved | Success rate: {dashboard_data.get('success_rate', 0):.1f}%")
        return jsonify({
            "success": True,
            "dashboard": dashboard,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error getting performance dashboard: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
