---
title: GET /api/process/health-check
group: api
handler: process_health_check
module: __main__
line_range: [15065, 15155]
discovered_in_chunk: 15
---

# GET /api/process/health-check

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Comprehensive health check of the process management system

## Complete Signature & Definition
```python
@app.route("/api/process/health-check", methods=["GET"])
def process_health_check():
    """Comprehensive health check of the process management system"""
```

## Purpose & Behavior
Process health monitoring endpoint providing:
- **System Health Assessment:** Comprehensive evaluation of system health
- **Resource Monitoring:** Monitor CPU, memory, and disk usage
- **Performance Analysis:** Analyze process pool and cache performance
- **Health Scoring:** Calculate overall health score with recommendations

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/health-check
- **Content-Type:** None (GET request)

### Parameters
None - this is a GET endpoint with no parameters.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "health_report": {
        "overall_status": "excellent",
        "health_score": 95,
        "issues": [],
        "system_stats": {
            "resource_usage": {
                "cpu_percent": 45.2,
                "memory_percent": 62.1,
                "disk_percent": 78.5
            },
            "process_pool": {
                "active_workers": 4,
                "queue_size": 12
            },
            "cache": {
                "hit_rate": 85.3
            }
        },
        "recommendations": []
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
@app.route("/api/process/health-check", methods=["GET"])
def process_health_check():
    """Comprehensive health check of the process management system"""
    try:
        # Get all system stats
        comprehensive_stats = enhanced_process_manager.get_comprehensive_stats()
        
        # Determine overall health
        resource_usage = comprehensive_stats["resource_usage"]
        pool_stats = comprehensive_stats["process_pool"]
        cache_stats = comprehensive_stats["cache"]
        
        health_score = 100
        issues = []
        
        # CPU health
        if resource_usage["cpu_percent"] > 95:
            health_score -= 30
            issues.append("Critical CPU usage")
        elif resource_usage["cpu_percent"] > 80:
            health_score -= 15
            issues.append("High CPU usage")
        
        # Memory health
        if resource_usage["memory_percent"] > 95:
            health_score -= 25
            issues.append("Critical memory usage")
        elif resource_usage["memory_percent"] > 85:
            health_score -= 10
            issues.append("High memory usage")
        
        # Disk health
        if resource_usage["disk_percent"] > 98:
            health_score -= 20
            issues.append("Critical disk usage")
        elif resource_usage["disk_percent"] > 90:
            health_score -= 5
            issues.append("High disk usage")
        
        # Process pool health
        if pool_stats["queue_size"] > 50:
            health_score -= 15
            issues.append("High task queue backlog")
        
        # Cache health
        if cache_stats["hit_rate"] < 30:
            health_score -= 10
            issues.append("Low cache hit rate")
        
        health_score = max(0, health_score)
        
        # Determine status
        if health_score >= 90:
            status = "excellent"
        elif health_score >= 75:
            status = "good"
        elif health_score >= 50:
            status = "fair"
        elif health_score >= 25:
            status = "poor"
        else:
            status = "critical"
        
        health_report = {
            "overall_status": status,
            "health_score": health_score,
            "issues": issues,
            "system_stats": comprehensive_stats,
            "recommendations": []
        }
        
        # Add recommendations based on issues
        if "High CPU usage" in issues:
            health_report["recommendations"].append("Consider reducing concurrent processes or upgrading CPU")
        if "High memory usage" in issues:
            health_report["recommendations"].append("Clear caches or increase available memory")
        if "High task queue backlog" in issues:
            health_report["recommendations"].append("Scale up process pool or optimize task processing")
        if "Low cache hit rate" in issues:
            health_report["recommendations"].append("Review cache TTL settings or increase cache size")
        
        logger.info(f"🏥 Health check completed | Status: {status} | Score: {health_score}/100")
        return jsonify({
            "success": True,
            "health_report": health_report,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error in health check: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
