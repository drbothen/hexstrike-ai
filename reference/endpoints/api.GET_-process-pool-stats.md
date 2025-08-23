---
title: GET /api/process/pool-stats
group: api
handler: get_pool_stats
module: __main__
line_range: [7555, 7580]
discovered_in_chunk: 7
---

# GET /api/process/pool-stats

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get process pool statistics and performance metrics

## Complete Signature & Definition
```python
@app.route("/api/process/pool-stats", methods=["GET"])
def get_pool_stats():
    """Get process pool statistics and performance metrics with enhanced logging"""
```

## Purpose & Behavior
Process pool monitoring endpoint providing:
- **Pool Statistics:** Comprehensive process pool statistics
- **Performance Metrics:** Performance and resource usage metrics
- **Queue Status:** Task queue status and backlog information
- **Enhanced Logging:** Detailed logging of statistics collection

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/pool-stats
- **Content-Type:** application/json

### Request Body
No request body required for GET request.

### Parameters
No parameters required.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "pool_stats": {
        "pool_info": {
            "max_workers": 8,
            "active_workers": 5,
            "idle_workers": 3,
            "total_capacity": 8,
            "utilization_percentage": 62.5
        },
        "queue_stats": {
            "queued_tasks": 12,
            "running_tasks": 5,
            "completed_tasks": 156,
            "failed_tasks": 8,
            "total_tasks": 181,
            "average_queue_time": 15.3,
            "average_execution_time": 45.7
        },
        "performance_metrics": {
            "tasks_per_minute": 3.2,
            "success_rate": 95.6,
            "average_cpu_usage": 35.2,
            "average_memory_usage": 512.5,
            "peak_memory_usage": 1024.0,
            "uptime": "2 days, 14:32:15"
        },
        "priority_breakdown": {
            "high": {
                "queued": 2,
                "running": 1,
                "completed": 25
            },
            "normal": {
                "queued": 8,
                "running": 3,
                "completed": 120
            },
            "low": {
                "queued": 2,
                "running": 1,
                "completed": 11
            }
        },
        "resource_usage": {
            "cpu_percent": 35.2,
            "memory_mb": 512.5,
            "disk_io_mb": 128.3,
            "network_io_mb": 45.7,
            "open_files": 156,
            "threads": 24
        },
        "recent_activity": [
            {
                "task_id": "task_1234567890",
                "command": "nmap -sV 192.168.1.1",
                "status": "completed",
                "execution_time": 130.5,
                "completed_at": "2024-01-01T12:02:15Z"
            }
        ]
    },
    "collection_time": 0.5,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Statistics Collection Logic
```python
try:
    start_time = time.time()
    
    # Get pool statistics from process manager
    pool_info = enhanced_process_manager.get_pool_info()
    queue_stats = enhanced_process_manager.get_queue_stats()
    performance_metrics = enhanced_process_manager.get_performance_metrics()
    priority_breakdown = enhanced_process_manager.get_priority_breakdown()
    resource_usage = enhanced_process_manager.get_resource_usage()
    recent_activity = enhanced_process_manager.get_recent_activity(limit=10)
    
    collection_time = time.time() - start_time
    
    pool_stats = {
        "pool_info": pool_info,
        "queue_stats": queue_stats,
        "performance_metrics": performance_metrics,
        "priority_breakdown": priority_breakdown,
        "resource_usage": resource_usage,
        "recent_activity": recent_activity
    }
    
except Exception as e:
    logger.error(f"💥 Error collecting pool stats: {str(e)}")
    return jsonify({"error": f"Server error: {str(e)}"}), 500
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Process pool monitoring access required

## Error Handling
- **Statistics Collection Errors:** Handle errors during statistics collection
- **Resource Access Errors:** Handle permission denied errors
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Information Disclosure:** Limit sensitive system information exposure
- **Resource Monitoring:** Monitor statistics collection resource usage
- **Access Control:** Implement proper access controls for pool statistics

## Use Cases and Applications

#### System Monitoring
- **Performance Monitoring:** Monitor process pool performance
- **Capacity Planning:** Plan system capacity based on usage patterns
- **Resource Optimization:** Optimize resource allocation and usage

#### Operations Management
- **Health Monitoring:** Monitor system health and performance
- **Troubleshooting:** Diagnose performance issues and bottlenecks
- **Alerting:** Generate alerts based on performance thresholds

## Testing & Validation
- Statistics collection accuracy testing
- Performance impact assessment
- Error handling behavior validation
- Data consistency verification

## Code Reproduction
```python
@app.route("/api/process/pool-stats", methods=["GET"])
def get_pool_stats():
    """Get process pool statistics and performance metrics with enhanced logging"""
    try:
        logger.info("📊 Collecting process pool statistics")
        
        start_time = time.time()
        
        # Get pool statistics from process manager
        pool_info = enhanced_process_manager.get_pool_info()
        queue_stats = enhanced_process_manager.get_queue_stats()
        performance_metrics = enhanced_process_manager.get_performance_metrics()
        priority_breakdown = enhanced_process_manager.get_priority_breakdown()
        resource_usage = enhanced_process_manager.get_resource_usage()
        recent_activity = enhanced_process_manager.get_recent_activity(limit=10)
        
        collection_time = time.time() - start_time
        
        pool_stats = {
            "pool_info": pool_info,
            "queue_stats": queue_stats,
            "performance_metrics": performance_metrics,
            "priority_breakdown": priority_breakdown,
            "resource_usage": resource_usage,
            "recent_activity": recent_activity
        }
        
        logger.info(f"📊 Pool stats collected in {collection_time:.2f}s | Active workers: {pool_info.get('active_workers', 0)}")
        
        return jsonify({
            "success": True,
            "pool_stats": pool_stats,
            "collection_time": collection_time,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error collecting pool stats: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
