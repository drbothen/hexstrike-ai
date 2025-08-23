---
title: GET /api/process/cache-stats
group: api
handler: get_cache_stats
module: __main__
line_range: [14880, 14895]
discovered_in_chunk: 14
---

# GET /api/process/cache-stats

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get advanced cache statistics with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/process/cache-stats", methods=["GET"])
def get_cache_stats():
    """Get advanced cache statistics"""
```

## Purpose & Behavior
Cache statistics endpoint providing:
- **Cache Metrics:** Comprehensive cache performance statistics
- **Hit Rate Analysis:** Cache hit/miss ratios and efficiency metrics
- **Memory Usage:** Cache memory consumption and optimization data
- **Enhanced Logging:** Detailed logging of cache statistics retrieval

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/process/cache-stats
- **Content-Type:** None (GET request)

### Parameters
None - this is a GET endpoint with no parameters.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "cache_stats": {
        "hit_rate": 87.5,
        "miss_rate": 12.5,
        "total_requests": 1250,
        "cache_hits": 1094,
        "cache_misses": 156,
        "cache_size": 512,
        "memory_usage": "45.2 MB",
        "evictions": 23,
        "average_response_time": 0.15
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
@app.route("/api/process/cache-stats", methods=["GET"])
def get_cache_stats():
    """Get advanced cache statistics"""
    try:
        cache_stats = enhanced_process_manager.cache.get_stats()
        
        logger.info(f"💾 Cache stats retrieved | Hit rate: {cache_stats['hit_rate']:.1f}%")
        return jsonify({
            "success": True,
            "cache_stats": cache_stats,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error getting cache stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
