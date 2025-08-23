---
title: GET /api/cache/stats
group: api
handler: cache_stats
module: __main__
line_range: [7400, 7403]
discovered_in_chunk: 7
---

# GET /api/cache/stats

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get cache statistics

## Complete Signature & Definition
```python
@app.route("/api/cache/stats", methods=["GET"])
def cache_stats():
    """Get cache statistics"""
    return jsonify(cache.get_stats())
```

## Purpose & Behavior
Cache statistics endpoint providing:
- **Performance Metrics:** Cache hit rate, size, and usage statistics
- **Operational Insights:** Cache effectiveness and performance data
- **Monitoring Support:** Real-time cache performance monitoring

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/cache/stats
- **Parameters:** None required

## Response

### Success Response (200 OK)
```json
{
    "size": 150,                    // Current cache size
    "max_size": 1000,               // Maximum cache capacity
    "hit_rate": "75.5%",            // Hit rate percentage
    "hits": 302,                    // Total cache hits
    "misses": 98,                   // Total cache misses
    "evictions": 5                  // Total evictions
}
```

## Implementation Details

### Direct Integration
- **Cache Access:** Direct call to cache.get_stats()
- **JSON Response:** Automatic JSON serialization of statistics
- **Real-time Data:** Current cache performance metrics

## AuthN/AuthZ
- **Authentication:** Not required (monitoring endpoint)
- **Authorization:** Not required (read-only statistics)

## Use Cases and Applications

#### Performance Monitoring
- **Cache Effectiveness:** Monitor cache hit rates and effectiveness
- **Performance Analysis:** Analyze cache performance trends
- **Capacity Planning:** Monitor cache usage for capacity planning

#### Operations and Debugging
- **Troubleshooting:** Debug cache-related performance issues
- **Optimization:** Optimize cache configuration based on statistics
- **Monitoring:** Real-time cache performance monitoring

## Testing & Validation
- Statistics accuracy verification
- Response format validation
- Real-time data consistency testing

## Code Reproduction
```python
@app.route("/api/cache/stats", methods=["GET"])
def cache_stats():
    """Get cache statistics"""
    return jsonify(cache.get_stats())
```
