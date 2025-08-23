---
title: POST /api/cache/clear
group: api
handler: clear_cache
module: __main__
line_range: [7405, 7411]
discovered_in_chunk: 7
---

# POST /api/cache/clear

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Clear the cache

## Complete Signature & Definition
```python
@app.route("/api/cache/clear", methods=["POST"])
def clear_cache():
    """Clear the cache"""
    cache.cache.clear()
    cache.stats = {"hits": 0, "misses": 0, "evictions": 0}
    logger.info("🧹 Cache cleared")
    return jsonify({"success": True, "message": "Cache cleared"})
```

## Purpose & Behavior
Cache clearing endpoint providing:
- **Cache Reset:** Clear all cached entries
- **Statistics Reset:** Reset cache statistics to zero
- **Operational Control:** Manual cache management capability
- **Logging Integration:** Log cache clearing operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/cache/clear
- **Parameters:** None required

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "message": "Cache cleared"
}
```

## Implementation Details

### Cache Clearing Process
1. **Cache Clear:** cache.cache.clear() to remove all entries
2. **Statistics Reset:** Reset hits, misses, and evictions to 0
3. **Logging:** Log cache clearing operation
4. **Response:** Return success confirmation

### Statistics Reset
```python
cache.stats = {"hits": 0, "misses": 0, "evictions": 0}
```

## AuthN/AuthZ
- **Authentication:** Not specified (administrative operation)
- **Authorization:** Cache management access required

## Observability
- **Logging:** "🧹 Cache cleared" message logged
- **Operation Tracking:** Cache clearing operations tracked

## Use Cases and Applications

#### Cache Management
- **Manual Reset:** Manually reset cache when needed
- **Testing:** Clear cache for testing scenarios
- **Troubleshooting:** Clear cache to resolve issues

#### Operations and Maintenance
- **Maintenance Operations:** Clear cache during maintenance
- **Performance Reset:** Reset cache performance metrics
- **Development Support:** Clear cache during development

## Testing & Validation
- Cache clearing functionality verification
- Statistics reset accuracy testing
- Logging integration validation

## Code Reproduction
```python
@app.route("/api/cache/clear", methods=["POST"])
def clear_cache():
    """Clear the cache"""
    cache.cache.clear()
    cache.stats = {"hits": 0, "misses": 0, "evictions": 0}
    logger.info("🧹 Cache cleared")
    return jsonify({"success": True, "message": "Cache cleared"})
```
