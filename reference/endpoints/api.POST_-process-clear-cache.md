---
title: POST /api/process/clear-cache
group: api
handler: clear_process_cache
module: __main__
line_range: [14897, 14912]
discovered_in_chunk: 14
---

# POST /api/process/clear-cache

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Clear the advanced cache with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/process/clear-cache", methods=["POST"])
def clear_process_cache():
    """Clear the advanced cache"""
```

## Purpose & Behavior
Cache clearing endpoint providing:
- **Cache Management:** Clear all cached data and reset statistics
- **Memory Optimization:** Free up cache memory for system optimization
- **Performance Reset:** Reset cache performance metrics
- **Enhanced Logging:** Detailed logging of cache clearing operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/process/clear-cache
- **Content-Type:** application/json

### Request Body
```json
{}
```

### Parameters
None - this endpoint accepts an empty JSON body.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "message": "Cache cleared successfully",
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
@app.route("/api/process/clear-cache", methods=["POST"])
def clear_process_cache():
    """Clear the advanced cache"""
    try:
        enhanced_process_manager.cache.clear()
        
        logger.info("🧹 Process cache cleared")
        return jsonify({
            "success": True,
            "message": "Cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error clearing cache: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
