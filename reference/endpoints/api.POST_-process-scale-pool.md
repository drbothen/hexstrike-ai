---
title: POST /api/process/scale-pool
group: api
handler: manual_scale_pool
module: __main__
line_range: [15021, 15063]
discovered_in_chunk: 15
---

# POST /api/process/scale-pool

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Manually scale the process pool up or down with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/process/scale-pool", methods=["POST"])
def manual_scale_pool():
    """Manually scale the process pool"""
```

## Purpose & Behavior
Process pool scaling endpoint providing:
- **Manual Scaling:** Scale process pool workers up or down on demand
- **Capacity Management:** Manage worker capacity within defined limits
- **Resource Optimization:** Optimize resource usage based on workload
- **Enhanced Logging:** Detailed logging of scaling operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/process/scale-pool
- **Content-Type:** application/json

### Request Body
```json
{
    "action": "string",              // Required: "up" or "down"
    "count": integer                 // Optional: Number of workers to scale (default: 1)
}
```

### Parameters
- **action:** Scaling action - "up" or "down" (required)
- **count:** Number of workers to scale (optional, default: 1)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "message": "Scaled up by 2 workers",
    "previous_workers": 4,
    "current_workers": 6,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Invalid Action (400 Bad Request)
```json
{
    "error": "Action must be 'up' or 'down'"
}
```

#### Scaling Limit Exceeded (400 Bad Request)
```json
{
    "error": "Cannot scale up: would exceed max workers (10)"
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
@app.route("/api/process/scale-pool", methods=["POST"])
def manual_scale_pool():
    """Manually scale the process pool"""
    try:
        params = request.json
        action = params.get("action", "")  # "up" or "down"
        count = params.get("count", 1)
        
        if action not in ["up", "down"]:
            return jsonify({"error": "Action must be 'up' or 'down'"}), 400
        
        current_stats = enhanced_process_manager.process_pool.get_pool_stats()
        current_workers = current_stats["active_workers"]
        
        if action == "up":
            max_workers = enhanced_process_manager.process_pool.max_workers
            if current_workers + count <= max_workers:
                enhanced_process_manager.process_pool._scale_up(count)
                new_workers = current_workers + count
                message = f"Scaled up by {count} workers"
            else:
                return jsonify({"error": f"Cannot scale up: would exceed max workers ({max_workers})"}), 400
        else:  # down
            min_workers = enhanced_process_manager.process_pool.min_workers
            if current_workers - count >= min_workers:
                enhanced_process_manager.process_pool._scale_down(count)
                new_workers = current_workers - count
                message = f"Scaled down by {count} workers"
            else:
                return jsonify({"error": f"Cannot scale down: would go below min workers ({min_workers})"}), 400
        
        logger.info(f"📏 Manual scaling | {message} | Workers: {current_workers} → {new_workers}")
        return jsonify({
            "success": True,
            "message": message,
            "previous_workers": current_workers,
            "current_workers": new_workers,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error scaling pool: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
