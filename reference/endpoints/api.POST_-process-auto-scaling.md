---
title: POST /api/process/auto-scaling
group: api
handler: configure_auto_scaling
module: __main__
line_range: [14995, 15019]
discovered_in_chunk: 16
---

# POST /api/process/auto-scaling

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Configure auto-scaling settings

## Complete Signature & Definition
```python
@app.route("/api/process/auto-scaling", methods=["POST"])
def configure_auto_scaling():
    """Configure auto-scaling settings"""
```

## Purpose & Behavior
Auto-scaling configuration endpoint providing:
- **Dynamic Scaling:** Enable or disable automatic process pool scaling
- **Threshold Configuration:** Configure resource thresholds for scaling decisions
- **Performance Optimization:** Optimize system performance through intelligent scaling
- **Resource Management:** Manage system resources efficiently

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/process/auto-scaling
- **Content-Type:** application/json

### Request Body
```json
{
    "enabled": boolean,                 // Optional: Enable auto-scaling (default: true)
    "thresholds": {                     // Optional: Resource thresholds
        "cpu_threshold": 80,
        "memory_threshold": 85,
        "queue_threshold": 10
    }
}
```

### Parameters
- **enabled:** Whether to enable auto-scaling (optional, default: true)
- **thresholds:** Resource thresholds for scaling decisions (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "auto_scaling_enabled": true,
    "resource_thresholds": {
        "cpu_threshold": 80,
        "memory_threshold": 85,
        "queue_threshold": 10
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
@app.route("/api/process/auto-scaling", methods=["POST"])
def configure_auto_scaling():
    """Configure auto-scaling settings"""
    try:
        params = request.json
        enabled = params.get("enabled", True)
        thresholds = params.get("thresholds", {})
        
        # Update auto-scaling configuration
        enhanced_process_manager.auto_scaling_enabled = enabled
        
        if thresholds:
            enhanced_process_manager.resource_thresholds.update(thresholds)
        
        logger.info(f"⚙️ Auto-scaling configured | Enabled: {enabled}")
        return jsonify({
            "success": True,
            "auto_scaling_enabled": enabled,
            "resource_thresholds": enhanced_process_manager.resource_thresholds,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error configuring auto-scaling: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
