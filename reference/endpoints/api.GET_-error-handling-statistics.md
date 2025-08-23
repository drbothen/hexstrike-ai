---
title: GET /api/error-handling/statistics
group: api
handler: get_error_statistics
module: __main__
line_range: [15165, 15177]
discovered_in_chunk: 15
---

# GET /api/error-handling/statistics

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get error handling statistics with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/error-handling/statistics", methods=["GET"])
def get_error_statistics():
    """Get error handling statistics"""
```

## Purpose & Behavior
Error statistics endpoint providing:
- **Error Metrics:** Comprehensive error handling statistics
- **Performance Analysis:** Error recovery success rates and patterns
- **System Health:** Error frequency and classification data
- **Enhanced Logging:** Detailed logging of statistics retrieval

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/error-handling/statistics
- **Content-Type:** None (GET request)

### Parameters
None - this is a GET endpoint with no parameters.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "statistics": {
        "total_errors": 156,
        "error_types": {
            "timeout": 45,
            "permission_denied": 23,
            "network_unreachable": 18
        },
        "recovery_success_rate": 87.5,
        "most_common_errors": ["timeout", "permission_denied"],
        "tools_with_errors": ["nmap", "gobuster", "nuclei"]
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
@app.route("/api/error-handling/statistics", methods=["GET"])
def get_error_statistics():
    """Get error handling statistics"""
    try:
        stats = error_handler.get_error_statistics()
        return jsonify({
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting error statistics: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
