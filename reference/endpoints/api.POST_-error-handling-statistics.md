---
title: POST /api/error-handling/statistics
group: api
handler: error_handling_statistics
module: __main__
line_range: [15136, 15165]
discovered_in_chunk: 15
---

# POST /api/error-handling/statistics

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Retrieve error handling statistics and recovery metrics

## Complete Signature & Definition
```python
@app.route("/api/error-handling/statistics", methods=["POST"])
def error_handling_statistics():
    """Retrieve error handling statistics and recovery metrics"""
```

## Purpose & Behavior
Error handling statistics endpoint providing:
- **Error Metrics:** Retrieve comprehensive error handling statistics
- **Recovery Metrics:** Get metrics on recovery strategy effectiveness
- **Error Patterns:** Identify common error patterns and frequencies
- **Performance Impact:** Measure performance impact of error recovery
- **Trend Analysis:** Analyze error trends over time

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/error-handling/statistics
- **Content-Type:** application/json

### Request Body
```json
{
    "time_period": "string",          // Optional: Time period for statistics (default: "all")
    "error_types": ["string"],        // Optional: Filter by error types
    "tool_names": ["string"],         // Optional: Filter by tool names
    "include_details": boolean,       // Optional: Include detailed error records (default: false)
    "format": "string"                // Optional: Response format (default: "summary")
}
```

### Parameters
- **time_period:** Time period for statistics (optional) - "all", "today", "week", "month"
- **error_types:** Filter by error types (optional) - List of error types to include
- **tool_names:** Filter by tool names (optional) - List of tool names to include
- **include_details:** Include detailed error records (optional, default: false)
- **format:** Response format (optional) - "summary", "detailed", "chart"

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "statistics": {
        "total_errors": 120,
        "recovered_errors": 98,
        "recovery_rate": 81.67,
        "average_recovery_time": 1.5,
        "error_types": {
            "NETWORK": 45,
            "PERMISSION": 32,
            "TIMEOUT": 25,
            "RESOURCE": 18
        },
        "recovery_strategies": {
            "RETRY": {
                "count": 65,
                "success_rate": 92.3
            },
            "PARAMETER_ADJUSTMENT": {
                "count": 25,
                "success_rate": 84.0
            },
            "ALTERNATIVE_TOOL": {
                "count": 18,
                "success_rate": 77.8
            },
            "GRACEFUL_DEGRADATION": {
                "count": 12,
                "success_rate": 50.0
            }
        },
        "top_error_patterns": [
            {
                "pattern": "Connection refused",
                "count": 28,
                "recovery_rate": 96.4
            },
            {
                "pattern": "Permission denied",
                "count": 22,
                "recovery_rate": 81.8
            }
        ],
        "time_series": {
            "labels": ["2024-01-01", "2024-01-02", "2024-01-03"],
            "errors": [42, 35, 43],
            "recoveries": [35, 30, 33]
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

## Implementation Details

### Parameter Extraction
```python
params = request.json or {}
time_period = params.get("time_period", "all")
error_types = params.get("error_types", [])
tool_names = params.get("tool_names", [])
include_details = params.get("include_details", False)
format_type = params.get("format", "summary")
```

### Statistics Collection
```python
# Get base statistics from error handler
stats = error_handler.get_statistics(
    time_period=time_period,
    error_types=error_types,
    tool_names=tool_names
)

# Calculate derived metrics
if stats["total_errors"] > 0:
    stats["recovery_rate"] = (stats["recovered_errors"] / stats["total_errors"]) * 100

# Add time series data if requested
if format_type in ["detailed", "chart"]:
    stats["time_series"] = error_handler.get_time_series_data(
        time_period=time_period,
        error_types=error_types,
        tool_names=tool_names
    )

# Add detailed error records if requested
if include_details:
    stats["error_records"] = error_handler.get_error_records(
        time_period=time_period,
        error_types=error_types,
        tool_names=tool_names,
        limit=100
    )
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Error statistics access required

## Error Handling
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Information Disclosure:** Ensure sensitive information is not exposed in error details
- **Access Control:** Restrict access to error statistics to authorized users

## Use Cases and Applications

#### Error Analysis
- **Error Pattern Identification:** Identify common error patterns
- **Recovery Effectiveness:** Evaluate recovery strategy effectiveness
- **Trend Analysis:** Analyze error trends over time

#### System Optimization
- **Recovery Strategy Optimization:** Optimize recovery strategies based on effectiveness
- **Error Prevention:** Identify and address common error sources
- **Performance Improvement:** Reduce error impact on system performance

#### Operational Awareness
- **System Health Monitoring:** Monitor system health through error metrics
- **Recovery Capability Assessment:** Assess system recovery capabilities
- **Reliability Measurement:** Measure system reliability through error recovery rates

## Testing & Validation
- Parameter handling verification
- Statistics calculation accuracy testing
- Filtering functionality testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/error-handling/statistics", methods=["POST"])
def error_handling_statistics():
    """Retrieve error handling statistics and recovery metrics"""
    try:
        params = request.json or {}
        time_period = params.get("time_period", "all")
        error_types = params.get("error_types", [])
        tool_names = params.get("tool_names", [])
        include_details = params.get("include_details", False)
        format_type = params.get("format", "summary")
        
        # Get base statistics from error handler
        stats = error_handler.get_statistics(
            time_period=time_period,
            error_types=error_types,
            tool_names=tool_names
        )
        
        # Calculate derived metrics
        if stats["total_errors"] > 0:
            stats["recovery_rate"] = (stats["recovered_errors"] / stats["total_errors"]) * 100
        
        # Add time series data if requested
        if format_type in ["detailed", "chart"]:
            stats["time_series"] = error_handler.get_time_series_data(
                time_period=time_period,
                error_types=error_types,
                tool_names=tool_names
            )
        
        # Add detailed error records if requested
        if include_details:
            stats["error_records"] = error_handler.get_error_records(
                time_period=time_period,
                error_types=error_types,
                tool_names=tool_names,
                limit=100
            )
        
        logger.info(f"📊 Error handling statistics retrieved | Period: {time_period} | Types: {len(error_types)} | Tools: {len(tool_names)}")
        
        return jsonify({
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error retrieving error handling statistics: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
