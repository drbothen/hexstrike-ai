---
title: GET /api/telemetry
group: api
handler: get_telemetry
module: __main__
line_range: [7414, 7417]
discovered_in_chunk: 7
---

# GET /api/telemetry

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get system telemetry

## Complete Signature & Definition
```python
@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """Get system telemetry"""
    return jsonify(telemetry.get_stats())
```

## Purpose & Behavior
System telemetry endpoint providing:
- **System Metrics:** Real-time system performance metrics
- **Execution Statistics:** Command execution success rates and timing
- **Operational Insights:** System health and performance data
- **Monitoring Support:** Comprehensive system monitoring

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/telemetry
- **Parameters:** None required

## Response

### Success Response (200 OK)
```json
{
    "uptime_seconds": 3600.5,
    "commands_executed": 245,
    "success_rate": "92.7%",
    "average_execution_time": "2.34s",
    "system_metrics": {
        "cpu_percent": 15.2,
        "memory_percent": 45.8,
        "disk_usage": 67.3,
        "network_io": {}
    }
}
```

## Implementation Details

### Direct Integration
- **Telemetry Access:** Direct call to telemetry.get_stats()
- **JSON Response:** Automatic JSON serialization of telemetry data
- **Real-time Data:** Current system performance and execution metrics

### Telemetry Data
- **Uptime:** System operational duration
- **Command Statistics:** Execution counts and success rates
- **Performance Metrics:** Average execution times
- **System Resources:** CPU, memory, disk, and network usage

## AuthN/AuthZ
- **Authentication:** Not required (monitoring endpoint)
- **Authorization:** Not required (read-only system metrics)

## Use Cases and Applications

#### System Monitoring
- **Health Monitoring:** Monitor system health and performance
- **Performance Analysis:** Analyze system performance trends
- **Capacity Planning:** Monitor resource usage for planning

#### Operations and Debugging
- **Troubleshooting:** Debug system performance issues
- **Optimization:** Optimize system configuration based on metrics
- **Alerting:** Real-time system monitoring and alerting

## Testing & Validation
- Telemetry data accuracy verification
- Response format validation
- Real-time metrics consistency testing

## Code Reproduction
```python
@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    """Get system telemetry"""
    return jsonify(telemetry.get_stats())
```
