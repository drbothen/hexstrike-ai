---
title: GET /api/processes/dashboard
group: api
handler: process_dashboard
module: __main__
line_range: [7477, 7502]
discovered_in_chunk: 7
---

# GET /api/processes/dashboard

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get comprehensive process dashboard information

## Complete Signature & Definition
```python
@app.route("/api/processes/dashboard", methods=["GET"])
def process_dashboard():
    """Get comprehensive process dashboard information with enhanced logging"""
```

## Purpose & Behavior
Process monitoring dashboard endpoint providing:
- **System Overview:** Comprehensive system and process overview
- **Resource Monitoring:** CPU, memory, and disk usage statistics
- **Process Analytics:** Process count, status distribution, and trends
- **Enhanced Logging:** Detailed logging of dashboard data collection

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/processes/dashboard
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
    "dashboard_data": {
        "system_info": {
            "hostname": "hexstrike-server",
            "platform": "Linux-5.4.0-74-generic-x86_64",
            "cpu_count": 8,
            "memory_total": "16.0 GB",
            "disk_total": "500.0 GB",
            "uptime": "5 days, 12:34:56",
            "load_average": [1.2, 1.5, 1.8]
        },
        "resource_usage": {
            "cpu_percent": 25.3,
            "memory_percent": 68.7,
            "disk_percent": 45.2,
            "network_io": {
                "bytes_sent": 1024000000,
                "bytes_recv": 2048000000,
                "packets_sent": 500000,
                "packets_recv": 750000
            },
            "disk_io": {
                "read_bytes": 5120000000,
                "write_bytes": 3072000000,
                "read_count": 250000,
                "write_count": 180000
            }
        },
        "process_summary": {
            "total_processes": 156,
            "running_processes": 45,
            "sleeping_processes": 98,
            "stopped_processes": 2,
            "zombie_processes": 0,
            "top_cpu_processes": [
                {
                    "pid": 1234,
                    "name": "python3",
                    "cpu_percent": 15.2,
                    "memory_percent": 8.5
                }
            ],
            "top_memory_processes": [
                {
                    "pid": 5678,
                    "name": "chrome",
                    "cpu_percent": 5.1,
                    "memory_percent": 25.3
                }
            ]
        },
        "security_processes": {
            "hexstrike_processes": [
                {
                    "pid": 9999,
                    "name": "reference-server",
                    "status": "running",
                    "cpu_percent": 2.1,
                    "memory_percent": 3.5,
                    "create_time": "2024-01-01T10:00:00Z"
                }
            ],
            "suspicious_processes": [],
            "high_resource_processes": [
                {
                    "pid": 1111,
                    "name": "heavy_process",
                    "cpu_percent": 45.2,
                    "memory_percent": 15.8,
                    "alert_reason": "High CPU usage"
                }
            ]
        },
        "alerts": [
            {
                "type": "warning",
                "message": "High memory usage detected (68.7%)",
                "timestamp": "2024-01-01T12:00:00Z"
            }
        ]
    },
    "collection_time": 2.3,
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

### Data Collection Logic
```python
try:
    start_time = time.time()
    
    # Collect system information
    system_info = {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "cpu_count": psutil.cpu_count(),
        "memory_total": f"{psutil.virtual_memory().total / (1024**3):.1f} GB",
        "disk_total": f"{psutil.disk_usage('/').total / (1024**3):.1f} GB",
        "uptime": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
        "load_average": list(os.getloadavg()) if hasattr(os, 'getloadavg') else [0, 0, 0]
    }
    
    # Collect resource usage
    resource_usage = {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "network_io": psutil.net_io_counters()._asdict(),
        "disk_io": psutil.disk_io_counters()._asdict()
    }
    
    # Collect process information
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    collection_time = time.time() - start_time
    
except Exception as e:
    logger.error(f"💥 Error collecting dashboard data: {str(e)}")
    return jsonify({"error": f"Server error: {str(e)}"}), 500
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Process monitoring access required

## Error Handling
- **Data Collection Errors:** Handle errors during system data collection
- **Process Access Errors:** Handle permission denied errors for process information
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Information Disclosure:** Limit sensitive system information exposure
- **Process Privacy:** Respect process privacy and access controls
- **Resource Usage:** Monitor dashboard resource consumption

## Use Cases and Applications

#### System Monitoring
- **Real-time Monitoring:** Real-time system and process monitoring
- **Performance Analysis:** Analyze system performance and resource usage
- **Capacity Planning:** Plan system capacity based on usage patterns

#### Security Operations
- **Threat Detection:** Detect suspicious processes and activities
- **Incident Response:** Monitor system state during incident response
- **Forensic Analysis:** Collect system state for forensic analysis

## Testing & Validation
- Data collection accuracy testing
- Performance impact assessment
- Error handling behavior validation
- Dashboard rendering verification

## Code Reproduction
```python
@app.route("/api/processes/dashboard", methods=["GET"])
def process_dashboard():
    """Get comprehensive process dashboard information with enhanced logging"""
    try:
        logger.info("📊 Collecting process dashboard data")
        
        start_time = time.time()
        
        # Collect system information
        system_info = {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "cpu_count": psutil.cpu_count(),
            "memory_total": f"{psutil.virtual_memory().total / (1024**3):.1f} GB",
            "disk_total": f"{psutil.disk_usage('/').total / (1024**3):.1f} GB",
            "uptime": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
            "load_average": list(os.getloadavg()) if hasattr(os, 'getloadavg') else [0, 0, 0]
        }
        
        # Collect resource usage
        resource_usage = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "network_io": psutil.net_io_counters()._asdict(),
            "disk_io": psutil.disk_io_counters()._asdict()
        }
        
        # Collect process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'create_time']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Analyze processes
        process_summary = analyze_processes(processes)
        security_processes = analyze_security_processes(processes)
        alerts = generate_alerts(resource_usage, processes)
        
        collection_time = time.time() - start_time
        
        dashboard_data = {
            "system_info": system_info,
            "resource_usage": resource_usage,
            "process_summary": process_summary,
            "security_processes": security_processes,
            "alerts": alerts
        }
        
        logger.info(f"📊 Dashboard data collected in {collection_time:.2f}s | Processes: {len(processes)}")
        
        return jsonify({
            "success": True,
            "dashboard_data": dashboard_data,
            "collection_time": collection_time,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error collecting dashboard data: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
