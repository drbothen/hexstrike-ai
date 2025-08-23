---
title: class.TelemetryCollector
kind: class
module: __main__
line_range: [6077, 6119]
discovered_in_chunk: 6
---

# TelemetryCollector Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Collect and manage system telemetry

## Complete Signature & Definition
```python
class TelemetryCollector:
    """Collect and manage system telemetry"""
    
    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }
    
    def record_execution(self, success: bool, execution_time: float):
        """Record command execution statistics"""
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
```

## Purpose & Behavior
System telemetry collection and management providing:
- **Execution Statistics:** Track command execution success/failure rates
- **Performance Metrics:** Monitor execution times and system performance
- **System Monitoring:** Real-time system resource monitoring
- **Uptime Tracking:** Track system uptime and operational statistics

## Dependencies & Usage
- **Depends on:**
  - time module for timestamp tracking
  - psutil for system metrics collection
  - typing.Dict, Any for type annotations
- **Used by:**
  - Command execution systems
  - Performance monitoring frameworks
  - System analytics and reporting

## Implementation Details

### Core Attributes
- **stats:** Execution statistics dictionary with 5 metrics

### Key Methods

#### Statistics Management
1. **record_execution(success: bool, execution_time: float):** Record command execution statistics
2. **get_system_metrics() -> Dict[str, Any]:** Get current system metrics
3. **get_stats() -> Dict[str, Any]:** Get comprehensive telemetry statistics

### Execution Statistics Tracking (5 Metrics)

#### Core Statistics
- **commands_executed:** Total number of commands executed
- **successful_commands:** Number of successful command executions
- **failed_commands:** Number of failed command executions
- **total_execution_time:** Cumulative execution time in seconds
- **start_time:** System start timestamp

### Execution Recording

#### Recording Process
```python
def record_execution(self, success: bool, execution_time: float):
    self.stats["commands_executed"] += 1
    if success:
        self.stats["successful_commands"] += 1
    else:
        self.stats["failed_commands"] += 1
    self.stats["total_execution_time"] += execution_time
```

#### Statistics Updates
- **Command Counter:** Increment total commands executed
- **Success/Failure Tracking:** Increment appropriate success or failure counter
- **Execution Time:** Add execution time to cumulative total

### System Metrics Collection

#### Real-time System Metrics
```python
{
    "cpu_percent": float,           # CPU usage percentage (1-second interval)
    "memory_percent": float,        # Memory usage percentage
    "disk_usage": float,            # Disk usage percentage for root filesystem
    "network_io": Dict[str, Any]    # Network I/O counters as dictionary
}
```

#### psutil Integration
- **CPU Monitoring:** psutil.cpu_percent(interval=1) for accurate CPU measurement
- **Memory Monitoring:** psutil.virtual_memory().percent for memory usage
- **Disk Monitoring:** psutil.disk_usage('/').percent for root filesystem usage
- **Network Monitoring:** psutil.net_io_counters()._asdict() for network I/O statistics

#### Error Handling
- **Network I/O Fallback:** Empty dict if psutil.net_io_counters() returns None
- **Exception Safety:** Graceful handling of psutil errors

### Telemetry Statistics

#### Comprehensive Statistics Output
```python
{
    "uptime_seconds": float,            # System uptime in seconds
    "commands_executed": int,           # Total commands executed
    "success_rate": str,                # Success rate percentage
    "average_execution_time": str,      # Average execution time
    "system_metrics": Dict[str, Any]    # Current system metrics
}
```

#### Calculated Metrics
- **Uptime:** Current time - start_time
- **Success Rate:** (successful_commands / commands_executed) * 100
- **Average Execution Time:** total_execution_time / commands_executed

#### Statistics Calculation
```python
uptime = time.time() - self.stats["start_time"]
success_rate = (self.stats["successful_commands"] / self.stats["commands_executed"] * 100) if self.stats["commands_executed"] > 0 else 0
avg_execution_time = (self.stats["total_execution_time"] / self.stats["commands_executed"]) if self.stats["commands_executed"] > 0 else 0
```

#### Formatted Output
- **Success Rate:** Formatted as percentage with 1 decimal place
- **Average Execution Time:** Formatted as seconds with 2 decimal places
- **System Metrics:** Real-time system metrics included

### Performance Analytics

#### Execution Performance
- **Success Rate Tracking:** Monitor command execution success rates
- **Execution Time Analysis:** Track and analyze execution durations
- **Failure Pattern Detection:** Identify patterns in failed executions

#### System Performance
- **Resource Usage Monitoring:** Monitor CPU, memory, disk, and network usage
- **Performance Trends:** Track performance trends over time
- **Capacity Planning:** Historical data for capacity planning

### Error Handling and Resilience

#### Division by Zero Prevention
- **Safe Calculations:** Check for zero commands executed before division
- **Default Values:** Return 0 for rates when no commands executed
- **Graceful Degradation:** Continue operation despite calculation errors

#### System Metrics Resilience
- **psutil Error Handling:** Graceful handling of system monitoring errors
- **Fallback Behavior:** Provide empty network I/O dict on errors
- **Continuous Operation:** Continue telemetry collection despite individual metric failures

### Integration with Command Execution

#### Automatic Recording
- **Execution Integration:** Automatic recording of all command executions
- **Success/Failure Tracking:** Track both successful and failed executions
- **Performance Monitoring:** Monitor execution performance over time

#### Real-time Analytics
- **Live Statistics:** Real-time telemetry statistics
- **System Health:** Current system health monitoring
- **Performance Insights:** Immediate performance insights

### Use Cases and Applications

#### System Monitoring
- **Operational Monitoring:** Monitor system operational health
- **Performance Analysis:** Analyze system and command performance
- **Capacity Planning:** Plan system capacity based on usage patterns

#### Quality Assurance
- **Success Rate Monitoring:** Monitor command execution success rates
- **Performance Regression Detection:** Detect performance regressions
- **System Health Checks:** Continuous system health monitoring

#### Analytics and Reporting
- **Usage Analytics:** Analyze system usage patterns
- **Performance Reports:** Generate performance reports
- **Trend Analysis:** Analyze performance trends over time

### Initialization and Lifecycle

#### Initialization
- **Statistics Initialization:** Initialize all statistics to zero
- **Start Time Recording:** Record system start time for uptime calculation
- **Continuous Operation:** Designed for continuous operation

#### Lifecycle Management
- **Persistent Statistics:** Statistics persist for system lifetime
- **Cumulative Tracking:** All metrics are cumulative
- **Real-time Updates:** Statistics updated in real-time

## Testing & Validation
- Execution recording accuracy testing
- System metrics collection validation
- Statistics calculation correctness verification
- Performance analytics accuracy assessment

## Code Reproduction
Complete class implementation with 3 methods for system telemetry collection and management, including execution statistics tracking, real-time system metrics, and comprehensive performance analytics. Essential for system monitoring and performance analysis.
