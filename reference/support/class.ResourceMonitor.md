---
title: class.ResourceMonitor
kind: class
module: __main__
line_range: [5423, 5293]
discovered_in_chunk: 4
---

# ResourceMonitor Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced resource monitoring with historical tracking

## Complete Signature & Definition
```python
class ResourceMonitor:
    """Advanced resource monitoring with historical tracking"""
    
    def __init__(self, history_size=100):
        self.history_size = history_size
        self.usage_history = []
        self.history_lock = threading.Lock()
```

## Purpose & Behavior
Advanced resource monitoring system providing:
- **Real-time Resource Monitoring:** Continuous system resource usage tracking
- **Historical Data Collection:** Configurable history size for trend analysis
- **Comprehensive Metrics:** CPU, memory, disk, and network usage monitoring
- **Thread-safe Operations:** Concurrent access support with lock synchronization

## Dependencies & Usage
- **Depends on:**
  - psutil for system resource monitoring
  - time module for timestamp tracking
  - threading.Lock for synchronization
  - typing.Dict for type annotations
- **Used by:**
  - EnhancedProcessManager for resource-aware execution
  - Performance optimization systems
  - Auto-scaling decision systems

## Implementation Details

### Core Attributes
- **history_size:** Maximum history entries (default: 100)
- **usage_history:** Historical resource usage data list
- **history_lock:** Thread synchronization lock

### Key Methods

#### Resource Monitoring
1. **get_current_usage() -> Dict[str, float]:** Get current system resource usage with historical tracking
2. **get_process_usage(pid: int) -> Dict[str, Any]:** Get specific process resource usage (method signature inferred)

### Current Resource Usage Monitoring

#### Comprehensive Resource Metrics
```python
{
    "cpu_percent": float,               # CPU usage percentage
    "memory_percent": float,            # Memory usage percentage
    "memory_available_gb": float,       # Available memory in GB
    "disk_percent": float,              # Disk usage percentage
    "disk_free_gb": float,              # Free disk space in GB
    "network_bytes_sent": int,          # Network bytes sent
    "network_bytes_recv": int,          # Network bytes received
    "timestamp": float                  # Collection timestamp
}
```

#### psutil Integration

##### CPU Monitoring
- **Measurement Method:** psutil.cpu_percent(interval=1)
- **Interval:** 1-second measurement interval for accuracy
- **Metric:** Overall system CPU usage percentage

##### Memory Monitoring
- **Data Source:** psutil.virtual_memory()
- **Percentage:** Memory usage percentage
- **Available GB:** Available memory in gigabytes (memory.available / 1024³)

##### Disk Monitoring
- **Target:** Root filesystem ('/') usage
- **Data Source:** psutil.disk_usage('/')
- **Percentage:** Disk usage percentage
- **Free GB:** Free disk space in gigabytes (disk.free / 1024³)

##### Network Monitoring
- **Data Source:** psutil.net_io_counters()
- **Metrics:** Total bytes sent and received
- **Scope:** System-wide network I/O statistics

### Historical Data Management

#### History Collection
- **Automatic Addition:** Each usage collection added to history
- **Thread Safety:** History updates protected by lock
- **Size Management:** Maintain configured history size limit

#### History Size Management
```python
with self.history_lock:
    self.usage_history.append(usage)
    if len(self.usage_history) > self.history_size:
        self.usage_history.pop(0)  # Remove oldest entry
```

#### Historical Analysis Capabilities
- **Trend Analysis:** Historical resource usage patterns
- **Performance Tracking:** Resource usage over time
- **Capacity Planning:** Historical data for scaling decisions

### Error Handling and Resilience

#### Exception Safety
- **psutil Errors:** Graceful handling of system monitoring failures
- **Fallback Behavior:** Continue operation despite monitoring errors
- **Error Logging:** Comprehensive error logging for troubleshooting

#### Monitoring Reliability
- **Continuous Operation:** Robust monitoring despite individual failures
- **Data Integrity:** Consistent data collection and storage
- **Recovery:** Automatic recovery from transient errors

### Thread Safety and Synchronization

#### Lock Usage
- **History Protection:** History list protected by threading.Lock
- **Atomic Updates:** Thread-safe history updates
- **Concurrent Access:** Safe concurrent access to historical data

#### Data Consistency
- **Consistent State:** History always in consistent state
- **Race Condition Prevention:** Proper synchronization of history updates
- **Thread-safe Operations:** All operations designed for concurrent access

### Integration with Process Management

#### Resource-aware Execution
- **Real-time Monitoring:** Continuous resource usage tracking
- **Decision Support:** Resource data for execution decisions
- **Performance Optimization:** Resource-based parameter optimization

#### Auto-scaling Integration
- **Scaling Decisions:** Resource usage data for auto-scaling
- **Threshold Monitoring:** Continuous threshold monitoring
- **Performance Metrics:** Resource metrics for performance tracking

### Process-specific Monitoring

#### Process Resource Usage (Inferred Method)
- **Per-process Metrics:** Individual process resource tracking
- **Process Identification:** PID-based process monitoring
- **Resource Attribution:** Attribute resource usage to specific processes

### Performance Characteristics

#### Monitoring Overhead
- **Low Overhead:** Efficient resource monitoring with minimal impact
- **Configurable History:** Adjustable history size for memory management
- **Optimized Collection:** Efficient data collection and storage

#### Data Accuracy
- **Real-time Data:** Current resource usage with 1-second CPU interval
- **Comprehensive Coverage:** All major system resources monitored
- **Timestamp Precision:** Accurate timestamp for temporal analysis

### Use Cases and Applications

#### System Monitoring
- **Resource Tracking:** Continuous system resource monitoring
- **Performance Analysis:** Historical performance trend analysis
- **Capacity Planning:** Resource usage patterns for capacity planning

#### Auto-scaling Support
- **Scaling Triggers:** Resource thresholds for scaling decisions
- **Load Assessment:** Current system load evaluation
- **Performance Optimization:** Resource-aware optimization decisions

#### Process Management
- **Resource Allocation:** Intelligent resource allocation decisions
- **Performance Monitoring:** Process performance tracking
- **System Health:** Overall system health monitoring

### Historical Data Structure

#### Usage History Entry
```python
{
    "cpu_percent": float,
    "memory_percent": float,
    "memory_available_gb": float,
    "disk_percent": float,
    "disk_free_gb": float,
    "network_bytes_sent": int,
    "network_bytes_recv": int,
    "timestamp": float
}
```

#### History Management
- **FIFO Queue:** First-in-first-out history management
- **Size Limit:** Configurable maximum history size
- **Memory Efficiency:** Automatic cleanup of old entries

## Testing & Validation
- Resource monitoring accuracy testing
- Historical data collection validation
- Thread safety and synchronization testing
- Performance overhead assessment

## Code Reproduction
Complete class implementation with 1+ methods for advanced resource monitoring with historical tracking, including comprehensive system metrics, thread-safe operations, and integration with process management systems. Essential for resource-aware system monitoring and performance optimization.
