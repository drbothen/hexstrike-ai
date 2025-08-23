---
title: class.EnhancedProcessManager
kind: class
module: __main__
line_range: [5208, 5421]
discovered_in_chunk: 4
---

# EnhancedProcessManager Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced process management with intelligent resource allocation

## Complete Signature & Definition
```python
class EnhancedProcessManager:
    """Advanced process management with intelligent resource allocation"""
    
    def __init__(self):
        self.process_pool = ProcessPool(min_workers=4, max_workers=32)
        self.cache = AdvancedCache(max_size=2000, default_ttl=1800)  # 30 minutes default TTL
        self.resource_monitor = ResourceMonitor()
        self.process_registry = {}
        self.registry_lock = threading.RLock()
        self.performance_dashboard = PerformanceDashboard()
        
        # Process termination and recovery
        self.termination_handlers = {}
        self.recovery_strategies = {}
        
        # Auto-scaling configuration
        self.auto_scaling_enabled = True
        self.resource_thresholds = {
            # Resource threshold configuration
        }
```

## Purpose & Behavior
Comprehensive process management system providing:
- **Intelligent Resource Allocation:** Dynamic resource management with auto-scaling
- **Advanced Caching:** Command result caching with TTL and LRU eviction
- **Process Lifecycle Management:** Complete process tracking and graceful termination
- **Performance Monitoring:** Real-time performance tracking and optimization
- **Auto-scaling Capabilities:** Automatic scaling based on resource usage

## Dependencies & Usage
- **Depends on:**
  - ProcessPool for task execution management
  - AdvancedCache for result caching
  - ResourceMonitor for system monitoring
  - PerformanceDashboard for performance tracking
  - threading.RLock for synchronization
  - subprocess for process execution
  - time for timing and performance tracking
  - os for process management
- **Used by:**
  - Command execution systems
  - Resource-aware computation frameworks
  - Performance optimization systems

## Implementation Details

### Core Attributes
- **process_pool:** ProcessPool instance (4-32 workers)
- **cache:** AdvancedCache instance (2000 entries, 30-minute TTL)
- **resource_monitor:** ResourceMonitor instance for system tracking
- **process_registry:** Active process tracking registry
- **registry_lock:** Thread synchronization RLock
- **performance_dashboard:** PerformanceDashboard for metrics
- **termination_handlers:** Process termination handlers
- **recovery_strategies:** Process recovery strategies
- **auto_scaling_enabled:** Auto-scaling feature flag
- **resource_thresholds:** Resource usage thresholds

### Key Methods

#### Process Execution
1. **execute_command_async(command: str, context: Dict[str, Any] = None) -> str:** Asynchronous command execution
2. **_execute_command_internal(command: str, context: Dict[str, Any]) -> Dict[str, Any]:** Internal command execution with monitoring
3. **get_task_result(task_id: str) -> Dict[str, Any]:** Retrieve async task result

#### Process Management
4. **terminate_process_gracefully(pid: int, timeout: int = 30) -> bool:** Graceful process termination
5. **_monitor_system():** System resource monitoring and auto-scaling
6. **_auto_scale_based_on_resources(resource_usage: Dict[str, float]):** Resource-based auto-scaling
7. **get_comprehensive_stats() -> Dict[str, Any]:** Comprehensive system statistics

### Resource Threshold Configuration (4 Thresholds)

#### High Resource Usage Thresholds
- **cpu_high:** 85.0% - High CPU usage threshold
- **memory_high:** 90.0% - High memory usage threshold
- **disk_high:** 95.0% - High disk usage threshold
- **load_high:** 0.8 - High load threshold

### Process Pool Configuration

#### Worker Pool Settings
- **Minimum Workers:** 4 workers (baseline capacity)
- **Maximum Workers:** 32 workers (maximum scaling)
- **Auto-scaling:** Dynamic scaling based on load and resources

### Advanced Caching Configuration

#### Cache Settings
- **Maximum Size:** 2000 entries (large cache capacity)
- **Default TTL:** 1800 seconds (30 minutes)
- **Cache Strategy:** Command result caching with hash-based keys

### Asynchronous Command Execution

#### Execution Flow
1. **Cache Check:** Verify if result already cached
2. **Task Submission:** Submit to process pool if not cached
3. **Task ID Return:** Return task identifier for result retrieval

#### Cache Integration
```python
cache_key = f"cmd_result_{hash(command)}"
cached_result = self.cache.get(cache_key)
if cached_result and context and context.get("use_cache", True):
    return cached_result
```

#### Task Submission
- **Unique Task ID:** Generated using timestamp and command hash
- **Process Pool:** Submitted to intelligent process pool
- **Context Passing:** Command context passed to execution

### Internal Command Execution

#### Resource-aware Execution
- **Resource Monitoring:** Check system resources before execution
- **CPU Optimization:** Add nice priority for high CPU usage
- **Process Registration:** Track active processes in registry

#### Process Creation and Monitoring
```python
process = subprocess.Popen(
    command,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    preexec_fn=os.setsid if os.name != 'nt' else None
)
```

#### Process Registry Management
```python
self.process_registry[process.pid] = {
    "command": command,
    "process": process,
    "start_time": start_time,
    "context": context,
    "status": "running"
}
```

### Command Execution Result Structure

#### Successful Execution Result
```python
{
    "success": True,
    "stdout": str,                              # Command output
    "stderr": str,                              # Error output
    "return_code": int,                         # Process exit code
    "execution_time": float,                    # Execution duration
    "pid": int,                                 # Process ID
    "resource_usage": Dict[str, Any]            # Resource usage during execution
}
```

#### Failed Execution Result
```python
{
    "success": False,
    "stdout": "",
    "stderr": str,                              # Error message
    "return_code": -1,
    "execution_time": float,
    "error": str                                # Exception details
}
```

### Result Caching Strategy

#### Cache Conditions
- **Successful Results:** Only cache successful command executions
- **Context Control:** Respect context cache_result flag
- **TTL Configuration:** Use context cache_ttl or default (30 minutes)

#### Cache Key Generation
```python
cache_key = f"cmd_result_{hash(command)}"
```

### Graceful Process Termination

#### Termination Strategy
1. **Graceful Termination:** Send SIGTERM signal first
2. **Timeout Wait:** Wait for graceful termination (default: 30 seconds)
3. **Force Kill:** Send SIGKILL if graceful termination fails

#### Termination Process
```python
process.terminate()  # Graceful termination
try:
    process.wait(timeout=timeout)
    process_info["status"] = "terminated_gracefully"
except subprocess.TimeoutExpired:
    process.kill()  # Force kill
    process_info["status"] = "force_killed"
```

### System Resource Monitoring

#### Monitoring Frequency
- **Monitor Interval:** 15 seconds
- **Continuous Monitoring:** Background monitoring thread
- **Auto-scaling Integration:** Resource-based scaling decisions

#### Monitoring Integration
- **Resource Usage:** Get current system resource usage
- **Auto-scaling:** Trigger scaling based on resource thresholds
- **Performance Dashboard:** Update system metrics

### Auto-scaling Logic

#### Scale Down Conditions
- **High CPU:** CPU usage > 85%
- **High Memory:** Memory usage > 90%
- **Worker Reduction:** Scale down by 1 worker if above minimum

#### Scale Up Conditions
- **Low Resource Usage:** CPU < 60%, Memory < 70%
- **High Demand:** Queue size > 2 pending tasks
- **Worker Addition:** Scale up by 1 worker if below maximum

#### Auto-scaling Algorithm
```python
if (resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"] or
    resource_usage["memory_percent"] > self.resource_thresholds["memory_high"]):
    if current_workers > self.process_pool.min_workers:
        self.process_pool._scale_down(1)

elif (resource_usage["cpu_percent"] < 60 and 
      resource_usage["memory_percent"] < 70 and
      pool_stats["queue_size"] > 2):
    if current_workers < self.process_pool.max_workers:
        self.process_pool._scale_up(1)
```

### Comprehensive Statistics

#### Statistics Collection
```python
{
    "process_pool": Dict[str, Any],             # Process pool statistics
    "cache": Dict[str, Any],                    # Cache performance statistics
    "resource_usage": Dict[str, float],         # Current resource usage
    "active_processes": int,                    # Active process count
    "performance_dashboard": Dict[str, Any],    # Performance dashboard summary
    "auto_scaling_enabled": bool,               # Auto-scaling status
    "resource_thresholds": Dict[str, float]     # Resource threshold configuration
}
```

### Performance Integration

#### Performance Dashboard Integration
- **Execution Recording:** Record all command executions
- **Metrics Collection:** Comprehensive performance metrics
- **System Metrics:** Real-time system resource updates

#### Resource Monitor Integration
- **Current Usage:** Real-time resource usage monitoring
- **Historical Tracking:** Resource usage history
- **Process Usage:** Per-process resource tracking

### Error Handling and Resilience

#### Command Execution Errors
- **Exception Handling:** Comprehensive exception catching
- **Error Result Generation:** Structured error result format
- **Performance Recording:** Record failed executions for analysis

#### Process Management Errors
- **Termination Errors:** Graceful handling of termination failures
- **Registry Cleanup:** Proper cleanup of process registry
- **Resource Monitoring Errors:** Fallback behavior for monitoring failures

### Thread Safety and Synchronization

#### Registry Lock Usage
- **RLock Protection:** Process registry protected by RLock
- **Atomic Operations:** Thread-safe process registration and cleanup
- **Deadlock Prevention:** Careful lock ordering and release

#### Process Lifecycle Management
- **Registration:** Atomic process registration on creation
- **Cleanup:** Automatic cleanup on process completion
- **Status Tracking:** Thread-safe status updates

### Integration with Advanced Systems

#### Process Pool Integration
- **Task Management:** Seamless task submission and result retrieval
- **Auto-scaling:** Intelligent scaling based on system load
- **Performance Optimization:** Resource-aware task execution

#### Cache Integration
- **Result Caching:** Automatic caching of successful command results
- **Performance Optimization:** Avoid repeated command execution
- **TTL Management:** Intelligent cache expiration

## Testing & Validation
- Asynchronous execution reliability testing
- Resource-aware optimization validation
- Auto-scaling behavior verification
- Cache performance and accuracy testing

## Code Reproduction
Complete class implementation with 7 methods for advanced process management with intelligent resource allocation, including asynchronous execution, comprehensive caching, graceful termination, and auto-scaling capabilities. Essential for high-performance process management and resource optimization.
