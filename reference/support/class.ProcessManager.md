---
title: class.ProcessManager
kind: class
module: __main__
line_range: [5576, 5687]
discovered_in_chunk: 5
---

# ProcessManager Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Enhanced process manager for command termination and monitoring

## Complete Signature & Definition
```python
class ProcessManager:
    """Enhanced process manager for command termination and monitoring"""
    
    @staticmethod
    def register_process(pid, command, process_obj):
        """Register a new active process"""
    
    @staticmethod
    def update_process_progress(pid, progress, last_output="", bytes_processed=0):
        """Update process progress and stats"""
    
    @staticmethod
    def terminate_process(pid):
        """Terminate a specific process"""
    
    @staticmethod
    def cleanup_process(pid):
        """Remove process from active registry"""
    
    @staticmethod
    def get_process_status(pid):
        """Get status of a specific process"""
    
    @staticmethod
    def list_active_processes():
        """List all active processes"""
    
    @staticmethod
    def pause_process(pid):
        """Pause a specific process (SIGSTOP)"""
    
    @staticmethod
    def resume_process(pid):
        """Resume a paused process (SIGCONT)"""
```

## Purpose & Behavior
Enhanced process management system providing:
- **Process Registration:** Track active processes with comprehensive metadata
- **Progress Monitoring:** Real-time progress tracking with ETA calculation
- **Process Control:** Terminate, pause, and resume process operations
- **Status Management:** Complete process lifecycle status tracking

## Dependencies & Usage
- **Depends on:**
  - threading.Lock (process_lock) for synchronization
  - time module for timing calculations
  - os module for signal operations
  - signal module for SIGSTOP/SIGCONT
  - logger for comprehensive logging
- **Used by:**
  - Command execution systems
  - Process monitoring frameworks
  - Process lifecycle management

## Implementation Details

### Core Attributes
- **Static Methods Only:** All methods are static for utility-style access
- **Global State:** Uses global active_processes dictionary and process_lock
- **Thread Safety:** All operations protected by process_lock

### Key Methods

#### Process Lifecycle Management
1. **register_process(pid, command, process_obj):** Register new active process with metadata
2. **cleanup_process(pid):** Remove process from active registry
3. **get_process_status(pid):** Get status of specific process
4. **list_active_processes():** List all active processes

#### Process Control Operations
5. **terminate_process(pid):** Terminate specific process with graceful degradation
6. **pause_process(pid):** Pause process using SIGSTOP signal
7. **resume_process(pid):** Resume paused process using SIGCONT signal

#### Progress Monitoring
8. **update_process_progress(pid, progress, last_output="", bytes_processed=0):** Update process progress and statistics

### Process Registration

#### Registration Data Structure
```python
{
    "pid": int,                     # Process ID
    "command": str,                 # Command being executed
    "process": subprocess.Popen,    # Process object
    "start_time": float,            # Process start timestamp
    "status": str,                  # Process status (running, paused, terminated)
    "progress": float,              # Progress percentage (0.0-1.0)
    "last_output": str,             # Last output from process
    "bytes_processed": int          # Bytes processed by process
}
```

#### Registration Process
1. **Thread Safety:** Acquire process_lock for atomic registration
2. **Metadata Collection:** Store comprehensive process information
3. **Status Initialization:** Set initial status to "running"
4. **Logging:** Log process registration with truncated command

### Progress Monitoring and ETA Calculation

#### Progress Update Process
1. **Progress Tracking:** Update progress percentage (0.0-1.0)
2. **Output Tracking:** Store last output from process
3. **Bytes Tracking:** Track bytes processed for throughput calculation
4. **Runtime Calculation:** Calculate elapsed time since process start

#### ETA Calculation Algorithm
```python
runtime = time.time() - active_processes[pid]["start_time"]
eta = 0
if progress > 0:
    eta = (runtime / progress) * (1.0 - progress)

active_processes[pid]["runtime"] = runtime
active_processes[pid]["eta"] = eta
```

#### Progress Metadata
- **Runtime:** Elapsed time since process start
- **ETA:** Estimated time to completion based on current progress
- **Throughput:** Implicit throughput calculation via bytes_processed

### Process Termination

#### Graceful Termination Strategy
1. **Process Validation:** Check if process exists and is running
2. **Graceful Termination:** Send terminate() signal first
3. **Grace Period:** Wait 1 second for graceful termination
4. **Force Kill:** Use kill() if process still running after grace period
5. **Status Update:** Mark process as "terminated"

#### Termination Algorithm
```python
process_obj = process_info["process"]
if process_obj and process_obj.poll() is None:
    process_obj.terminate()
    time.sleep(1)  # Grace period
    if process_obj.poll() is None:
        process_obj.kill()  # Force kill
    
    active_processes[pid]["status"] = "terminated"
```

### Process Control Operations

#### Pause Process (SIGSTOP)
- **Signal:** Send SIGSTOP signal to pause process execution
- **Status Update:** Change status to "paused"
- **Validation:** Check process exists and is running before pausing

#### Resume Process (SIGCONT)
- **Signal:** Send SIGCONT signal to resume process execution
- **Status Update:** Change status back to "running"
- **Validation:** Check process exists before resuming

#### Signal Operations
```python
os.kill(pid, signal.SIGSTOP)  # Pause
os.kill(pid, signal.SIGCONT)  # Resume
```

### Process Registry Management

#### Registry Operations
- **Registration:** Add new process to active_processes dictionary
- **Cleanup:** Remove process from registry and return process info
- **Status Query:** Get current status of specific process
- **List All:** Return copy of all active processes

#### Thread Safety
- **Lock Protection:** All registry operations protected by process_lock
- **Atomic Operations:** Ensure consistent state during concurrent access
- **Safe Cleanup:** Proper cleanup with process info return

### Error Handling and Resilience

#### Exception Handling
- **Termination Errors:** Graceful handling of termination failures
- **Signal Errors:** Safe handling of signal operation failures
- **Process Validation:** Check process existence before operations

#### Logging Integration
- **Registration Logging:** Log process registration with command preview
- **Termination Logging:** Log successful and failed terminations
- **Control Logging:** Log pause/resume operations
- **Error Logging:** Comprehensive error logging for troubleshooting

### Status Management

#### Process Status Values
- **"running":** Process is actively executing
- **"paused":** Process is paused via SIGSTOP
- **"terminated":** Process has been terminated

#### Status Transitions
- **Registration:** → "running"
- **Pause:** "running" → "paused"
- **Resume:** "paused" → "running"
- **Termination:** any status → "terminated"

### Integration with Process Management

#### Command Execution Integration
- **Automatic Registration:** Register processes during command execution
- **Progress Updates:** Update progress during long-running operations
- **Cleanup Integration:** Automatic cleanup on process completion

#### Monitoring Integration
- **Real-time Monitoring:** Live process status and progress monitoring
- **Dashboard Integration:** Process information for dashboard display
- **Performance Tracking:** Process performance and resource usage

### Use Cases and Applications

#### Process Lifecycle Management
- **Long-running Commands:** Track and manage long-running security tools
- **Batch Operations:** Manage multiple concurrent processes
- **Interactive Control:** Pause, resume, and terminate processes as needed

#### Monitoring and Analytics
- **Progress Tracking:** Real-time progress monitoring with ETA
- **Performance Analysis:** Process runtime and throughput analysis
- **Resource Management:** Process resource usage tracking

## Testing & Validation
- Process registration and cleanup testing
- Progress tracking and ETA calculation validation
- Process control operations (pause/resume/terminate) testing
- Thread safety and concurrent access verification

## Code Reproduction
Complete class implementation with 8 static methods for enhanced process management, including registration, progress monitoring, process control, and comprehensive status tracking. Essential for command execution lifecycle management and process monitoring.
