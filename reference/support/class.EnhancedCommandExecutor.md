---
title: class.EnhancedCommandExecutor
kind: class
module: __main__
line_range: [6124, 6344]
discovered_in_chunk: 6
---

# EnhancedCommandExecutor Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Enhanced command executor with caching, progress tracking, and better output handling

## Complete Signature & Definition
```python
class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None
        
    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
    
    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
    
    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
```

## Purpose & Behavior
Enhanced command execution system providing:
- **Real-time Output Streaming:** Continuous stdout/stderr reading and display
- **Progress Tracking:** Visual progress indication with ETA and speed calculation
- **Process Management Integration:** Integration with ProcessManager for lifecycle tracking
- **Timeout Handling:** Graceful timeout handling with partial results
- **Telemetry Integration:** Automatic execution statistics recording
- **Beautiful Result Formatting:** Enhanced result display with visual formatting

## Dependencies & Usage
- **Depends on:**
  - subprocess for process execution
  - threading for concurrent output reading
  - time for timing and progress tracking
  - datetime for timestamp generation
  - traceback for error reporting
  - COMMAND_TIMEOUT constant
  - ProcessManager for process tracking
  - ModernVisualEngine for visual formatting
  - telemetry for statistics recording
  - logger for comprehensive logging
- **Used by:**
  - Command execution systems
  - Security tool execution frameworks
  - Long-running process management

## Implementation Details

### Core Attributes
- **command:** Command string to execute
- **timeout:** Execution timeout (default: COMMAND_TIMEOUT)
- **process:** subprocess.Popen instance
- **stdout_data:** Accumulated stdout output
- **stderr_data:** Accumulated stderr output
- **stdout_thread:** Thread for stdout reading
- **stderr_thread:** Thread for stderr reading
- **return_code:** Process exit code
- **timed_out:** Timeout flag
- **start_time:** Execution start timestamp
- **end_time:** Execution end timestamp

### Key Methods

#### Command Execution
1. **execute() -> Dict[str, Any]:** Main command execution with enhanced monitoring and output

#### Internal Operations
2. **_read_stdout():** Thread function to continuously read and display stdout
3. **_read_stderr():** Thread function to continuously read and display stderr
4. **_show_progress(duration: float):** Show enhanced progress indication for long-running commands

### Real-time Output Streaming

#### Stdout Reading Thread
```python
def _read_stdout(self):
    try:
        for line in iter(self.process.stdout.readline, ''):
            if line:
                self.stdout_data += line
                logger.info(f"📤 STDOUT: {line.strip()}")
    except Exception as e:
        logger.error(f"Error reading stdout: {e}")
```

#### Stderr Reading Thread
```python
def _read_stderr(self):
    try:
        for line in iter(self.process.stderr.readline, ''):
            if line:
                self.stderr_data += line
                logger.warning(f"📥 STDERR: {line.strip()}")
    except Exception as e:
        logger.error(f"Error reading stderr: {e}")
```

#### Real-time Features
- **Continuous Reading:** Non-blocking continuous output reading
- **Immediate Display:** Real-time output display with emoji indicators
- **Data Accumulation:** Accumulate output for final result
- **Error Handling:** Graceful handling of reading errors

### Progress Tracking System

#### Progress Display Conditions
- **Duration Threshold:** Show progress for commands taking more than 2 seconds
- **Visual Indicators:** Animated progress characters from ModernVisualEngine
- **Progress Calculation:** Rough progress estimation based on elapsed time vs timeout

#### Progress Metrics Calculation
```python
progress_percent = min((elapsed / self.timeout) * 100, 99.9)
progress_fraction = progress_percent / 100

# ETA calculation (after 5% progress)
if progress_percent > 5:
    eta = ((elapsed / progress_percent) * 100) - elapsed

# Speed calculation
bytes_processed = len(self.stdout_data) + len(self.stderr_data)
speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"
```

#### Progress Bar Integration
```python
progress_bar = ModernVisualEngine.render_progress_bar(
    progress_fraction, 
    width=30, 
    style='cyber',
    label=f"⚡ PROGRESS {char}",
    eta=eta,
    speed=speed
)
```

### Process Management Integration

#### ProcessManager Integration
- **Process Registration:** Automatic registration with ProcessManager
- **Progress Updates:** Real-time progress updates to ProcessManager
- **Cleanup:** Automatic cleanup from ProcessManager on completion

#### Registration and Updates
```python
ProcessManager.register_process(pid, self.command, self.process)

ProcessManager.update_process_progress(
    self.process.pid,
    progress_fraction,
    f"Running for {elapsed:.1f}s",
    bytes_processed
)

ProcessManager.cleanup_process(pid)
```

### Command Execution Flow

#### Execution Process
1. **Initialization:** Record start time and log execution start
2. **Process Creation:** Create subprocess with pipes for stdout/stderr
3. **Thread Management:** Start stdout/stderr reading threads
4. **Progress Tracking:** Start progress tracking thread for long commands
5. **Process Monitoring:** Wait for completion or timeout
6. **Result Processing:** Process results and generate formatted output
7. **Cleanup:** Clean up threads and process registry

#### Process Creation
```python
self.process = subprocess.Popen(
    self.command,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)
```

### Timeout Handling

#### Graceful Timeout Management
- **Timeout Detection:** subprocess.TimeoutExpired exception handling
- **Graceful Termination:** Try terminate() first, then kill() if needed
- **Partial Results:** Consider timeout successful if output was produced
- **Status Tracking:** Track timeout status for result processing

#### Timeout Process
```python
try:
    self.return_code = self.process.wait(timeout=self.timeout)
except subprocess.TimeoutExpired:
    self.timed_out = True
    self.process.terminate()
    try:
        self.process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        self.process.kill()
    self.return_code = -1
```

### Result Processing and Formatting

#### Success Determination
```python
success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
```

#### Beautiful Results Summary
```python
results_summary = f"""
╭─────────────────────────────────────────────────────────────────────────────╮
│ 📊 FINAL RESULTS {status_icon}
├─────────────────────────────────────────────────────────────────────────────┤
│ 🚀 Command: {self.command[:55]}{'...' if len(self.command) > 55 else ''}
│ ⏱️ Duration: {execution_time:.2f}s{timeout_status}
│ 📊 Output Size: {output_size} bytes
│ 🔢 Exit Code: {self.return_code}
│ 📈 Status: {'SUCCESS' if success else 'FAILED'} | Cached: Yes
╰─────────────────────────────────────────────────────────────────────────────╯
"""
```

### Result Structure

#### Comprehensive Result Dictionary
```python
{
    "stdout": str,                      # Complete stdout output
    "stderr": str,                      # Complete stderr output
    "return_code": int,                 # Process exit code
    "success": bool,                    # Success determination
    "timed_out": bool,                  # Timeout flag
    "partial_results": bool,            # Partial results flag
    "execution_time": float,            # Execution duration
    "timestamp": str                    # ISO format timestamp
}
```

#### Success Logic
- **Normal Success:** return_code == 0
- **Timeout Success:** timed_out and (stdout_data or stderr_data)
- **Partial Results:** Available when timed_out and output exists

### Error Handling and Resilience

#### Exception Handling
- **Process Creation Errors:** Comprehensive exception handling
- **Thread Errors:** Graceful handling of thread errors
- **Timeout Errors:** Proper timeout exception handling
- **General Errors:** Catch-all exception handling with traceback

#### Error Result Structure
```python
{
    "stdout": str,                      # Any stdout collected
    "stderr": str,                      # Error message + any stderr
    "return_code": -1,                  # Error return code
    "success": False,                   # Failed execution
    "timed_out": False,                 # Not a timeout
    "partial_results": bool,            # Any output available
    "execution_time": float,            # Execution duration
    "timestamp": str                    # ISO format timestamp
}
```

### Telemetry Integration

#### Automatic Statistics Recording
- **Success Recording:** Record successful executions with telemetry
- **Failure Recording:** Record failed executions with telemetry
- **Execution Time:** Include execution time in telemetry data

#### Telemetry Calls
```python
telemetry.record_execution(True, execution_time)   # Success
telemetry.record_execution(False, execution_time)  # Failure
```

### Logging Integration

#### Comprehensive Logging
- **Execution Start:** Log command execution start with timeout
- **Process Registration:** Log process ID and registration
- **Real-time Output:** Log stdout/stderr in real-time
- **Progress Updates:** Log progress with beautiful progress bars
- **Final Results:** Log formatted results summary
- **Error Logging:** Comprehensive error logging with traceback

#### Log Message Examples
- **Start:** "🚀 EXECUTING: {command}"
- **Process:** "🆔 PROCESS: PID {pid} started"
- **Success:** "✅ SUCCESS: Command completed | Exit Code: {code} | Duration: {time}s"
- **Timeout:** "⏰ TIMEOUT: Command timed out after {timeout}s | Terminating PID {pid}"

### Thread Management

#### Thread Lifecycle
- **Daemon Threads:** All threads are daemon threads for clean shutdown
- **Thread Joining:** Proper thread joining with timeout
- **Thread Safety:** Thread-safe data access and modification

#### Thread Coordination
- **Concurrent Reading:** Simultaneous stdout/stderr reading
- **Progress Tracking:** Independent progress tracking thread
- **Clean Shutdown:** Proper thread cleanup on completion

### Use Cases and Applications

#### Security Tool Execution
- **Long-running Scans:** Execute long-running security scans with progress tracking
- **Real-time Monitoring:** Monitor tool output in real-time
- **Timeout Management:** Handle tools that may hang or run indefinitely

#### Development and Testing
- **Command Testing:** Test command execution with enhanced monitoring
- **Performance Analysis:** Analyze command execution performance
- **Debug Support:** Enhanced debugging with real-time output

#### Production Operations
- **Operational Commands:** Execute operational commands with monitoring
- **Process Management:** Manage long-running processes effectively
- **Performance Monitoring:** Monitor command execution performance

## Testing & Validation
- Command execution accuracy testing
- Real-time output streaming validation
- Progress tracking correctness verification
- Timeout handling behavior testing

## Code Reproduction
```python
class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None
        
    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    logger.info(f"📤 STDOUT: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")
    
    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    logger.warning(f"📥 STDERR: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")
    
    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
        if duration < 2:
            return
            
        progress_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        char_index = 0
        
        while self.process.poll() is None:
            char = progress_chars[char_index % len(progress_chars)]
            elapsed = time.time() - self.start_time
            
            # Calculate progress metrics
            progress_percent = min((elapsed / self.timeout) * 100, 99.9)
            progress_fraction = progress_percent / 100
            
            # ETA calculation
            eta = "calculating..." if progress_percent < 5 else f"{((elapsed / progress_percent) * 100) - elapsed:.1f}s"
            
            # Speed calculation
            bytes_processed = len(self.stdout_data) + len(self.stderr_data)
            speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"
            
            progress_bar = ModernVisualEngine.render_progress_bar(
                progress_fraction, 
                width=30, 
                style='cyber',
                label=f"⚡ PROGRESS {char}",
                eta=eta,
                speed=speed
            )
            
            logger.info(progress_bar)
            char_index += 1
            time.sleep(0.1)
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
        self.start_time = time.time()
        logger.info(f"🚀 EXECUTING: {self.command}")
        
        try:
            # Create subprocess with pipes
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            pid = self.process.pid
            logger.info(f"🆔 PROCESS: PID {pid} started")
            
            # Register with ProcessManager
            ProcessManager.register_process(pid, self.command, self.process)
            
            # Start output reading threads
            self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Start progress tracking for long commands
            progress_thread = threading.Thread(
                target=self._show_progress, 
                args=(self.timeout,), 
                daemon=True
            )
            progress_thread.start()
            
            # Wait for completion or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"⏰ TIMEOUT: Command timed out after {self.timeout}s | Terminating PID {pid}")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                self.return_code = -1
            
            # Wait for threads to complete
            if self.stdout_thread.is_alive():
                self.stdout_thread.join(timeout=2)
            if self.stderr_thread.is_alive():
                self.stderr_thread.join(timeout=2)
            
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time
            
            # Determine success
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            # Log results
            status_icon = "✅" if success else "❌"
            timeout_status = " (TIMEOUT)" if self.timed_out else ""
            output_size = len(self.stdout_data) + len(self.stderr_data)
            
            results_summary = f"""
╭─────────────────────────────────────────────────────────────────────────────╮
│ 📊 FINAL RESULTS {status_icon}
├─────────────────────────────────────────────────────────────────────────────┤
│ 🚀 Command: {self.command[:55]}{'...' if len(self.command) > 55 else ''}
│ ⏱️ Duration: {execution_time:.2f}s{timeout_status}
│ 📊 Output Size: {output_size} bytes
│ 🔢 Exit Code: {self.return_code}
│ 📈 Status: {'SUCCESS' if success else 'FAILED'} | Cached: Yes
╰─────────────────────────────────────────────────────────────────────────────╯
"""
            logger.info(results_summary)
            
            # Record telemetry
            telemetry.record_execution(success, execution_time)
            
            # Cleanup
            ProcessManager.cleanup_process(pid)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0
            
            logger.error(f"💥 EXECUTION ERROR: {str(e)}")
            logger.error(f"📋 TRACEBACK: {traceback.format_exc()}")
            
            telemetry.record_execution(False, execution_time)
            
            return {
                "stdout": self.stdout_data,
                "stderr": f"Execution error: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }
```
