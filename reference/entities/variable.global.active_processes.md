---
title: variable.global.active_processes
kind: variable
scope: module
module: __main__
line_range: [5573, 5573]
discovered_in_chunk: 5
---

# Global Variable: active_processes

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** Dict[int, Dict[str, Any]]

## Complete Signature & Definition
```python
active_processes = {}  # pid -> process info
```

## Purpose & Behavior
Global dictionary for tracking active processes by PID, storing comprehensive process information including command, status, progress, and timing data.

## Dependencies & Usage
- **Depends on:** Process management infrastructure
- **Used by:** ProcessManager class for process tracking and management
- **Protected by:** process_lock for thread-safe access

## Implementation Details
- **Key Structure:** PID (int) -> process information dictionary
- **Thread Safety:** Protected by process_lock for concurrent access
- **Process Lifecycle:** Tracks processes from registration to cleanup

## Testing & Validation
- Process registration and cleanup testing
- Thread safety validation
- Process information integrity verification

## Code Reproduction
```python
active_processes = {}  # pid -> process info
```
