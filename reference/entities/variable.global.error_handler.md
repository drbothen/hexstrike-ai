---
title: variable.global.error_handler
kind: variable
scope: module
module: __main__
line_range: [2430, 2430]
discovered_in_chunk: 2
---

# Global Variable: error_handler

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** IntelligentErrorHandler

## Complete Signature & Definition
```python
error_handler = IntelligentErrorHandler()
```

## Purpose & Behavior
Global singleton instance of the IntelligentErrorHandler for centralized error handling throughout the application. Provides pattern recognition, recovery strategies, and human escalation capabilities.

## Dependencies & Usage
- **Depends on:** IntelligentErrorHandler class
- **Used by:** Tool execution workflows, attack chains, error recovery systems
- **Initialization:** Creates instance with default error patterns and recovery strategies

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide error handling
- **State Management:** Maintains error history and recovery statistics
- **Thread Safety:** Requires consideration for concurrent error handling

## Testing & Validation
- Instance creation validation
- Error handling method accessibility
- Global state management testing

## Code Reproduction
```python
error_handler = IntelligentErrorHandler()
```
