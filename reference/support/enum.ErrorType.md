---
title: enum.ErrorType
kind: enum
module: __main__
line_range: [1558, 1570]
discovered_in_chunk: 2
---

# ErrorType Enumeration

## Entity Classification & Context
- **Kind:** Enumeration class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Base Class:** Enum

## Complete Signature & Definition
```python
class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"
```

## Purpose & Behavior
Comprehensive enumeration of error types for intelligent error handling and recovery:
- **Network Errors:** TIMEOUT, NETWORK_UNREACHABLE, TARGET_UNREACHABLE
- **Permission Errors:** PERMISSION_DENIED, AUTHENTICATION_FAILED
- **Resource Errors:** RESOURCE_EXHAUSTED, RATE_LIMITED
- **Tool Errors:** TOOL_NOT_FOUND, INVALID_PARAMETERS
- **Data Errors:** PARSING_ERROR
- **Fallback:** UNKNOWN for unclassified errors

## Dependencies & Usage
- **Depends on:** enum.Enum (standard library)
- **Used by:**
  - IntelligentErrorHandler for error classification
  - ErrorContext for error type storage
  - Recovery strategy selection logic

## Implementation Details
- **String Values:** Enable JSON serialization and logging
- **Comprehensive Coverage:** Covers common security tool execution errors
- **Hierarchical Classification:** Groups related error types for recovery strategies
- **Extensible Design:** Can be extended for new error types

## Testing & Validation
- Error classification accuracy
- Recovery strategy mapping validation
- JSON serialization compatibility

## Code Reproduction
```python
class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"
```
