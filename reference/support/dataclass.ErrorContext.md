---
title: dataclass.ErrorContext
kind: dataclass
module: __main__
line_range: [1582, 1594]
discovered_in_chunk: 2
---

# ErrorContext Dataclass

## Entity Classification & Context
- **Kind:** Dataclass
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Decorators:** @dataclass

## Complete Signature & Definition
```python
@dataclass
class ErrorContext:
    """Context information for error handling decisions"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: Dict[str, Any]
    previous_errors: List['ErrorContext'] = field(default_factory=list)
```

## Purpose & Behavior
Comprehensive context information for intelligent error handling decisions:
- **Tool Information:** Name and parameters of the failing tool
- **Target Details:** Target being tested when error occurred
- **Error Classification:** Type and detailed error message
- **Execution Context:** Attempt count, timestamp, stack trace
- **System State:** Resource availability and constraints
- **Historical Data:** Previous errors for pattern recognition

## Dependencies & Usage
- **Depends on:**
  - dataclasses.dataclass, field
  - typing.Dict, Any, List
  - ErrorType enum
  - datetime for timestamps
- **Used by:**
  - IntelligentErrorHandler for error analysis
  - Recovery strategy selection logic
  - Error pattern recognition

## Implementation Details

### Key Fields
- **tool_name:** String identifier of the failing tool
- **target:** Target URL, IP, or identifier being tested
- **parameters:** Tool parameters that caused the failure
- **error_type:** Classified error type from ErrorType enum
- **error_message:** Raw error message from tool execution
- **attempt_count:** Number of attempts made so far
- **timestamp:** When the error occurred
- **stack_trace:** Full stack trace for debugging
- **system_resources:** Current system resource usage
- **previous_errors:** Historical error context for pattern analysis

### Self-Referential Design
- Uses forward reference `'ErrorContext'` for previous_errors list
- Enables building error history chains
- Supports pattern recognition across multiple failures

## Testing & Validation
- Field validation and type checking
- Timestamp accuracy and timezone handling
- Stack trace capture completeness
- Historical error chain integrity

## Code Reproduction
```python
@dataclass
class ErrorContext:
    """Context information for error handling decisions"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: Dict[str, Any]
    previous_errors: List['ErrorContext'] = field(default_factory=list)
```
