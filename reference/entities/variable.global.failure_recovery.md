---
title: variable.global.failure_recovery
kind: variable
scope: module
module: __main__
line_range: [5557, 5557]
discovered_in_chunk: 5
---

# Global Variable: failure_recovery

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** FailureRecoverySystem

## Complete Signature & Definition
```python
failure_recovery = FailureRecoverySystem()
```

## Purpose & Behavior
Global singleton instance of the FailureRecoverySystem for centralized failure recovery and alternative tool selection throughout the application.

## Dependencies & Usage
- **Depends on:** FailureRecoverySystem class
- **Used by:** Tool execution systems, parameter optimization frameworks, automated recovery workflows
- **Initialization:** Creates instance with comprehensive tool alternatives and failure pattern recognition

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide failure recovery
- **Tool Alternatives:** 8 tool alternative mappings for comprehensive coverage
- **Failure Patterns:** 6 failure pattern types with intelligent recognition

## Testing & Validation
- Instance creation validation
- Failure pattern recognition testing
- Alternative tool effectiveness verification

## Code Reproduction
```python
failure_recovery = FailureRecoverySystem()
```
