---
title: constant.config.COMMAND_TIMEOUT
kind: constant
scope: module
module: __main__
line_range: [6005, 6005]
discovered_in_chunk: 5
---

# Configuration Constant: COMMAND_TIMEOUT

## Entity Classification & Context
- **Kind:** Module-level constant
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Default timeout for command execution

## Complete Signature & Definition
```python
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
```

## Purpose & Behavior
Default timeout value in seconds for command execution, set to 5 minutes (300 seconds) to prevent indefinite hanging of security tools and commands.

## Dependencies & Usage
- **Used by:** Command execution systems, EnhancedCommandExecutor, timeout management
- **Value:** 300 seconds (5 minutes)
- **Purpose:** Prevent indefinite command execution

## Implementation Details
- **Type:** Integer (seconds)
- **Value:** 300 seconds = 5 minutes
- **Scope:** Global default for all command executions

## Testing & Validation
- Timeout value appropriateness testing
- Command execution timeout verification
- Performance impact assessment

## Code Reproduction
```python
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
```
