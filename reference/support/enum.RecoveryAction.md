---
title: enum.RecoveryAction
kind: enum
module: __main__
line_range: [1572, 1580]
discovered_in_chunk: 2
---

# RecoveryAction Enumeration

## Entity Classification & Context
- **Kind:** Enumeration class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Base Class:** Enum

## Complete Signature & Definition
```python
class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"
```

## Purpose & Behavior
Defines recovery strategies for intelligent error handling:
- **Retry Strategies:** RETRY_WITH_BACKOFF, RETRY_WITH_REDUCED_SCOPE
- **Alternative Approaches:** SWITCH_TO_ALTERNATIVE_TOOL, ADJUST_PARAMETERS
- **Escalation:** ESCALATE_TO_HUMAN for human intervention
- **Fallback:** GRACEFUL_DEGRADATION for partial functionality
- **Termination:** ABORT_OPERATION for unrecoverable errors

## Dependencies & Usage
- **Depends on:** enum.Enum (standard library)
- **Used by:**
  - IntelligentErrorHandler for recovery strategy selection
  - RecoveryStrategy for action specification
  - Error handling workflows

## Implementation Details
- **Action Categories:** Grouped by recovery approach (retry, alternative, escalation)
- **Progressive Escalation:** From simple retries to human intervention
- **Context-Aware:** Actions selected based on error type and context
- **Configurable:** Each action can have associated parameters

## Testing & Validation
- Recovery action effectiveness testing
- Strategy selection logic validation
- Parameter configuration testing

## Code Reproduction
```python
class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"
```
