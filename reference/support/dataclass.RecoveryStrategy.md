---
title: dataclass.RecoveryStrategy
kind: dataclass
module: __main__
line_range: [1596, 1604]
discovered_in_chunk: 2
---

# RecoveryStrategy Dataclass

## Entity Classification & Context
- **Kind:** Dataclass
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Decorators:** @dataclass

## Complete Signature & Definition
```python
@dataclass
class RecoveryStrategy:
    """Recovery strategy with configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds
```

## Purpose & Behavior
Defines a specific recovery strategy with configuration and metrics:
- **Action Specification:** Type of recovery action to take
- **Parameter Configuration:** Action-specific parameters
- **Retry Logic:** Maximum attempts and backoff behavior
- **Success Metrics:** Probability of success and time estimation
- **Resource Planning:** Time allocation for recovery attempts

## Dependencies & Usage
- **Depends on:**
  - dataclasses.dataclass
  - typing.Dict, Any
  - RecoveryAction enum
- **Used by:**
  - IntelligentErrorHandler for strategy selection
  - Error recovery execution logic
  - Recovery planning and optimization

## Implementation Details

### Key Fields
- **action:** RecoveryAction enum value specifying the recovery approach
- **parameters:** Dictionary of action-specific configuration
- **max_attempts:** Maximum number of retry attempts
- **backoff_multiplier:** Exponential backoff multiplier for delays
- **success_probability:** Estimated probability of success (0.0-1.0)
- **estimated_time:** Expected execution time in seconds

### Strategy Configuration Examples
- **Retry with Backoff:** `{"initial_delay": 5, "max_delay": 60}`
- **Reduced Scope:** `{"reduce_threads": True, "reduce_timeout": True}`
- **Alternative Tool:** `{"prefer_faster_tools": True}`
- **Parameter Adjustment:** `{"use_defaults": True, "remove_invalid": True}`
- **Human Escalation:** `{"message": "...", "urgency": "medium"}`

### Metrics and Planning
- **Success Probability:** Used for strategy ranking and selection
- **Time Estimation:** Enables resource allocation and timeout planning
- **Backoff Logic:** Prevents overwhelming failed services

## Testing & Validation
- Strategy effectiveness validation
- Parameter configuration testing
- Success probability calibration
- Time estimation accuracy

## Code Reproduction
```python
@dataclass
class RecoveryStrategy:
    """Recovery strategy with configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds
```
