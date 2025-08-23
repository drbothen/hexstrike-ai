---
title: dataclass.AttackStep
kind: dataclass
module: __main__
line_range: [512, 520]
discovered_in_chunk: 1
---

# AttackStep Dataclass

## Entity Classification & Context
- **Kind:** Dataclass
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Decorators:** @dataclass

## Complete Signature & Definition
```python
@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)
```

## Purpose & Behavior
Represents a single step in an automated attack chain with:
- **Tool Specification:** Name of the security tool to execute
- **Parameter Configuration:** Tool-specific parameters and options
- **Outcome Prediction:** Expected results from tool execution
- **Success Metrics:** Probability of successful execution
- **Time Estimation:** Expected execution duration in seconds
- **Dependency Management:** Prerequisites for this step

## Dependencies & Usage
- **Depends on:** 
  - dataclasses.dataclass, field
  - typing.Dict, Any, List
- **Used by:**
  - AttackChain for building attack sequences
  - IntelligentDecisionEngine for attack planning

## Implementation Details
- **tool:** String identifier for the security tool
- **parameters:** Dictionary of tool-specific configuration
- **expected_outcome:** Human-readable description of expected results
- **success_probability:** Float between 0.0 and 1.0
- **execution_time_estimate:** Integer seconds for time planning
- **dependencies:** List of prerequisite tools or conditions

## Testing & Validation
- Parameter validation for tool compatibility
- Success probability bounds checking
- Dependency resolution validation

## Code Reproduction
```python
@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)
```
