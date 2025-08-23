---
title: class.AttackChain
kind: class
module: __main__
line_range: [522, 570]
discovered_in_chunk: 1
---

# AttackChain Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Represents a sequence of attacks for maximum impact

## Complete Signature & Definition
```python
class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"
```

## Purpose & Behavior
Manages sequences of coordinated security testing steps:
- **Step Management:** Add and organize attack steps
- **Probability Calculation:** Compound success probability for the chain
- **Time Estimation:** Total execution time for all steps
- **Tool Tracking:** Required tools for the entire chain
- **Risk Assessment:** Overall risk level of the attack chain

## Dependencies & Usage
- **Depends on:**
  - TargetProfile for target context
  - AttackStep for individual steps
  - typing.List, Set
- **Used by:**
  - IntelligentDecisionEngine for attack planning
  - Attack execution workflows

## Implementation Details

### Key Attributes
- **target_profile:** TargetProfile instance for context
- **steps:** List of AttackStep instances in execution order
- **success_probability:** Calculated compound probability (0.0-1.0)
- **estimated_time:** Total execution time in seconds
- **required_tools:** Set of unique tools needed
- **risk_level:** Risk classification string

### Key Methods
1. **add_step(step: AttackStep):** Add step to chain and update metrics
2. **calculate_success_probability():** Compute compound probability
3. **to_dict():** Convert to dictionary for JSON serialization

### Probability Calculation
Uses compound probability for sequential steps:
```python
prob = 1.0
for step in self.steps:
    prob *= step.success_probability
self.success_probability = prob
```

## Testing & Validation
- Step ordering validation
- Probability calculation accuracy
- Tool dependency resolution
- JSON serialization compatibility

## Code Reproduction
```python
class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"
    
    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate
        
    def calculate_success_probability(self):
        """Calculate overall success probability of the attack chain"""
        if not self.steps:
            self.success_probability = 0.0
            return
        
        # Use compound probability for sequential steps
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability
        
        self.success_probability = prob
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }
```
