---
title: variable.global.decision_engine
kind: variable
scope: module
module: __main__
line_range: [1545, 1545]
discovered_in_chunk: 2
---

# Global Variable: decision_engine

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** IntelligentDecisionEngine

## Complete Signature & Definition
```python
decision_engine = IntelligentDecisionEngine()
```

## Purpose & Behavior
Global singleton instance of the IntelligentDecisionEngine for use throughout the application. Provides centralized access to AI-powered tool selection, parameter optimization, and attack planning capabilities.

## Dependencies & Usage
- **Depends on:** IntelligentDecisionEngine class
- **Used by:** API endpoints, workflow managers, tool execution systems
- **Initialization:** Creates instance with default configuration

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide use
- **Lazy Loading:** Initialized at module load time
- **Thread Safety:** Requires consideration for concurrent access
- **State Management:** Maintains tool effectiveness mappings and attack patterns

## Testing & Validation
- Instance creation validation
- Method accessibility testing
- Thread safety validation for concurrent usage

## Code Reproduction
```python
decision_engine = IntelligentDecisionEngine()
```
