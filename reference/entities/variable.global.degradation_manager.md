---
title: variable.global.degradation_manager
kind: variable
scope: module
module: __main__
line_range: [2431, 2431]
discovered_in_chunk: 2
---

# Global Variable: degradation_manager

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** GracefulDegradation

## Complete Signature & Definition
```python
degradation_manager = GracefulDegradation()
```

## Purpose & Behavior
Global singleton instance of the GracefulDegradation class for managing fallback operations and partial failure recovery throughout the application.

## Dependencies & Usage
- **Depends on:** GracefulDegradation class
- **Used by:** Tool execution workflows, critical operation management, fallback systems
- **Initialization:** Creates instance with fallback chains and critical operation definitions

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide degradation management
- **Fallback Coordination:** Manages multi-tier tool alternatives
- **Critical Operations:** Ensures essential operations have guaranteed fallbacks

## Testing & Validation
- Instance creation validation
- Fallback chain accessibility
- Critical operation coverage testing

## Code Reproduction
```python
degradation_manager = GracefulDegradation()
```
