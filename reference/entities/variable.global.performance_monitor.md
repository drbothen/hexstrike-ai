---
title: variable.global.performance_monitor
kind: variable
scope: module
module: __main__
line_range: [5558, 5558]
discovered_in_chunk: 5
---

# Global Variable: performance_monitor

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** PerformanceMonitor

## Complete Signature & Definition
```python
performance_monitor = PerformanceMonitor()
```

## Purpose & Behavior
Global singleton instance of the PerformanceMonitor for centralized performance monitoring and automatic resource allocation throughout the application.

## Dependencies & Usage
- **Depends on:** PerformanceMonitor class
- **Used by:** Parameter optimization systems, resource allocation frameworks, performance-aware tool execution
- **Initialization:** Creates instance with advanced performance monitoring and resource thresholds

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide performance monitoring
- **Resource Thresholds:** 4 resource thresholds for optimization triggers
- **Optimization Rules:** 4 optimization rule sets for different resource constraints

## Testing & Validation
- Instance creation validation
- Resource monitoring accuracy testing
- Optimization rule effectiveness verification

## Code Reproduction
```python
performance_monitor = PerformanceMonitor()
```
