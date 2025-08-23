---
title: variable.global.telemetry
kind: variable
scope: module
module: __main__
line_range: [6122, 6122]
discovered_in_chunk: 6
---

# Global Variable: telemetry

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** TelemetryCollector

## Complete Signature & Definition
```python
telemetry = TelemetryCollector()
```

## Purpose & Behavior
Global singleton instance of the TelemetryCollector for centralized system telemetry collection and management throughout the application.

## Dependencies & Usage
- **Depends on:** TelemetryCollector class
- **Used by:** Command execution systems, performance monitoring frameworks, system analytics and reporting
- **Initialization:** Creates instance with execution statistics tracking and system metrics collection

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide telemetry collection
- **Statistics Tracking:** Execution statistics, performance metrics, and system monitoring
- **Real-time Analytics:** Live system health and performance monitoring

## Testing & Validation
- Instance creation validation
- Telemetry collection functionality testing
- Statistics accuracy verification

## Code Reproduction
```python
telemetry = TelemetryCollector()
```
