---
title: variable.global.tech_detector
kind: variable
scope: module
module: __main__
line_range: [5555, 5555]
discovered_in_chunk: 5
---

# Global Variable: tech_detector

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** TechnologyDetector

## Complete Signature & Definition
```python
tech_detector = TechnologyDetector()
```

## Purpose & Behavior
Global singleton instance of the TechnologyDetector for centralized technology detection and context-aware parameter selection throughout the application.

## Dependencies & Usage
- **Depends on:** TechnologyDetector class
- **Used by:** Parameter optimization systems, context-aware tool selection, technology-specific testing workflows
- **Initialization:** Creates instance with comprehensive technology detection patterns

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide technology detection
- **Detection Capabilities:** 6 technology categories with comprehensive pattern matching
- **Context-aware Analysis:** Intelligent technology stack identification for parameter optimization

## Testing & Validation
- Instance creation validation
- Technology detection accuracy testing
- Pattern matching precision verification

## Code Reproduction
```python
tech_detector = TechnologyDetector()
```
