---
title: variable.global.cve_intelligence
kind: variable
scope: module
module: __main__
line_range: [6764, 6764]
discovered_in_chunk: 6
---

# Global Variable: cve_intelligence

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** CVEIntelligenceManager

## Complete Signature & Definition
```python
cve_intelligence = CVEIntelligenceManager()
```

## Purpose & Behavior
Global singleton instance of the CVEIntelligenceManager for centralized CVE intelligence and vulnerability management throughout the application.

## Dependencies & Usage
- **Depends on:** CVEIntelligenceManager class
- **Used by:** Vulnerability management systems, security testing frameworks, report generation and visualization
- **Initialization:** Creates instance with CVE cache, vulnerability database, and threat intelligence

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide CVE intelligence
- **Intelligence Management:** CVE cache, vulnerability database, and threat intelligence data
- **Visual Formatting:** Enhanced progress bars, vulnerability cards, and dashboards

## Testing & Validation
- Instance creation validation
- CVE intelligence functionality testing
- Visual formatting capability verification

## Code Reproduction
```python
cve_intelligence = CVEIntelligenceManager()
```
