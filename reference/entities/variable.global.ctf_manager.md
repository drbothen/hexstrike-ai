---
title: variable.global.ctf_manager
kind: variable
scope: module
module: __main__
line_range: [2778, 2778]
discovered_in_chunk: 2
---

# Global Variable: ctf_manager

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** CTFWorkflowManager

## Complete Signature & Definition
```python
ctf_manager = CTFWorkflowManager()
```

## Purpose & Behavior
Global singleton instance of the CTFWorkflowManager for centralized CTF competition workflow management throughout the application.

## Dependencies & Usage
- **Depends on:** CTFWorkflowManager class
- **Used by:** CTF competition automation, challenge solving workflows
- **Initialization:** Creates instance with comprehensive tool mappings and workflow strategies

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide CTF management
- **Workflow Coordination:** Manages challenge solving workflows across all CTF categories
- **Tool Integration:** Coordinates specialized CTF tools for different challenge types

## Testing & Validation
- Instance creation validation
- Workflow generation testing
- Tool integration verification

## Code Reproduction
```python
ctf_manager = CTFWorkflowManager()
```
