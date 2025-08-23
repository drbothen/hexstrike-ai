---
title: variable.global.env_manager
kind: variable
scope: module
module: __main__
line_range: [5744, 5744]
discovered_in_chunk: 5
---

# Global Variable: env_manager

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** PythonEnvironmentManager

## Complete Signature & Definition
```python
env_manager = PythonEnvironmentManager()
```

## Purpose & Behavior
Global singleton instance of the PythonEnvironmentManager for centralized Python virtual environment and dependency management throughout the application.

## Dependencies & Usage
- **Depends on:** PythonEnvironmentManager class
- **Used by:** Tool execution systems requiring isolated Python environments, package dependency management
- **Initialization:** Creates instance with default base directory "/tmp/hexstrike_envs"

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide environment management
- **Environment Management:** Virtual environment creation and package installation
- **Path Resolution:** Python executable path resolution for isolated execution

## Testing & Validation
- Instance creation validation
- Environment management functionality testing
- Package installation capability verification

## Code Reproduction
```python
env_manager = PythonEnvironmentManager()
```
