---
title: variable.global.file_manager
kind: variable
scope: module
module: __main__
line_range: [7151, 7151]
discovered_in_chunk: 7
---

# Global Variable: file_manager

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** FileOperationsManager

## Complete Signature & Definition
```python
file_manager = FileOperationsManager()
```

## Purpose & Behavior
Global singleton instance of the FileOperationsManager for centralized file operations management throughout the application.

## Dependencies & Usage
- **Depends on:** FileOperationsManager class
- **Used by:** Flask API endpoints for file operations, payload generation systems, file management workflows
- **Initialization:** Creates instance with default base directory "/tmp/hexstrike_files" and 100MB size limit

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide file operations
- **Security Controls:** File size limits and path validation
- **Operation Support:** File creation, modification, deletion, and directory listing

## Testing & Validation
- Instance creation validation
- File operations functionality testing
- Security controls verification

## Code Reproduction
```python
file_manager = FileOperationsManager()
```
