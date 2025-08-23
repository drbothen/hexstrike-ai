---
title: function.execute_sqlmap_scan
kind: function
scope: module
module: __main__
line_range: [8021, 8031]
discovered_in_chunk: 8
---

# Function: execute_sqlmap_scan

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute sqlmap scan with optimized parameters

## Complete Signature & Definition
```python
def execute_sqlmap_scan(target, params):
    """Execute sqlmap scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '--batch --random-agent')
        cmd_parts = ['sqlmap', '-u', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())
            
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```

## Purpose & Behavior
SQLMap execution helper providing:
- **SQL Injection Testing:** Execute sqlmap for SQL injection vulnerability detection
- **Automated Testing:** Batch mode for automated testing
- **User Agent Randomization:** Random user agent for evasion
- **Configurable Parameters:** Support for additional sqlmap options

## Dependencies & Usage
- **Depends on:** execute_command function for command execution
- **Used by:** intelligent_smart_scan endpoint for sqlmap execution
- **Parameters:** target and params dictionary for configuration

## Implementation Details

### Parameter Processing (1 Parameter)
- **additional_args:** Additional sqlmap arguments (default: "--batch --random-agent")

### Command Construction
```python
cmd_parts = ['sqlmap', '-u', target]
if additional_args:
    cmd_parts.extend(additional_args.split())
```

### Default Configuration
- **Batch Mode:** --batch for non-interactive execution
- **Random Agent:** --random-agent for user agent randomization
- **URL Target:** -u flag for target URL specification

### SQLMap Features
- **SQL Injection Detection:** Comprehensive SQL injection testing
- **Database Enumeration:** Database structure and data enumeration
- **Evasion Techniques:** Built-in evasion and obfuscation
- **Multiple Database Support:** Support for various database systems

## Testing & Validation
- Parameter processing accuracy testing
- Command construction verification
- SQL injection detection validation

## Code Reproduction
```python
def execute_sqlmap_scan(target, params):
    """Execute sqlmap scan with optimized parameters"""
    try:
        additional_args = params.get('additional_args', '--batch --random-agent')
        cmd_parts = ['sqlmap', '-u', target]
        if additional_args:
            cmd_parts.extend(additional_args.split())
            
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```
