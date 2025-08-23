---
title: function.execute_nuclei_scan
kind: function
scope: module
module: __main__
line_range: [7990, 7996]
discovered_in_chunk: 7
---

# Function: execute_nuclei_scan

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute nuclei scan with optimized parameters

## Complete Signature & Definition
```python
def execute_nuclei_scan(target, params):
    """Execute nuclei scan with optimized parameters"""
    try:
        severity = params.get('severity', '')
        tags = params.get('tags', '')
        additional_args = params.get('additional_args', '')
        
        cmd_parts = ['nuclei', '-u', target]
        if severity:
            cmd_parts.extend(['-severity', severity])
        if tags:
            cmd_parts.extend(['-tags', tags])
        if additional_args:
            cmd_parts.extend(additional_args.split())
            
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```

## Purpose & Behavior
Nuclei execution helper providing:
- **Vulnerability Scanning:** Execute nuclei for template-based vulnerability scanning
- **Severity Filtering:** Support for severity-based filtering
- **Tag-based Selection:** Support for tag-based template selection
- **Parameter Optimization:** Configurable parameters for optimized scanning

## Dependencies & Usage
- **Depends on:** execute_command function for command execution
- **Used by:** intelligent_smart_scan endpoint for nuclei execution
- **Parameters:** target and params dictionary for configuration

## Implementation Details

### Parameter Processing (3 Parameters)
- **severity:** Severity level filtering (optional)
- **tags:** Tag-based template selection (optional)
- **additional_args:** Additional nuclei arguments (optional)

### Command Construction
```python
cmd_parts = ['nuclei', '-u', target]
if severity:
    cmd_parts.extend(['-severity', severity])
if tags:
    cmd_parts.extend(['-tags', tags])
if additional_args:
    cmd_parts.extend(additional_args.split())
```

### Nuclei Features
- **Template-based Scanning:** Use nuclei templates for vulnerability detection
- **Severity Filtering:** Filter by CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Tag-based Selection:** Select templates by tags (e.g., sqli, xss, rce)
- **Flexible Arguments:** Support for additional nuclei options

## Testing & Validation
- Parameter processing accuracy testing
- Command construction verification
- Severity and tag filtering validation

## Code Reproduction
```python
def execute_nuclei_scan(target, params):
    """Execute nuclei scan with optimized parameters"""
    try:
        severity = params.get('severity', '')
        tags = params.get('tags', '')
        additional_args = params.get('additional_args', '')
        
        cmd_parts = ['nuclei', '-u', target]
        if severity:
            cmd_parts.extend(['-severity', severity])
        if tags:
            cmd_parts.extend(['-tags', tags])
        if additional_args:
            cmd_parts.extend(additional_args.split())
            
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```
