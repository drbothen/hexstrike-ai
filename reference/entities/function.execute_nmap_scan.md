---
title: function.execute_nmap_scan
kind: function
scope: module
module: __main__
line_range: [7956, 7973]
discovered_in_chunk: 7
---

# Function: execute_nmap_scan

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute nmap scan with optimized parameters

## Complete Signature & Definition
```python
def execute_nmap_scan(target, params):
    """Execute nmap scan with optimized parameters"""
    try:
        scan_type = params.get('scan_type', '-sV')
        ports = params.get('ports', '')
        additional_args = params.get('additional_args', '')
        
        # Build nmap command
        cmd_parts = ['nmap', scan_type]
        if ports:
            cmd_parts.extend(['-p', ports])
        if additional_args:
            cmd_parts.extend(additional_args.split())
        cmd_parts.append(target)
        
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```

## Purpose & Behavior
Nmap execution helper providing:
- **Parameter-driven Execution:** Execute nmap with configurable parameters
- **Command Construction:** Build nmap command from parameters
- **Error Handling:** Graceful error handling with structured response
- **Integration Support:** Support for intelligent smart scan integration

## Dependencies & Usage
- **Depends on:** execute_command function for command execution
- **Used by:** intelligent_smart_scan endpoint for nmap execution
- **Parameters:** target and params dictionary for configuration

## Implementation Details

### Parameter Processing (3 Parameters)
- **scan_type:** Nmap scan type (default: "-sV")
- **ports:** Port specification (optional)
- **additional_args:** Additional nmap arguments (optional)

### Command Construction
```python
cmd_parts = ['nmap', scan_type]
if ports:
    cmd_parts.extend(['-p', ports])
if additional_args:
    cmd_parts.extend(additional_args.split())
cmd_parts.append(target)
```

### Error Handling
- **Exception Catching:** Catch all exceptions during execution
- **Error Response:** Return structured error response
- **Graceful Degradation:** Continue operation despite errors

## Testing & Validation
- Parameter processing accuracy testing
- Command construction verification
- Error handling behavior validation

## Code Reproduction
```python
def execute_nmap_scan(target, params):
    """Execute nmap scan with optimized parameters"""
    try:
        scan_type = params.get('scan_type', '-sV')
        ports = params.get('ports', '')
        additional_args = params.get('additional_args', '')
        
        # Build nmap command
        cmd_parts = ['nmap', scan_type]
        if ports:
            cmd_parts.extend(['-p', ports])
        if additional_args:
            cmd_parts.extend(additional_args.split())
        cmd_parts.append(target)
        
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```
