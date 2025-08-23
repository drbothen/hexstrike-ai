---
title: function.execute_gobuster_scan
kind: function
scope: module
module: __main__
line_range: [7975, 7988]
discovered_in_chunk: 7
---

# Function: execute_gobuster_scan

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute gobuster scan with optimized parameters

## Complete Signature & Definition
```python
def execute_gobuster_scan(target, params):
    """Execute gobuster scan with optimized parameters"""
    try:
        mode = params.get('mode', 'dir')
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        additional_args = params.get('additional_args', '')
        
        cmd_parts = ['gobuster', mode, '-u', target, '-w', wordlist]
        if additional_args:
            cmd_parts.extend(additional_args.split())
            
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```

## Purpose & Behavior
Gobuster execution helper providing:
- **Directory Brute-forcing:** Execute gobuster for directory and file discovery
- **Configurable Parameters:** Support for mode, wordlist, and additional arguments
- **Command Construction:** Build gobuster command from parameters
- **Error Handling:** Graceful error handling with structured response

## Dependencies & Usage
- **Depends on:** execute_command function for command execution
- **Used by:** intelligent_smart_scan endpoint for gobuster execution
- **Parameters:** target and params dictionary for configuration

## Implementation Details

### Parameter Processing (3 Parameters)
- **mode:** Gobuster mode (default: "dir")
- **wordlist:** Wordlist file path (default: "/usr/share/wordlists/dirb/common.txt")
- **additional_args:** Additional gobuster arguments (optional)

### Command Construction
```python
cmd_parts = ['gobuster', mode, '-u', target, '-w', wordlist]
if additional_args:
    cmd_parts.extend(additional_args.split())
```

### Default Configuration
- **Default Mode:** "dir" for directory brute-forcing
- **Default Wordlist:** Common dirb wordlist for broad coverage
- **Flexible Arguments:** Support for additional gobuster options

## Testing & Validation
- Parameter processing accuracy testing
- Command construction verification
- Wordlist path validation
- Error handling behavior validation

## Code Reproduction
```python
def execute_gobuster_scan(target, params):
    """Execute gobuster scan with optimized parameters"""
    try:
        mode = params.get('mode', 'dir')
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        additional_args = params.get('additional_args', '')
        
        cmd_parts = ['gobuster', mode, '-u', target, '-w', wordlist]
        if additional_args:
            cmd_parts.extend(additional_args.split())
            
        return execute_command(' '.join(cmd_parts))
    except Exception as e:
        return {"success": False, "error": str(e)}
```
