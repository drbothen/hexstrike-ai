---
title: function._rebuild_command_with_params
kind: function
scope: module
module: __main__
line_range: [7011, 7034]
discovered_in_chunk: 6
---

# Function: _rebuild_command_with_params

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Rebuild command with new parameters

## Complete Signature & Definition
```python
def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    # This is a simplified implementation - in practice, you'd need tool-specific logic
    # For now, we'll just append new parameters
    additional_args = []
    
    for key, value in new_params.items():
        if key == "timeout" and tool_name in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and tool_name in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and tool_name in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and tool_name == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and tool_name == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and tool_name == "nuclei":
            additional_args.append(f"-rl {value}")
    
    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"
    
    return original_command
```

## Purpose & Behavior
Command reconstruction utility providing:
- **Tool-specific Parameter Mapping:** Map generic parameters to tool-specific command-line arguments
- **Command Augmentation:** Add new parameters to existing commands
- **Parameter Translation:** Translate parameter names to appropriate command-line flags
- **Fallback Behavior:** Return original command if no applicable parameters

## Dependencies & Usage
- **Depends on:**
  - typing.Dict, Any for type annotations
- **Used by:**
  - execute_command_with_recovery function for parameter adjustment
  - Error recovery systems for command modification
  - Parameter optimization workflows

## Implementation Details

### Parameters
- **tool_name:** Name of the tool for parameter mapping (required)
- **original_command:** Original command string (required)
- **new_params:** Dictionary of new parameters to add (required)

### Return Value
- **Type:** str
- **Content:** Modified command string with additional parameters

### Tool-specific Parameter Mapping (6 Parameter Types)

#### Timeout Parameter
- **Tools:** ["nmap", "gobuster", "nuclei"]
- **Flag:** "--timeout {value}"
- **Purpose:** Set command execution timeout

#### Threads Parameter
- **Tools:** ["gobuster", "feroxbuster", "ffuf"]
- **Flag:** "-t {value}"
- **Purpose:** Set number of concurrent threads

#### Delay Parameter
- **Tools:** ["gobuster", "feroxbuster"]
- **Flag:** "--delay {value}"
- **Purpose:** Set delay between requests

#### Timing Parameter
- **Tools:** ["nmap"]
- **Flag:** "{value}" (direct value)
- **Purpose:** Set nmap timing template

#### Concurrency Parameter
- **Tools:** ["nuclei"]
- **Flag:** "-c {value}"
- **Purpose:** Set nuclei concurrency level

#### Rate Limit Parameter
- **Tools:** ["nuclei"]
- **Flag:** "-rl {value}"
- **Purpose:** Set nuclei rate limit

### Parameter Processing Logic

#### Parameter Iteration
```python
for key, value in new_params.items():
    # Tool-specific parameter mapping
```

#### Conditional Parameter Addition
- **Tool Matching:** Check if tool supports the parameter
- **Flag Generation:** Generate appropriate command-line flag
- **Argument Collection:** Collect all additional arguments

#### Command Reconstruction
```python
if additional_args:
    return f"{original_command} {' '.join(additional_args)}"
return original_command
```

### Tool Support Matrix

#### Network Scanning Tools
- **nmap:** timeout, timing parameters
- **gobuster:** timeout, threads, delay parameters
- **nuclei:** timeout, concurrency, rate-limit parameters

#### Web Testing Tools
- **feroxbuster:** threads, delay parameters
- **ffuf:** threads parameter

### Implementation Notes

#### Simplified Implementation
- **Current State:** Simplified parameter appending
- **Production Needs:** Tool-specific logic required for full implementation
- **Extension Points:** Easy to extend for additional tools and parameters

#### Parameter Validation
- **No Validation:** Current implementation doesn't validate parameter values
- **Future Enhancement:** Add parameter validation and sanitization
- **Error Handling:** Could add error handling for invalid parameters

### Use Cases and Applications

#### Error Recovery
- **Parameter Adjustment:** Adjust parameters during error recovery
- **Performance Tuning:** Modify parameters for better performance
- **Resource Management:** Adjust resource usage parameters

#### Dynamic Optimization
- **Runtime Optimization:** Optimize parameters based on runtime conditions
- **Context-aware Adjustment:** Adjust parameters based on target context
- **Performance Adaptation:** Adapt parameters for performance requirements

#### Testing and Development
- **Parameter Testing:** Test different parameter combinations
- **Development Support:** Support parameter experimentation
- **Debugging:** Modify parameters for debugging purposes

## Testing & Validation
- Tool-specific parameter mapping accuracy testing
- Command reconstruction correctness verification
- Parameter translation precision validation

## Code Reproduction
```python
def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    # This is a simplified implementation - in practice, you'd need tool-specific logic
    # For now, we'll just append new parameters
    additional_args = []
    
    for key, value in new_params.items():
        if key == "timeout" and tool_name in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and tool_name in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and tool_name in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and tool_name == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and tool_name == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and tool_name == "nuclei":
            additional_args.append(f"-rl {value}")
    
    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"
    
    return original_command
```
