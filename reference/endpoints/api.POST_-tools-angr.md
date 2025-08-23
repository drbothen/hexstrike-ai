---
title: POST /api/tools/angr
group: api
handler: angr
module: __main__
line_range: [10629, 10718]
discovered_in_chunk: 11
---

# POST /api/tools/angr

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute angr for symbolic execution and binary analysis

## Complete Signature & Definition
```python
@app.route("/api/tools/angr", methods=["POST"])
def angr():
    """Execute angr for symbolic execution and binary analysis"""
```

## Purpose & Behavior
Symbolic execution and binary analysis endpoint providing:
- **Symbolic Execution:** Execute angr for advanced symbolic execution analysis
- **Control Flow Analysis:** Generate and analyze control flow graphs
- **Script Generation:** Support for custom angr scripts and analysis templates
- **Multi-analysis Support:** Support for symbolic, CFG, and static analysis types

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/angr
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",                 // Required: Path to binary file to analyze
    "script_content": "string",         // Optional: Custom angr script content
    "find_address": "string",           // Optional: Target address to find
    "avoid_addresses": "string",        // Optional: Comma-separated addresses to avoid
    "analysis_type": "string",          // Optional: Analysis type (default: "symbolic")
    "additional_args": "string"         // Optional: Additional arguments
}
```

### Parameters
- **binary:** Path to binary file for analysis (required)
- **script_content:** Custom angr script content (optional)
- **find_address:** Target address for symbolic execution (optional)
- **avoid_addresses:** Comma-separated addresses to avoid during execution (optional)
- **analysis_type:** Type of analysis - "symbolic", "cfg", "static" (optional, default: "symbolic")
- **additional_args:** Additional script arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Angr analysis output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 300.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "python3 /tmp/angr_analysis.py"
}
```

### Error Responses

#### Missing Binary (400 Bad Request)
```json
{
    "error": "Binary parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Script Generation Process
1. **Custom Script:** Use provided script content if available
2. **Template Generation:** Generate analysis template based on analysis type
3. **Target Configuration:** Configure find and avoid addresses for symbolic execution
4. **Script Execution:** Execute Python script with angr framework

### Analysis Types

#### Symbolic Execution (default)
```python
template += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
"""
```

#### Control Flow Graph Analysis
```python
template += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""
```

### Extended Timeout
```python
result = execute_command(command, timeout=600)  # Longer timeout for symbolic execution
```

### File Cleanup
```python
try:
    os.remove(script_file)
except:
    pass
```

### Angr Features
- **Symbolic Execution:** Advanced symbolic execution engine
- **Binary Analysis:** Comprehensive binary analysis capabilities
- **Control Flow Analysis:** Control flow graph generation and analysis
- **Constraint Solving:** Z3-based constraint solving

### Analysis Capabilities
- **Path Exploration:** Explore execution paths symbolically
- **Vulnerability Discovery:** Discover potential vulnerabilities
- **Input Generation:** Generate inputs to reach specific code paths
- **Static Analysis:** Perform static analysis on binaries

## AuthN/AuthZ
- **File System Access:** Requires access to binary files
- **Python Environment:** Requires angr Python framework installation

## Observability
- **Analysis Logging:** "🔧 Starting angr analysis: {binary}"
- **Completion Logging:** "📊 angr analysis completed"
- **Warning Logging:** "🔧 angr called without binary parameter"
- **Error Logging:** "💥 Error in angr endpoint: {error}"

## Use Cases and Applications

#### Vulnerability Research
- **Symbolic Execution:** Symbolically execute binaries to find vulnerabilities
- **Path Exploration:** Explore different execution paths
- **Input Generation:** Generate inputs to trigger specific behaviors

#### Reverse Engineering
- **Control Flow Analysis:** Analyze program control flow
- **Function Discovery:** Discover and analyze functions
- **Binary Understanding:** Understand binary behavior and structure

#### CTF Competitions
- **Challenge Solving:** Solve binary exploitation challenges
- **Automated Analysis:** Automate binary analysis workflows
- **Exploit Development:** Support exploit development with symbolic execution

## Testing & Validation
- Binary file path validation
- Script generation verification
- Analysis type functionality testing
- Timeout configuration validation

## Code Reproduction
Complete Flask endpoint implementation for angr symbolic execution and binary analysis with script generation support, multiple analysis types, and comprehensive binary analysis capabilities. Essential for advanced binary analysis and vulnerability research workflows.
