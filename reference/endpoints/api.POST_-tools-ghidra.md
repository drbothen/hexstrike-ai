---
title: POST /api/tools/ghidra
group: api
handler: ghidra
module: __main__
line_range: [10385, 10423]
discovered_in_chunk: 10
---

# POST /api/tools/ghidra

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Ghidra for advanced binary analysis and reverse engineering

## Complete Signature & Definition
```python
@app.route("/api/tools/ghidra", methods=["POST"])
def ghidra():
    """Execute Ghidra for advanced binary analysis and reverse engineering"""
```

## Purpose & Behavior
Advanced binary analysis endpoint providing:
- **Headless Analysis:** Execute Ghidra in headless mode for automated binary analysis
- **Project Management:** Automatic project creation and management
- **Script Execution:** Support for custom Ghidra scripts and post-analysis scripts
- **Export Capabilities:** Export analysis results in various formats (XML, etc.)

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/ghidra
- **Content-Type:** application/json

### Request Body
```json
{
    "binary": "string",                 // Required: Path to binary file to analyze
    "project_name": "string",           // Optional: Project name (default: "hexstrike_analysis")
    "script_file": "string",            // Optional: Path to Ghidra script file
    "analysis_timeout": 300,            // Optional: Analysis timeout in seconds (default: 300)
    "output_format": "string",          // Optional: Output format (default: "xml")
    "additional_args": "string"         // Optional: Additional Ghidra arguments
}
```

### Parameters
- **binary:** Path to binary file for analysis (required)
- **project_name:** Ghidra project name (optional, default: "hexstrike_analysis")
- **script_file:** Path to custom Ghidra script (optional)
- **analysis_timeout:** Analysis timeout in seconds (optional, default: 300)
- **output_format:** Export format for results (optional, default: "xml")
- **additional_args:** Additional Ghidra arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Ghidra analysis output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 180.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "analyzeHeadless /tmp/ghidra_projects/hexstrike_analysis hexstrike_analysis -import /path/to/binary -deleteProject"
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

### Project Management
```python
project_dir = f"/tmp/ghidra_projects/{project_name}"
os.makedirs(project_dir, exist_ok=True)
```

### Command Construction Process
1. **Base Command:** Start with "analyzeHeadless {project_dir} {project_name}"
2. **Binary Import:** Add "-import {binary} -deleteProject"
3. **Script Execution:** Add post-analysis scripts if specified
4. **Export Configuration:** Configure output format and export
5. **Additional Arguments:** Append additional arguments

### Command Building Logic
```python
command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"

if script_file:
    command += f" -postScript {script_file}"

if output_format == "xml":
    command += f" -postScript ExportXml.java {project_dir}/analysis.xml"

if additional_args:
    command += f" {additional_args}"
```

### Timeout Configuration
```python
result = execute_command(command, timeout=analysis_timeout)
```

### Ghidra Features
- **Headless Analysis:** Automated analysis without GUI
- **Comprehensive Analysis:** Function analysis, data type recovery, cross-references
- **Script Support:** Custom analysis scripts and automation
- **Export Capabilities:** Multiple export formats for analysis results

### Analysis Capabilities
- **Function Discovery:** Automatic function identification and analysis
- **Data Type Recovery:** Recover data types and structures
- **Cross-Reference Analysis:** Analyze code and data cross-references
- **Control Flow Analysis:** Analyze program control flow
- **String Analysis:** Extract and analyze strings

## AuthN/AuthZ
- **File System Access:** Requires access to binary files and project directories
- **Ghidra Installation:** Requires Ghidra installation and configuration

## Observability
- **Analysis Logging:** "🔧 Starting Ghidra analysis: {binary}"
- **Completion Logging:** "📊 Ghidra analysis completed for {binary}"
- **Warning Logging:** "🔧 Ghidra called without binary parameter"
- **Error Logging:** "💥 Error in ghidra endpoint: {error}"

## Use Cases and Applications

#### Reverse Engineering
- **Binary Analysis:** Comprehensive binary reverse engineering
- **Malware Analysis:** Analyze malware samples and behavior
- **Firmware Analysis:** Analyze embedded firmware and IoT devices

#### Vulnerability Research
- **Code Analysis:** Analyze code for potential vulnerabilities
- **Exploit Development:** Support exploit development workflows
- **Security Assessment:** Assess binary security features

#### Software Analysis
- **Legacy Code Analysis:** Analyze legacy software without source code
- **Third-party Analysis:** Analyze third-party binaries and libraries
- **Compliance Analysis:** Analyze software for compliance requirements

## Testing & Validation
- Binary file path validation
- Project directory creation verification
- Script execution functionality testing
- Export format functionality validation

## Code Reproduction
```python
# From line 10385: Complete Flask endpoint implementation
@app.route("/api/tools/ghidra", methods=["POST"])
def ghidra():
    """Execute Ghidra for advanced binary analysis and reverse engineering"""
    try:
        params = request.json
        binary = params.get("binary", "")
        project_name = params.get("project_name", "hexstrike_analysis")
        script_file = params.get("script_file", "")
        analysis_timeout = params.get("analysis_timeout", 300)
        output_format = params.get("output_format", "xml")
        additional_args = params.get("additional_args", "")
        
        if not binary:
            logger.warning("🔧 Ghidra called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400
        
        # Create Ghidra project directory
        project_dir = f"/tmp/ghidra_projects/{project_name}"
        os.makedirs(project_dir, exist_ok=True)
        
        # Base Ghidra command for headless analysis
        command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"
        
        if script_file:
            command += f" -postScript {script_file}"
        
        if output_format == "xml":
            command += f" -postScript ExportXml.java {project_dir}/analysis.xml"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔧 Starting Ghidra analysis: {binary}")
        result = execute_command(command, timeout=analysis_timeout)
        logger.info(f"📊 Ghidra analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ghidra endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
