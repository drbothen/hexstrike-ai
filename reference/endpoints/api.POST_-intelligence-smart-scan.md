---
title: POST /api/intelligence/smart-scan
group: api
handler: intelligent_smart_scan
module: __main__
line_range: [7803, 7953]
discovered_in_chunk: 7
---

# POST /api/intelligence/smart-scan

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute an intelligent scan using AI-driven tool selection and parameter optimization with parallel execution

## Complete Signature & Definition
```python
@app.route("/api/intelligence/smart-scan", methods=["POST"])
def intelligent_smart_scan():
    """Execute an intelligent scan using AI-driven tool selection and parameter optimization with parallel execution"""
```

## Purpose & Behavior
Intelligent automated scanning endpoint providing:
- **AI-Driven Tool Selection:** Automatic selection of optimal security tools based on target analysis
- **Parameter Optimization:** Intelligent parameter optimization for each selected tool
- **Parallel Execution:** Concurrent execution of multiple tools using ThreadPoolExecutor
- **Vulnerability Detection:** Automatic vulnerability detection and counting
- **Comprehensive Reporting:** Detailed scan results with execution summary and combined output

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/intelligence/smart-scan
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",         // Required: Target to scan (IP, domain, URL)
    "objective": "string",      // Optional: Scan objective (default: "comprehensive")
    "max_tools": 5              // Optional: Maximum number of tools to use (default: 5)
}
```

### Parameters
- **target:** Target to scan - IP address, domain, or URL (required)
- **objective:** Scan objective - "comprehensive", "quick", or "stealth" (optional, default: "comprehensive")
- **max_tools:** Maximum number of tools to execute in parallel (optional, default: 5)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "scan_results": {
        "target": "example.com",
        "target_profile": {
            "target_type": "web_application",
            "technologies": ["nginx", "php"],
            "risk_level": "medium",
            "confidence": 0.85
        },
        "tools_executed": [
            {
                "tool": "nmap",
                "parameters": {"scan_type": "-sV", "ports": "80,443"},
                "status": "success",
                "timestamp": "2024-01-01T12:00:00Z",
                "execution_time": 15.2,
                "stdout": "...",
                "stderr": "",
                "vulnerabilities_found": 2,
                "command": "nmap -sV -p 80,443 example.com",
                "success": true
            }
        ],
        "total_vulnerabilities": 5,
        "execution_summary": {
            "total_tools": 5,
            "successful_tools": 4,
            "failed_tools": 1,
            "success_rate": 80.0,
            "total_execution_time": 45.7,
            "tools_used": ["nmap", "gobuster", "nuclei", "nikto"]
        },
        "combined_output": "=== NMAP OUTPUT ===\n...\n=== GOBUSTER OUTPUT ===\n..."
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}",
    "success": false
}
```

## Implementation Details

### Intelligent Scan Process
1. **Target Analysis:** Analyze target using IntelligentDecisionEngine
2. **Tool Selection:** Select optimal tools based on target profile and objective
3. **Tool Limiting:** Limit to max_tools for performance
4. **Parallel Execution:** Execute tools concurrently using ThreadPoolExecutor
5. **Result Aggregation:** Collect and aggregate results from all tools
6. **Vulnerability Detection:** Count vulnerabilities using pattern matching
7. **Summary Generation:** Generate execution summary and combined output

### Target Analysis Integration
```python
profile = decision_engine.analyze_target(target)
selected_tools = decision_engine.select_optimal_tools(profile, objective)[:max_tools]
```

### Tool Execution Mapping (16 Supported Tools)
- **nmap:** Network mapping and port scanning
- **gobuster:** Directory and file brute-forcing
- **nuclei:** Vulnerability scanner with templates
- **nikto:** Web server scanner
- **sqlmap:** SQL injection testing
- **ffuf:** Fast web fuzzer
- **feroxbuster:** Fast content discovery
- **katana:** Web crawling
- **httpx:** HTTP toolkit
- **wpscan:** WordPress scanner
- **dirsearch:** Web path scanner
- **arjun:** HTTP parameter discovery
- **paramspider:** Parameter mining
- **dalfox:** XSS scanner
- **amass:** Attack surface mapping
- **subfinder:** Subdomain discovery

### Parallel Execution System

#### ThreadPoolExecutor Configuration
```python
with ThreadPoolExecutor(max_workers=min(len(selected_tools), 5)) as executor:
    future_to_tool = {
        executor.submit(execute_single_tool, tool, target, profile): tool 
        for tool in selected_tools
    }
```

#### Concurrent Processing
- **Worker Limit:** Maximum 5 concurrent workers
- **Tool Mapping:** Map futures to tool names for result tracking
- **Result Collection:** Collect results as they complete
- **Error Isolation:** Individual tool failures don't affect others

### Vulnerability Detection Algorithm

#### Pattern-based Detection
```python
vuln_indicators = ['CRITICAL', 'HIGH', 'MEDIUM', 'VULNERABILITY', 'EXPLOIT', 'SQL injection', 'XSS', 'CSRF']
vuln_count = sum(1 for indicator in vuln_indicators if indicator.lower() in output.lower())
```

#### Detection Categories
- **Severity Levels:** CRITICAL, HIGH, MEDIUM
- **Vulnerability Types:** SQL injection, XSS, CSRF
- **General Indicators:** VULNERABILITY, EXPLOIT

### Tool Result Structure

#### Individual Tool Result
```python
{
    "tool": str,                    # Tool name
    "parameters": Dict[str, Any],   # Optimized parameters used
    "status": str,                  # "success", "failed", or "skipped"
    "timestamp": str,               # ISO timestamp
    "execution_time": float,        # Execution duration in seconds
    "stdout": str,                  # Tool output
    "stderr": str,                  # Error output
    "vulnerabilities_found": int,   # Number of vulnerabilities detected
    "command": str,                 # Actual command executed
    "success": bool                 # Success flag
}
```

#### Error Handling for Tools
- **Execution Errors:** Capture and log tool execution errors
- **Missing Mappings:** Handle tools without execution mappings
- **Graceful Degradation:** Continue scan despite individual tool failures

### Result Aggregation

#### Vulnerability Counting
```python
if tool_result.get("vulnerabilities_found"):
    scan_results["total_vulnerabilities"] += tool_result["vulnerabilities_found"]
```

#### Output Combination
```python
scan_results["combined_output"] += f"\n=== {tool_result['tool'].upper()} OUTPUT ===\n"
scan_results["combined_output"] += tool_result["stdout"]
scan_results["combined_output"] += "\n" + "="*50 + "\n"
```

### Execution Summary Generation

#### Summary Metrics
```python
{
    "total_tools": int,             # Total tools selected
    "successful_tools": int,        # Successfully executed tools
    "failed_tools": int,            # Failed tool executions
    "success_rate": float,          # Success rate percentage
    "total_execution_time": float,  # Combined execution time
    "tools_used": List[str]         # List of successful tools
}
```

#### Success Rate Calculation
```python
success_rate = len(successful_tools) / len(selected_tools) * 100 if selected_tools else 0
```

### Error Handling and Resilience

#### Tool Execution Errors
- **Individual Isolation:** Tool failures don't affect other tools
- **Error Logging:** Comprehensive error logging for debugging
- **Status Tracking:** Track success/failure status for each tool

#### Missing Tool Mappings
- **Graceful Handling:** Skip tools without execution mappings
- **Warning Logging:** Log warnings for unmapped tools
- **Continued Execution:** Continue scan with available tools

### Integration with Decision Engine

#### Target Profile Integration
- **Profile Analysis:** Use decision engine for target analysis
- **Tool Selection:** Leverage AI-driven tool selection
- **Parameter Optimization:** Apply intelligent parameter optimization

#### Context-Aware Execution
- **Target-Specific:** Customize execution based on target characteristics
- **Objective-Driven:** Adapt tool selection based on scan objective
- **Profile-Optimized:** Optimize parameters based on target profile

### Performance Optimization

#### Parallel Processing
- **Concurrent Execution:** Execute multiple tools simultaneously
- **Resource Management:** Limit concurrent workers to prevent overload
- **Efficient Collection:** Collect results as they become available

#### Intelligent Selection
- **Tool Limiting:** Limit tools to prevent excessive execution time
- **Optimal Selection:** Select most effective tools for target
- **Parameter Optimization:** Use optimized parameters for better performance

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Scanning access required

## Observability
- **Scan Logging:** Comprehensive logging of scan initiation and completion
- **Tool Logging:** Individual tool execution logging
- **Result Logging:** Summary logging with vulnerability counts

## Use Cases and Applications

#### Automated Security Testing
- **Comprehensive Scanning:** Automated comprehensive security scanning
- **Target-Specific Testing:** Customized testing based on target analysis
- **Parallel Efficiency:** Efficient parallel execution of multiple tools

#### Penetration Testing
- **Initial Reconnaissance:** Automated initial reconnaissance phase
- **Vulnerability Discovery:** Systematic vulnerability discovery
- **Tool Orchestration:** Intelligent orchestration of security tools

#### Security Assessment
- **Risk Assessment:** Automated risk assessment with vulnerability counting
- **Coverage Analysis:** Comprehensive coverage with multiple tool types
- **Efficiency Optimization:** Optimized scanning with intelligent tool selection

## Testing & Validation
- Target analysis accuracy testing
- Tool selection optimization verification
- Parallel execution performance validation
- Vulnerability detection accuracy assessment

## Code Reproduction
Complete Flask endpoint implementation for intelligent automated scanning with AI-driven tool selection, parallel execution, vulnerability detection, and comprehensive reporting. Essential for automated security testing and penetration testing workflows.
