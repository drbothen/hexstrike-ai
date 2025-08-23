---
title: POST /api/intelligence/select-tools
group: api
handler: select_tools
module: __main__
line_range: [7685, 7710]
discovered_in_chunk: 7
---

# POST /api/intelligence/select-tools

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Select optimal tools for target assessment using AI

## Complete Signature & Definition
```python
@app.route("/api/intelligence/select-tools", methods=["POST"])
def select_tools():
    """Select optimal tools for target assessment using AI with enhanced logging"""
```

## Purpose & Behavior
AI-powered tool selection endpoint providing:
- **Tool Selection:** Select optimal tools for specific targets and objectives
- **Optimization:** Optimize tool selection based on target characteristics
- **Efficiency:** Maximize assessment efficiency through intelligent tool selection
- **Enhanced Logging:** Detailed logging of tool selection operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/intelligence/select-tools
- **Content-Type:** application/json

### Request Body
```json
{
    "target_profile": {
        "type": "string",             // Required: Target type
        "technologies": ["string"],   // Optional: Detected technologies
        "services": ["string"],       // Optional: Running services
        "ports": [integer],           // Optional: Open ports
        "os": "string",               // Optional: Operating system
        "characteristics": "object"   // Optional: Additional characteristics
    },
    "assessment_objectives": {
        "primary_goal": "string",     // Required: Primary assessment goal
        "secondary_goals": ["string"], // Optional: Secondary goals
        "scope": "string",            // Optional: Assessment scope
        "constraints": "object",      // Optional: Assessment constraints
        "compliance": ["string"]      // Optional: Compliance requirements
    },
    "selection_criteria": {
        "effectiveness": number,      // Optional: Effectiveness weight (default: 0.4)
        "efficiency": number,         // Optional: Efficiency weight (default: 0.3)
        "stealth": number,            // Optional: Stealth weight (default: 0.2)
        "accuracy": number,           // Optional: Accuracy weight (default: 0.1)
        "max_tools": integer,         // Optional: Maximum tools to select (default: 10)
        "exclude_tools": ["string"]   // Optional: Tools to exclude
    }
}
```

### Parameters
- **target_profile:** Target profile information (required)
  - **type:** Target type (required) - "web_app", "network", "host", "api", "mobile"
  - **technologies:** Detected technologies (optional)
  - **services:** Running services (optional)
  - **ports:** Open ports (optional)
  - **os:** Operating system (optional)
  - **characteristics:** Additional characteristics (optional)
- **assessment_objectives:** Assessment objectives (required)
  - **primary_goal:** Primary assessment goal (required) - "vulnerability_scan", "penetration_test", "compliance_check"
  - **secondary_goals:** Secondary goals (optional)
  - **scope:** Assessment scope (optional)
  - **constraints:** Assessment constraints (optional)
  - **compliance:** Compliance requirements (optional)
- **selection_criteria:** Tool selection criteria (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "selection_info": {
        "target_type": "web_app",
        "primary_goal": "vulnerability_scan",
        "tools_selected": 8,
        "selection_confidence": 0.92
    },
    "recommended_tools": [
        {
            "tool_name": "nmap",
            "category": "network_scanning",
            "priority": 1,
            "confidence": 0.95,
            "rationale": "Essential for port discovery and service enumeration",
            "parameters": {
                "scan_type": "-sV",
                "timing": "-T4",
                "additional_flags": ["--script=vuln"]
            },
            "expected_output": "Open ports, services, and basic vulnerabilities",
            "execution_time": "2-5 minutes"
        },
        {
            "tool_name": "nuclei",
            "category": "vulnerability_scanning",
            "priority": 2,
            "confidence": 0.88,
            "rationale": "Comprehensive vulnerability detection with extensive template library",
            "parameters": {
                "templates": ["cves", "exposures", "misconfiguration"],
                "rate_limit": "150",
                "severity": ["critical", "high", "medium"]
            },
            "expected_output": "Known vulnerabilities and misconfigurations",
            "execution_time": "5-15 minutes"
        }
    ],
    "execution_plan": {
        "phases": [
            {
                "phase": "reconnaissance",
                "tools": ["nmap", "subfinder"],
                "estimated_time": "10 minutes",
                "dependencies": []
            },
            {
                "phase": "vulnerability_scanning",
                "tools": ["nuclei", "nikto"],
                "estimated_time": "20 minutes",
                "dependencies": ["reconnaissance"]
            }
        ],
        "total_estimated_time": "30 minutes",
        "parallel_execution": true,
        "resource_requirements": {
            "cpu": "medium",
            "memory": "2GB",
            "network": "moderate"
        }
    },
    "alternative_tools": [
        {
            "tool_name": "gobuster",
            "reason": "Alternative for directory enumeration",
            "confidence": 0.75
        }
    ],
    "selection_metadata": {
        "algorithm_version": "v2.1",
        "factors_considered": ["target_type", "technologies", "objectives"],
        "selection_time": 1.2,
        "knowledge_base_version": "2024.01"
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: target_profile.type, assessment_objectives.primary_goal"
}
```

#### Invalid Target Type (400 Bad Request)
```json
{
    "error": "Invalid target type. Must be one of: web_app, network, host, api, mobile"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
target_profile = params.get("target_profile", {})
assessment_objectives = params.get("assessment_objectives", {})
selection_criteria = params.get("selection_criteria", {})

# Validate required fields
required_fields = [
    ("target_profile.type", target_profile.get("type")),
    ("assessment_objectives.primary_goal", assessment_objectives.get("primary_goal"))
]
missing_fields = [field for field, value in required_fields if not value]
if missing_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

# Validate target type
valid_types = ["web_app", "network", "host", "api", "mobile"]
if target_profile["type"] not in valid_types:
    return jsonify({"error": f"Invalid target type. Must be one of: {', '.join(valid_types)}"}), 400
```

### Tool Selection Logic
```python
# Use IntelligentDecisionEngine for tool selection
selection_request = {
    "target": target_profile,
    "objectives": assessment_objectives,
    "criteria": selection_criteria
}

# Select tools using decision engine
selection_result = decision_engine.select_optimal_tools(selection_request)

# Generate execution plan
execution_plan = decision_engine.create_execution_plan(selection_result)

# Identify alternative tools
alternatives = decision_engine.suggest_alternatives(selection_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Intelligence tool selection access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Invalid Parameters:** 400 error for invalid target types or goals
- **Selection Errors:** Handle errors during tool selection
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Tool Validation:** Validate selected tools for security and availability
- **Parameter Security:** Secure handling of tool parameters
- **Access Control:** Control access to tool selection capabilities
- **Audit Logging:** Log all tool selection operations

## Use Cases and Applications

#### Assessment Planning
- **Tool Optimization:** Optimize tool selection for specific targets
- **Efficiency Planning:** Plan efficient assessment workflows
- **Resource Management:** Manage assessment resources effectively

#### Automated Testing
- **Workflow Automation:** Automate tool selection for testing workflows
- **Adaptive Testing:** Adapt tool selection based on target characteristics
- **Quality Assurance:** Ensure optimal tool selection for assessments

## Testing & Validation
- Parameter validation accuracy testing
- Tool selection algorithm testing
- Execution plan generation testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/intelligence/select-tools", methods=["POST"])
def select_tools():
    """Select optimal tools for target assessment using AI with enhanced logging"""
    try:
        params = request.json
        target_profile = params.get("target_profile", {})
        assessment_objectives = params.get("assessment_objectives", {})
        selection_criteria = params.get("selection_criteria", {})
        
        # Validate required fields
        required_fields = [
            ("target_profile.type", target_profile.get("type")),
            ("assessment_objectives.primary_goal", assessment_objectives.get("primary_goal"))
        ]
        missing_fields = [field for field, value in required_fields if not value]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        # Validate target type
        valid_types = ["web_app", "network", "host", "api", "mobile"]
        if target_profile["type"] not in valid_types:
            return jsonify({"error": f"Invalid target type. Must be one of: {', '.join(valid_types)}"}), 400
        
        logger.info(f"🤖 Selecting tools for {target_profile['type']} | Goal: {assessment_objectives['primary_goal']}")
        
        start_time = time.time()
        
        # Use IntelligentDecisionEngine for tool selection
        selection_request = {
            "target": target_profile,
            "objectives": assessment_objectives,
            "criteria": selection_criteria
        }
        
        # Select tools using decision engine
        selection_result = decision_engine.select_optimal_tools(selection_request)
        
        # Generate execution plan
        execution_plan = decision_engine.create_execution_plan(selection_result)
        
        # Identify alternative tools
        alternatives = decision_engine.suggest_alternatives(selection_result)
        
        selection_time = time.time() - start_time
        
        selection_info = {
            "target_type": target_profile["type"],
            "primary_goal": assessment_objectives["primary_goal"],
            "tools_selected": len(selection_result["tools"]),
            "selection_confidence": selection_result.get("confidence", 0.0)
        }
        
        selection_metadata = {
            "algorithm_version": "v2.1",
            "factors_considered": selection_result.get("factors_considered", []),
            "selection_time": selection_time,
            "knowledge_base_version": "2024.01"
        }
        
        logger.info(f"🤖 Tool selection completed in {selection_time:.2f}s | Tools: {len(selection_result['tools'])}")
        
        return jsonify({
            "success": True,
            "selection_info": selection_info,
            "recommended_tools": selection_result["tools"],
            "execution_plan": execution_plan,
            "alternative_tools": alternatives,
            "selection_metadata": selection_metadata,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error selecting tools: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
