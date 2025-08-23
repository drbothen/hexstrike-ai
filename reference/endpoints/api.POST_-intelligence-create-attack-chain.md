---
title: POST /api/intelligence/create-attack-chain
group: api
handler: create_attack_chain
module: __main__
line_range: [7737, 7762]
discovered_in_chunk: 7
---

# POST /api/intelligence/create-attack-chain

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Create intelligent attack chain using AI decision engine

## Complete Signature & Definition
```python
@app.route("/api/intelligence/create-attack-chain", methods=["POST"])
def create_attack_chain():
    """Create intelligent attack chain using AI decision engine with enhanced logging"""
```

## Purpose & Behavior
AI-powered attack chain creation endpoint providing:
- **Attack Chain Generation:** Generate intelligent attack chains for penetration testing
- **Step Optimization:** Optimize attack steps for maximum effectiveness
- **Adaptive Planning:** Adapt attack plans based on target characteristics
- **Enhanced Logging:** Detailed logging of attack chain creation operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/intelligence/create-attack-chain
- **Content-Type:** application/json

### Request Body
```json
{
    "target_info": {
        "target_type": "string",      // Required: Target type
        "target_value": "string",     // Required: Target value
        "known_vulnerabilities": ["object"], // Optional: Known vulnerabilities
        "services": ["object"],       // Optional: Running services
        "technologies": ["string"],   // Optional: Detected technologies
        "access_level": "string"      // Optional: Current access level
    },
    "attack_objectives": {
        "primary_goal": "string",     // Required: Primary attack goal
        "secondary_goals": ["string"], // Optional: Secondary goals
        "constraints": "object",      // Optional: Attack constraints
        "stealth_level": "string",    // Optional: Stealth requirement
        "time_limit": integer         // Optional: Time limit in minutes
    },
    "chain_options": {
        "max_steps": integer,         // Optional: Maximum steps (default: 10)
        "complexity": "string",       // Optional: Chain complexity (default: medium)
        "risk_tolerance": "string",   // Optional: Risk tolerance (default: medium)
        "include_persistence": boolean, // Optional: Include persistence (default: true)
        "include_privilege_escalation": boolean, // Optional: Include privesc (default: true)
        "include_lateral_movement": boolean // Optional: Include lateral movement (default: false)
    }
}
```

### Parameters
- **target_info:** Target information (required)
  - **target_type:** Target type (required) - "host", "network", "web_app", "api"
  - **target_value:** Target value (required)
  - **known_vulnerabilities:** Known vulnerabilities (optional)
  - **services:** Running services (optional)
  - **technologies:** Detected technologies (optional)
  - **access_level:** Current access level (optional) - "none", "user", "admin", "root"
- **attack_objectives:** Attack objectives (required)
  - **primary_goal:** Primary attack goal (required) - "reconnaissance", "exploitation", "persistence", "exfiltration"
  - **secondary_goals:** Secondary goals (optional)
  - **constraints:** Attack constraints (optional)
  - **stealth_level:** Stealth requirement (optional) - "low", "medium", "high"
  - **time_limit:** Time limit in minutes (optional)
- **chain_options:** Chain generation options (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "chain_info": {
        "target_type": "web_app",
        "primary_goal": "exploitation",
        "total_steps": 6,
        "estimated_time": 45,
        "complexity": "medium",
        "success_probability": 0.78
    },
    "attack_chain": {
        "chain_id": "chain_1234567890",
        "steps": [
            {
                "step_id": 1,
                "phase": "reconnaissance",
                "action": "port_scan",
                "tool": "nmap",
                "parameters": {
                    "scan_type": "-sS",
                    "timing": "-T4",
                    "target": "192.168.1.100"
                },
                "expected_output": "Open ports and services",
                "success_criteria": "Identify web services",
                "estimated_time": 5,
                "risk_level": "low",
                "dependencies": [],
                "alternatives": ["masscan", "rustscan"]
            },
            {
                "step_id": 2,
                "phase": "vulnerability_discovery",
                "action": "web_vulnerability_scan",
                "tool": "nuclei",
                "parameters": {
                    "templates": ["cves", "exposures"],
                    "target": "http://192.168.1.100"
                },
                "expected_output": "Web vulnerabilities",
                "success_criteria": "Find exploitable vulnerabilities",
                "estimated_time": 15,
                "risk_level": "medium",
                "dependencies": [1],
                "alternatives": ["nikto", "dirb"]
            }
        ],
        "execution_plan": {
            "sequential_steps": [1, 2, 3],
            "parallel_steps": [[4, 5], [6]],
            "critical_path": [1, 2, 3, 6],
            "fallback_options": {
                "step_2_fail": "Use manual testing",
                "step_3_fail": "Try alternative exploit"
            }
        }
    },
    "risk_assessment": {
        "overall_risk": "Medium",
        "legal_considerations": ["Ensure proper authorization"],
        "technical_risks": ["Potential service disruption"],
        "detection_probability": 0.35,
        "mitigation_strategies": ["Use rate limiting", "Monitor for detection"]
    },
    "recommendations": [
        {
            "category": "Preparation",
            "suggestion": "Verify target authorization before execution",
            "priority": "Critical"
        },
        {
            "category": "Execution",
            "suggestion": "Monitor target response times to avoid detection",
            "priority": "High"
        }
    ],
    "chain_metadata": {
        "generation_algorithm": "intelligent_planning_v2",
        "knowledge_base_version": "2024.01",
        "generation_time": 8.3,
        "confidence_score": 0.82
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: target_info.target_type, attack_objectives.primary_goal"
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
target_info = params.get("target_info", {})
attack_objectives = params.get("attack_objectives", {})
chain_options = params.get("chain_options", {})

# Validate required fields
required_fields = [
    ("target_info.target_type", target_info.get("target_type")),
    ("target_info.target_value", target_info.get("target_value")),
    ("attack_objectives.primary_goal", attack_objectives.get("primary_goal"))
]
missing_fields = [field for field, value in required_fields if not value]
if missing_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
```

### Attack Chain Creation Logic
```python
# Use IntelligentDecisionEngine for attack chain creation
chain_request = {
    "target": target_info,
    "objectives": attack_objectives,
    "options": chain_options
}

# Create attack chain using decision engine
chain_result = decision_engine.create_attack_chain(chain_request)

# Assess risks and generate recommendations
risk_assessment = decision_engine.assess_attack_risks(chain_result)
recommendations = decision_engine.generate_attack_recommendations(chain_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Attack chain creation access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Chain Creation Errors:** Handle errors during attack chain creation
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Authorization Verification:** Verify proper authorization before creating attack chains
- **Ethical Use:** Emphasize ethical use of attack chain capabilities
- **Legal Compliance:** Ensure compliance with legal requirements
- **Audit Logging:** Log all attack chain creation operations

## Use Cases and Applications

#### Penetration Testing
- **Attack Planning:** Plan comprehensive penetration testing attacks
- **Methodology Development:** Develop systematic attack methodologies
- **Training Scenarios:** Create training scenarios for security professionals

#### Red Team Operations
- **Operation Planning:** Plan red team operations and exercises
- **Scenario Development:** Develop realistic attack scenarios
- **Capability Assessment:** Assess organizational security capabilities

## Testing & Validation
- Parameter validation accuracy testing
- Attack chain generation testing
- Risk assessment accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/intelligence/create-attack-chain", methods=["POST"])
def create_attack_chain():
    """Create intelligent attack chain using AI decision engine with enhanced logging"""
    try:
        params = request.json
        target_info = params.get("target_info", {})
        attack_objectives = params.get("attack_objectives", {})
        chain_options = params.get("chain_options", {})
        
        # Validate required fields
        required_fields = [
            ("target_info.target_type", target_info.get("target_type")),
            ("target_info.target_value", target_info.get("target_value")),
            ("attack_objectives.primary_goal", attack_objectives.get("primary_goal"))
        ]
        missing_fields = [field for field, value in required_fields if not value]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        logger.info(f"🤖 Creating attack chain for {target_info['target_type']} | Goal: {attack_objectives['primary_goal']}")
        
        start_time = time.time()
        
        # Generate chain ID
        chain_id = f"chain_{int(time.time() * 1000000)}"
        
        # Use IntelligentDecisionEngine for attack chain creation
        chain_request = {
            "target": target_info,
            "objectives": attack_objectives,
            "options": chain_options,
            "chain_id": chain_id
        }
        
        # Create attack chain using decision engine
        chain_result = decision_engine.create_attack_chain(chain_request)
        
        # Assess risks and generate recommendations
        risk_assessment = decision_engine.assess_attack_risks(chain_result)
        recommendations = decision_engine.generate_attack_recommendations(chain_result)
        
        generation_time = time.time() - start_time
        
        chain_info = {
            "target_type": target_info["target_type"],
            "primary_goal": attack_objectives["primary_goal"],
            "total_steps": len(chain_result["steps"]),
            "estimated_time": sum(step.get("estimated_time", 0) for step in chain_result["steps"]),
            "complexity": chain_options.get("complexity", "medium"),
            "success_probability": chain_result.get("success_probability", 0.0)
        }
        
        chain_metadata = {
            "generation_algorithm": "intelligent_planning_v2",
            "knowledge_base_version": "2024.01",
            "generation_time": generation_time,
            "confidence_score": chain_result.get("confidence_score", 0.0)
        }
        
        logger.info(f"🤖 Attack chain created in {generation_time:.2f}s | Steps: {len(chain_result['steps'])}")
        
        return jsonify({
            "success": True,
            "chain_info": chain_info,
            "attack_chain": chain_result,
            "risk_assessment": risk_assessment,
            "recommendations": recommendations,
            "chain_metadata": chain_metadata,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error creating attack chain: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
