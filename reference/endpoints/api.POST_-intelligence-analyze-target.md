---
title: POST /api/intelligence/analyze-target
group: api
handler: analyze_target
module: __main__
line_range: [7659, 7684]
discovered_in_chunk: 7
---

# POST /api/intelligence/analyze-target

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Analyze target using AI intelligence engine

## Complete Signature & Definition
```python
@app.route("/api/intelligence/analyze-target", methods=["POST"])
def analyze_target():
    """Analyze target using AI intelligence engine with enhanced logging"""
```

## Purpose & Behavior
AI-powered target analysis endpoint providing:
- **Target Analysis:** Comprehensive AI-powered target analysis
- **Intelligence Gathering:** Gather intelligence about target systems
- **Risk Assessment:** Assess target risk and attack surface
- **Enhanced Logging:** Detailed logging of analysis operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/intelligence/analyze-target
- **Content-Type:** application/json

### Request Body
```json
{
    "target": {
        "type": "string",             // Required: Target type (ip, domain, url, etc.)
        "value": "string",            // Required: Target value
        "description": "string",      // Optional: Target description
        "priority": "string",         // Optional: Analysis priority (default: normal)
        "scope": ["string"]           // Optional: Analysis scope
    },
    "analysis_options": {
        "depth": "string",            // Optional: Analysis depth (default: standard)
        "techniques": ["string"],     // Optional: Analysis techniques
        "timeout": integer,           // Optional: Analysis timeout (default: 300)
        "include_passive": boolean,   // Optional: Include passive analysis (default: true)
        "include_active": boolean,    // Optional: Include active analysis (default: false)
        "stealth_mode": boolean       // Optional: Stealth mode (default: true)
    },
    "intelligence_sources": {
        "osint": boolean,             // Optional: Use OSINT sources (default: true)
        "threat_intel": boolean,      // Optional: Use threat intelligence (default: true)
        "vulnerability_db": boolean,  // Optional: Use vulnerability databases (default: true)
        "custom_sources": ["string"] // Optional: Custom intelligence sources
    }
}
```

### Parameters
- **target:** Target information (required)
  - **type:** Target type (required) - "ip", "domain", "url", "network", "host"
  - **value:** Target value (required)
  - **description:** Target description (optional)
  - **priority:** Analysis priority (optional, default: "normal") - "low", "normal", "high", "critical"
  - **scope:** Analysis scope (optional)
- **analysis_options:** Analysis configuration options (optional)
- **intelligence_sources:** Intelligence source configuration (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "target_info": {
        "type": "domain",
        "value": "example.com",
        "priority": "normal",
        "analysis_id": "analysis_1234567890"
    },
    "analysis_results": {
        "target_profile": {
            "domain": "example.com",
            "ip_addresses": ["93.184.216.34"],
            "subdomains": ["www.example.com", "mail.example.com"],
            "technologies": ["Apache", "PHP", "MySQL"],
            "certificates": [
                {
                    "subject": "CN=example.com",
                    "issuer": "Let's Encrypt",
                    "valid_from": "2024-01-01",
                    "valid_to": "2024-04-01"
                }
            ]
        },
        "risk_assessment": {
            "overall_risk": "Medium",
            "risk_score": 6.5,
            "attack_surface": {
                "exposed_services": 5,
                "open_ports": [22, 80, 443],
                "web_applications": 2,
                "email_servers": 1
            },
            "vulnerabilities": [
                {
                    "type": "Outdated Software",
                    "severity": "Medium",
                    "description": "Apache version may have known vulnerabilities"
                }
            ]
        },
        "intelligence_findings": {
            "osint_data": {
                "social_media": ["twitter.com/example"],
                "employees": 25,
                "locations": ["New York", "London"]
            },
            "threat_intel": {
                "known_threats": 0,
                "reputation": "Clean",
                "blacklist_status": "Not listed"
            },
            "vulnerability_data": {
                "cve_matches": 3,
                "exploits_available": 1,
                "patch_status": "Partially patched"
            }
        }
    },
    "recommendations": [
        {
            "category": "Security",
            "priority": "High",
            "action": "Update Apache to latest version",
            "rationale": "Current version has known vulnerabilities"
        }
    ],
    "analysis_metadata": {
        "techniques_used": ["passive_dns", "certificate_analysis", "osint"],
        "sources_queried": ["virustotal", "shodan", "censys"],
        "analysis_time": 45.3,
        "confidence_score": 0.85
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: target.type, target.value"
}
```

#### Invalid Target Type (400 Bad Request)
```json
{
    "error": "Invalid target type. Must be one of: ip, domain, url, network, host"
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
target = params.get("target", {})
analysis_options = params.get("analysis_options", {})
intelligence_sources = params.get("intelligence_sources", {})

# Validate required target fields
required_fields = ["type", "value"]
missing_fields = [field for field in required_fields if not target.get(field)]
if missing_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(['target.' + field for field in missing_fields])}"}), 400

# Validate target type
valid_types = ["ip", "domain", "url", "network", "host"]
if target["type"] not in valid_types:
    return jsonify({"error": f"Invalid target type. Must be one of: {', '.join(valid_types)}"}), 400
```

### Analysis Logic
```python
# Use IntelligentDecisionEngine for analysis
analysis_request = {
    "target": target,
    "options": analysis_options,
    "sources": intelligence_sources
}

# Perform analysis using decision engine
analysis_result = decision_engine.analyze_target(analysis_request)

# Generate recommendations based on findings
recommendations = decision_engine.generate_recommendations(analysis_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Intelligence analysis access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Invalid Parameters:** 400 error for invalid target types
- **Analysis Errors:** Handle errors during target analysis
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Validate targets to prevent unauthorized analysis
- **Rate Limiting:** Implement rate limiting for analysis requests
- **Data Privacy:** Protect sensitive intelligence data
- **Responsible Use:** Emphasize responsible use of intelligence capabilities

## Use Cases and Applications

#### Threat Intelligence
- **Target Profiling:** Profile targets for security assessment
- **Risk Assessment:** Assess target risk and vulnerabilities
- **Intelligence Gathering:** Gather intelligence about target systems

#### Security Operations
- **Incident Response:** Analyze targets during incident response
- **Threat Hunting:** Hunt for threats using target analysis
- **Vulnerability Management:** Identify vulnerabilities in targets

## Testing & Validation
- Parameter validation accuracy testing
- Analysis functionality verification testing
- Intelligence source integration testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/intelligence/analyze-target", methods=["POST"])
def analyze_target():
    """Analyze target using AI intelligence engine with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", {})
        analysis_options = params.get("analysis_options", {})
        intelligence_sources = params.get("intelligence_sources", {})
        
        # Validate required target fields
        required_fields = ["type", "value"]
        missing_fields = [field for field in required_fields if not target.get(field)]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(['target.' + field for field in missing_fields])}"}), 400
        
        # Validate target type
        valid_types = ["ip", "domain", "url", "network", "host"]
        if target["type"] not in valid_types:
            return jsonify({"error": f"Invalid target type. Must be one of: {', '.join(valid_types)}"}), 400
        
        logger.info(f"🤖 Analyzing target: {target['type']} - {target['value']}")
        
        start_time = time.time()
        
        # Generate analysis ID
        analysis_id = f"analysis_{int(time.time() * 1000000)}"
        
        # Use IntelligentDecisionEngine for analysis
        analysis_request = {
            "target": target,
            "options": analysis_options,
            "sources": intelligence_sources,
            "analysis_id": analysis_id
        }
        
        # Perform analysis using decision engine
        analysis_result = decision_engine.analyze_target(analysis_request)
        
        # Generate recommendations based on findings
        recommendations = decision_engine.generate_recommendations(analysis_result)
        
        analysis_time = time.time() - start_time
        
        target_info = {
            "type": target["type"],
            "value": target["value"],
            "priority": target.get("priority", "normal"),
            "analysis_id": analysis_id
        }
        
        analysis_metadata = {
            "techniques_used": analysis_result.get("techniques_used", []),
            "sources_queried": analysis_result.get("sources_queried", []),
            "analysis_time": analysis_time,
            "confidence_score": analysis_result.get("confidence_score", 0.0)
        }
        
        logger.info(f"🤖 Target analysis completed in {analysis_time:.2f}s | Risk: {analysis_result.get('risk_assessment', {}).get('overall_risk', 'Unknown')}")
        
        return jsonify({
            "success": True,
            "target_info": target_info,
            "analysis_results": analysis_result,
            "recommendations": recommendations,
            "analysis_metadata": analysis_metadata,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error analyzing target: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
