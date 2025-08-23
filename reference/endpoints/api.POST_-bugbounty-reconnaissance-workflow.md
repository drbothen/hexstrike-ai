---
title: POST /api/bugbounty/reconnaissance-workflow
group: api
handler: reconnaissance_workflow
module: __main__
line_range: [8231, 8256]
discovered_in_chunk: 8
---

# POST /api/bugbounty/reconnaissance-workflow

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute comprehensive reconnaissance workflow for bug bounty

## Complete Signature & Definition
```python
@app.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
def reconnaissance_workflow():
    """Execute comprehensive reconnaissance workflow for bug bounty with enhanced logging"""
```

## Purpose & Behavior
Bug bounty reconnaissance workflow endpoint providing:
- **Comprehensive Reconnaissance:** Execute systematic reconnaissance for bug bounty targets
- **Multi-Phase Discovery:** Perform multi-phase target discovery and enumeration
- **Intelligence Gathering:** Gather comprehensive intelligence about targets
- **Enhanced Logging:** Detailed logging of reconnaissance operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/bugbounty/reconnaissance-workflow
- **Content-Type:** application/json

### Request Body
```json
{
    "target": {
        "domain": "string",           // Required: Target domain
        "scope": ["string"],          // Optional: In-scope domains/IPs
        "out_of_scope": ["string"],   // Optional: Out-of-scope items
        "program_type": "string",     // Optional: Bug bounty program type
        "priority": "string"          // Optional: Target priority
    },
    "reconnaissance_options": {
        "depth": "string",            // Optional: Reconnaissance depth (default: standard)
        "stealth_mode": boolean,      // Optional: Stealth mode (default: true)
        "passive_only": boolean,      // Optional: Passive reconnaissance only (default: false)
        "include_subdomains": boolean, // Optional: Include subdomain enumeration (default: true)
        "include_ports": boolean,     // Optional: Include port scanning (default: true)
        "include_technologies": boolean, // Optional: Include technology detection (default: true)
        "include_certificates": boolean, // Optional: Include certificate analysis (default: true)
        "timeout": integer            // Optional: Overall timeout (default: 3600)
    },
    "workflow_config": {
        "phases": ["string"],         // Optional: Specific phases to execute
        "parallel_execution": boolean, // Optional: Enable parallel execution (default: true)
        "rate_limiting": "object",    // Optional: Rate limiting configuration
        "output_format": "string",    // Optional: Output format (default: json)
        "save_results": boolean       // Optional: Save results to file (default: true)
    }
}
```

### Parameters
- **target:** Target information (required)
  - **domain:** Target domain (required)
  - **scope:** In-scope domains/IPs (optional)
  - **out_of_scope:** Out-of-scope items (optional)
  - **program_type:** Bug bounty program type (optional) - "web", "mobile", "api", "iot"
  - **priority:** Target priority (optional) - "low", "medium", "high", "critical"
- **reconnaissance_options:** Reconnaissance configuration (optional)
- **workflow_config:** Workflow configuration (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "workflow_info": {
        "target_domain": "example.com",
        "program_type": "web",
        "phases_executed": ["subdomain_enum", "port_scan", "tech_detection"],
        "total_execution_time": 1245.7,
        "stealth_mode": true
    },
    "reconnaissance_results": {
        "subdomains": {
            "total_found": 156,
            "active_subdomains": 142,
            "subdomains": [
                {
                    "subdomain": "www.example.com",
                    "ip": "93.184.216.34",
                    "status": "active",
                    "technologies": ["Apache", "PHP"]
                },
                {
                    "subdomain": "api.example.com",
                    "ip": "93.184.216.35",
                    "status": "active",
                    "technologies": ["Nginx", "Node.js"]
                }
            ]
        },
        "ports_and_services": {
            "total_hosts_scanned": 142,
            "total_open_ports": 284,
            "services": [
                {
                    "host": "www.example.com",
                    "port": 443,
                    "service": "https",
                    "version": "Apache/2.4.41",
                    "ssl_info": {
                        "certificate": "Let's Encrypt",
                        "valid_until": "2024-04-01"
                    }
                }
            ]
        },
        "technologies": {
            "web_technologies": {
                "servers": ["Apache", "Nginx"],
                "languages": ["PHP", "Node.js", "Python"],
                "frameworks": ["React", "Express"],
                "cms": ["WordPress"],
                "analytics": ["Google Analytics"]
            },
            "security_headers": {
                "csp": "present",
                "hsts": "present",
                "x_frame_options": "missing"
            }
        },
        "certificates": {
            "total_certificates": 45,
            "certificate_authorities": ["Let's Encrypt", "DigiCert"],
            "expiring_soon": 2,
            "wildcard_certificates": 8
        }
    },
    "attack_surface": {
        "web_applications": 25,
        "api_endpoints": 12,
        "admin_panels": 3,
        "login_pages": 8,
        "file_uploads": 5,
        "potential_vulnerabilities": [
            {
                "type": "Subdomain Takeover",
                "affected": ["old.example.com"],
                "severity": "High"
            }
        ]
    },
    "recommendations": [
        {
            "category": "Reconnaissance",
            "priority": "High",
            "action": "Investigate subdomain takeover opportunities",
            "targets": ["old.example.com", "staging.example.com"]
        }
    ],
    "workflow_metadata": {
        "tools_used": ["subfinder", "amass", "nmap", "httpx", "nuclei"],
        "data_sources": ["certificate_transparency", "dns_records", "search_engines"],
        "execution_phases": [
            {
                "phase": "subdomain_enumeration",
                "duration": 450.2,
                "results_count": 156
            },
            {
                "phase": "port_scanning",
                "duration": 680.5,
                "results_count": 284
            }
        ]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Domain (400 Bad Request)
```json
{
    "error": "Target domain is required"
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
reconnaissance_options = params.get("reconnaissance_options", {})
workflow_config = params.get("workflow_config", {})

domain = target.get("domain", "")
if not domain:
    return jsonify({"error": "Target domain is required"}), 400
```

### Workflow Execution Logic
```python
# Use BugBountyWorkflowManager for reconnaissance
workflow_request = {
    "target": target,
    "options": reconnaissance_options,
    "config": workflow_config
}

# Execute reconnaissance workflow
workflow_result = bugbounty_manager.execute_reconnaissance_workflow(workflow_request)

# Analyze attack surface
attack_surface = bugbounty_manager.analyze_attack_surface(workflow_result)

# Generate recommendations
recommendations = bugbounty_manager.generate_reconnaissance_recommendations(workflow_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Bug bounty reconnaissance access required

## Error Handling
- **Missing Parameters:** 400 error for missing domain
- **Workflow Errors:** Handle errors during reconnaissance workflow execution
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Scope Validation:** Validate targets are within authorized scope
- **Rate Limiting:** Implement rate limiting to avoid overwhelming targets
- **Responsible Disclosure:** Emphasize responsible disclosure practices
- **Legal Compliance:** Ensure compliance with bug bounty program terms

## Use Cases and Applications

#### Bug Bounty Hunting
- **Target Discovery:** Discover potential targets for bug bounty programs
- **Attack Surface Mapping:** Map comprehensive attack surface
- **Vulnerability Research:** Research potential vulnerabilities

#### Security Assessment
- **External Assessment:** Perform external security assessments
- **Asset Discovery:** Discover organizational assets
- **Risk Assessment:** Assess external security risks

## Testing & Validation
- Parameter validation accuracy testing
- Workflow execution verification testing
- Results accuracy and completeness testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
def reconnaissance_workflow():
    """Execute comprehensive reconnaissance workflow for bug bounty with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", {})
        reconnaissance_options = params.get("reconnaissance_options", {})
        workflow_config = params.get("workflow_config", {})
        
        domain = target.get("domain", "")
        if not domain:
            return jsonify({"error": "Target domain is required"}), 400
        
        logger.info(f"🔍 Starting reconnaissance workflow for domain: {domain}")
        
        start_time = time.time()
        
        # Use BugBountyWorkflowManager for reconnaissance
        workflow_request = {
            "target": target,
            "options": reconnaissance_options,
            "config": workflow_config
        }
        
        # Execute reconnaissance workflow
        workflow_result = bugbounty_manager.execute_reconnaissance_workflow(workflow_request)
        
        # Analyze attack surface
        attack_surface = bugbounty_manager.analyze_attack_surface(workflow_result)
        
        # Generate recommendations
        recommendations = bugbounty_manager.generate_reconnaissance_recommendations(workflow_result)
        
        execution_time = time.time() - start_time
        
        workflow_info = {
            "target_domain": domain,
            "program_type": target.get("program_type", "web"),
            "phases_executed": workflow_result.get("phases_executed", []),
            "total_execution_time": execution_time,
            "stealth_mode": reconnaissance_options.get("stealth_mode", True)
        }
        
        workflow_metadata = {
            "tools_used": workflow_result.get("tools_used", []),
            "data_sources": workflow_result.get("data_sources", []),
            "execution_phases": workflow_result.get("execution_phases", [])
        }
        
        logger.info(f"🔍 Reconnaissance workflow completed in {execution_time:.2f}s | Subdomains: {workflow_result.get('subdomains', {}).get('total_found', 0)}")
        
        return jsonify({
            "success": True,
            "workflow_info": workflow_info,
            "reconnaissance_results": workflow_result["results"],
            "attack_surface": attack_surface,
            "recommendations": recommendations,
            "workflow_metadata": workflow_metadata,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error in reconnaissance workflow: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
