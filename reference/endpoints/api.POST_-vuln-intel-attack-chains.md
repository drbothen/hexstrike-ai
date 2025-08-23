---
title: POST /api/vuln-intel/attack-chains
group: api
handler: discover_attack_chains
module: __main__
line_range: [13744, 13819]
discovered_in_chunk: 14
---

# POST /api/vuln-intel/attack-chains

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Discover multi-stage attack possibilities

## Complete Signature & Definition
```python
@app.route("/api/vuln-intel/attack-chains", methods=["POST"])
def discover_attack_chains():
    """Discover multi-stage attack possibilities"""
```

## Purpose & Behavior
Attack chain discovery endpoint providing:
- **Multi-Stage Analysis:** Discover complex attack chains across multiple vulnerabilities
- **Exploit Generation:** Generate exploits for viable attack chain stages
- **Risk Assessment:** Assess overall risk and success probability of attack chains
- **Zero-Day Integration:** Optional inclusion of zero-day vulnerabilities in chains

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/vuln-intel/attack-chains
- **Content-Type:** application/json

### Request Body
```json
{
    "target_software": "string",        // Required: Target software to analyze
    "attack_depth": integer,            // Optional: Attack chain depth (default: 3)
    "include_zero_days": boolean        // Optional: Include zero-day vulnerabilities (default: false)
}
```

### Parameters
- **target_software:** Target software for attack chain discovery (required)
- **attack_depth:** Maximum depth of attack chains to discover (optional, default: 3)
- **include_zero_days:** Whether to include zero-day vulnerabilities (optional, default: false)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "attack_chain_discovery": {
        "attack_chains": [
            {
                "chain_id": "string",
                "stages": [
                    {
                        "stage_number": 1,
                        "vulnerability": {
                            "cve_id": "CVE-2024-1234",
                            "description": "string"
                        },
                        "exploit_available": true,
                        "exploit_code": "string"
                    }
                ],
                "success_probability": 0.85,
                "overall_risk": "HIGH"
            }
        ],
        "enhanced_chains": []
    },
    "parameters": {
        "target_software": "string",
        "attack_depth": 3,
        "include_zero_days": false
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Target Software (400 Bad Request)
```json
{
    "success": false,
    "error": "Target software parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "success": false,
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/vuln-intel/attack-chains", methods=["POST"])
def discover_attack_chains():
    """Discover multi-stage attack possibilities"""
    try:
        params = request.json
        target_software = params.get("target_software", "")
        attack_depth = params.get("attack_depth", 3)
        include_zero_days = params.get("include_zero_days", False)
        
        if not target_software:
            logger.warning("🔗 Attack chain discovery called without target software")
            return jsonify({
                "success": False,
                "error": "Target software parameter is required"
            }), 400
        
        logger.info(f"🔗 Discovering attack chains for {target_software} | Depth: {attack_depth}")
        
        # Discover attack chains
        chain_results = vulnerability_correlator.find_attack_chains(target_software, attack_depth)
        
        # Enhance with exploit generation for viable chains
        if chain_results.get("success") and chain_results.get("attack_chains"):
            enhanced_chains = []
            
            for chain in chain_results["attack_chains"][:2]:  # Enhance top 2 chains
                enhanced_chain = chain.copy()
                enhanced_stages = []
                
                for stage in chain["stages"]:
                    enhanced_stage = stage.copy()
                    
                    # Try to generate exploit for this stage
                    vuln = stage.get("vulnerability", {})
                    cve_id = vuln.get("cve_id", "")
                    
                    if cve_id:
                        try:
                            cve_data = {"cve_id": cve_id, "description": vuln.get("description", "")}
                            target_info = {"target_os": "linux", "target_arch": "x64", "evasion_level": "basic"}
                            
                            exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)
                            enhanced_stage["exploit_available"] = exploit_result.get("success", False)
                            
                            if exploit_result.get("success"):
                                enhanced_stage["exploit_code"] = exploit_result.get("exploit_code", "")[:500] + "..."
                        except:
                            enhanced_stage["exploit_available"] = False
                    
                    enhanced_stages.append(enhanced_stage)
                
                enhanced_chain["stages"] = enhanced_stages
                enhanced_chains.append(enhanced_chain)
            
            chain_results["enhanced_chains"] = enhanced_chains
        
        result = {
            "success": True,
            "attack_chain_discovery": chain_results,
            "parameters": {
                "target_software": target_software,
                "attack_depth": attack_depth,
                "include_zero_days": include_zero_days
            },
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"🎯 Attack chain discovery completed | Found: {len(chain_results.get('attack_chains', []))} chains")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in attack chain discovery: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500
```
