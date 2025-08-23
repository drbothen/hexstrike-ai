---
title: GET /api/error-handling/fallback-chains
group: api
handler: get_fallback_chains
module: __main__
line_range: [15225, 15251]
discovered_in_chunk: 15
---

# GET /api/error-handling/fallback-chains

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get available fallback tool chains

## Complete Signature & Definition
```python
@app.route("/api/error-handling/fallback-chains", methods=["GET"])
def get_fallback_chains():
    """Get available fallback tool chains"""
```

## Purpose & Behavior
Fallback chains retrieval endpoint providing:
- **Chain Discovery:** Discover available fallback tool chains
- **Configuration Retrieval:** Retrieve fallback chain configurations
- **Dependency Mapping:** Map tool dependencies and alternatives
- **Enhanced Logging:** Detailed logging of fallback chain operations

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/error-handling/fallback-chains
- **Content-Type:** application/json

### Request Body
No request body required for GET request.

### Parameters
No parameters required.

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "fallback_info": {
        "total_chains": 15,
        "active_chains": 12,
        "inactive_chains": 3,
        "last_updated": "2024-01-01T10:00:00Z"
    },
    "fallback_chains": [
        {
            "chain_id": "nmap_fallback",
            "primary_tool": "nmap",
            "category": "network_scanning",
            "fallback_sequence": [
                {
                    "order": 1,
                    "tool": "masscan",
                    "trigger_conditions": ["timeout", "permission_denied"],
                    "parameters": {
                        "rate": "1000",
                        "timeout": "30"
                    },
                    "success_criteria": "ports_discovered > 0"
                },
                {
                    "order": 2,
                    "tool": "rustscan",
                    "trigger_conditions": ["masscan_failed", "low_accuracy"],
                    "parameters": {
                        "batch_size": "5000",
                        "timeout": "2000"
                    },
                    "success_criteria": "scan_completed"
                }
            ],
            "effectiveness_score": 0.92,
            "usage_frequency": 156,
            "last_used": "2024-01-01T11:30:00Z"
        },
        {
            "chain_id": "web_vuln_fallback",
            "primary_tool": "nuclei",
            "category": "vulnerability_scanning",
            "fallback_sequence": [
                {
                    "order": 1,
                    "tool": "nikto",
                    "trigger_conditions": ["template_load_failed", "rate_limited"],
                    "parameters": {
                        "timeout": "600",
                        "tuning": "1,2,3,4,5,6,7,8,9,0"
                    },
                    "success_criteria": "vulnerabilities_found > 0"
                },
                {
                    "order": 2,
                    "tool": "dirb",
                    "trigger_conditions": ["nikto_failed", "basic_scan_needed"],
                    "parameters": {
                        "wordlist": "/usr/share/dirb/wordlists/common.txt",
                        "extensions": ".php,.html,.js"
                    },
                    "success_criteria": "directories_found > 0"
                }
            ],
            "effectiveness_score": 0.85,
            "usage_frequency": 89,
            "last_used": "2024-01-01T09:15:00Z"
        }
    ],
    "chain_statistics": {
        "most_used_chain": "nmap_fallback",
        "highest_effectiveness": "subdomain_enum_fallback",
        "average_effectiveness": 0.87,
        "total_fallback_activations": 1250,
        "success_rate": 0.94
    },
    "tool_categories": [
        {
            "category": "network_scanning",
            "chains_available": 3,
            "primary_tools": ["nmap", "masscan", "rustscan"],
            "fallback_tools": ["zmap", "unicornscan"]
        },
        {
            "category": "vulnerability_scanning",
            "chains_available": 4,
            "primary_tools": ["nuclei", "nikto", "openvas"],
            "fallback_tools": ["dirb", "gobuster", "wfuzz"]
        },
        {
            "category": "web_enumeration",
            "chains_available": 5,
            "primary_tools": ["ffuf", "gobuster", "feroxbuster"],
            "fallback_tools": ["dirb", "dirbuster", "wfuzz"]
        }
    ],
    "configuration_options": {
        "auto_fallback_enabled": true,
        "fallback_timeout": 300,
        "max_fallback_attempts": 3,
        "effectiveness_threshold": 0.7,
        "learning_enabled": true
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Fallback Chain Retrieval Logic
```python
try:
    # Get fallback chains from error handler
    fallback_chains = error_handler.get_fallback_chains()
    
    # Get chain statistics
    chain_statistics = error_handler.get_chain_statistics()
    
    # Get tool categories
    tool_categories = error_handler.get_tool_categories()
    
    # Get configuration options
    configuration_options = error_handler.get_fallback_configuration()
    
    fallback_info = {
        "total_chains": len(fallback_chains),
        "active_chains": len([c for c in fallback_chains if c.get("active", True)]),
        "inactive_chains": len([c for c in fallback_chains if not c.get("active", True)]),
        "last_updated": error_handler.get_last_update_time()
    }
    
except Exception as e:
    logger.error(f"💥 Error getting fallback chains: {str(e)}")
    return jsonify({"error": f"Server error: {str(e)}"}), 500
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Fallback chain access required

## Error Handling
- **Retrieval Errors:** Handle errors during fallback chain retrieval
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Configuration Security:** Protect fallback chain configurations
- **Access Control:** Control access to fallback chain information
- **Information Disclosure:** Limit sensitive information exposure

## Use Cases and Applications

#### System Administration
- **Chain Management:** Manage fallback tool chains
- **Configuration Review:** Review fallback configurations
- **Performance Analysis:** Analyze fallback chain performance

#### Tool Integration
- **Alternative Discovery:** Discover alternative tools for operations
- **Dependency Planning:** Plan tool dependencies and alternatives
- **Workflow Optimization:** Optimize workflows with fallback chains

## Testing & Validation
- Fallback chain retrieval accuracy testing
- Configuration consistency verification testing
- Performance impact assessment testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/error-handling/fallback-chains", methods=["GET"])
def get_fallback_chains():
    """Get available fallback tool chains"""
    try:
        logger.info("📋 Retrieving fallback chains")
        
        # Get fallback chains from error handler
        fallback_chains = error_handler.get_fallback_chains()
        
        # Get chain statistics
        chain_statistics = error_handler.get_chain_statistics()
        
        # Get tool categories
        tool_categories = error_handler.get_tool_categories()
        
        # Get configuration options
        configuration_options = error_handler.get_fallback_configuration()
        
        fallback_info = {
            "total_chains": len(fallback_chains),
            "active_chains": len([c for c in fallback_chains if c.get("active", True)]),
            "inactive_chains": len([c for c in fallback_chains if not c.get("active", True)]),
            "last_updated": error_handler.get_last_update_time()
        }
        
        logger.info(f"📋 Retrieved {len(fallback_chains)} fallback chains")
        
        return jsonify({
            "success": True,
            "fallback_info": fallback_info,
            "fallback_chains": fallback_chains,
            "chain_statistics": chain_statistics,
            "tool_categories": tool_categories,
            "configuration_options": configuration_options,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error getting fallback chains: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
