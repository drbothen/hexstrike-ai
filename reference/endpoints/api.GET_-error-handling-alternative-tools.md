---
title: GET /api/error-handling/alternative-tools
group: api
handler: get_alternative_tools
module: __main__
line_range: [15351, 15381]
discovered_in_chunk: 15
---

# GET /api/error-handling/alternative-tools

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get alternative tools for a given tool

## Complete Signature & Definition
```python
@app.route("/api/error-handling/alternative-tools", methods=["GET"])
def get_alternative_tools():
    """Get alternative tools for a given tool"""
```

## Purpose & Behavior
Alternative tools discovery endpoint providing:
- **Tool Alternatives:** Discover alternative tools for specific tools
- **Fallback Options:** Provide fallback tool options for error recovery
- **Compatibility Analysis:** Analyze tool compatibility and alternatives
- **Enhanced Logging:** Detailed logging of alternative tool operations

## Request

### HTTP Method
- **Method:** GET
- **Path:** /api/error-handling/alternative-tools
- **Content-Type:** application/json

### Request Body
No request body required for GET request.

### Parameters
- **tool_name:** Tool name to find alternatives for (query parameter, optional)
- **category:** Tool category filter (query parameter, optional)
- **compatibility:** Compatibility requirements (query parameter, optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "alternatives_info": {
        "total_tools": 45,
        "categories_covered": 8,
        "compatibility_checked": true,
        "last_updated": "2024-01-01T10:00:00Z"
    },
    "tool_alternatives": [
        {
            "primary_tool": "nmap",
            "category": "network_scanning",
            "alternatives": [
                {
                    "tool_name": "masscan",
                    "compatibility_score": 0.92,
                    "use_case": "High-speed port scanning",
                    "advantages": ["Faster scanning", "Better for large networks"],
                    "disadvantages": ["Less detailed output", "Fewer scan types"],
                    "parameter_mapping": {
                        "ports": "-p",
                        "rate": "--rate",
                        "output": "-oX"
                    },
                    "fallback_priority": 1
                },
                {
                    "tool_name": "rustscan",
                    "compatibility_score": 0.85,
                    "use_case": "Fast initial port discovery",
                    "advantages": ["Very fast", "Modern implementation"],
                    "disadvantages": ["Limited scan options", "Less mature"],
                    "parameter_mapping": {
                        "ports": "-p",
                        "timeout": "-t",
                        "batch_size": "-b"
                    },
                    "fallback_priority": 2
                },
                {
                    "tool_name": "zmap",
                    "compatibility_score": 0.75,
                    "use_case": "Internet-wide scanning",
                    "advantages": ["Internet-scale scanning", "High performance"],
                    "disadvantages": ["Single port only", "Different paradigm"],
                    "parameter_mapping": {
                        "port": "-p",
                        "rate": "-r",
                        "output": "-o"
                    },
                    "fallback_priority": 3
                }
            ]
        },
        {
            "primary_tool": "nuclei",
            "category": "vulnerability_scanning",
            "alternatives": [
                {
                    "tool_name": "nikto",
                    "compatibility_score": 0.78,
                    "use_case": "Web vulnerability scanning",
                    "advantages": ["Mature tool", "Comprehensive checks"],
                    "disadvantages": ["Slower", "More false positives"],
                    "parameter_mapping": {
                        "host": "-h",
                        "port": "-p",
                        "output": "-o"
                    },
                    "fallback_priority": 1
                },
                {
                    "tool_name": "dirb",
                    "compatibility_score": 0.65,
                    "use_case": "Directory enumeration",
                    "advantages": ["Simple to use", "Reliable"],
                    "disadvantages": ["Limited scope", "Slower"],
                    "parameter_mapping": {
                        "url": "url",
                        "wordlist": "wordlist",
                        "extensions": "-X"
                    },
                    "fallback_priority": 2
                }
            ]
        }
    ],
    "category_alternatives": [
        {
            "category": "network_scanning",
            "primary_tools": ["nmap", "masscan", "rustscan"],
            "alternative_tools": ["zmap", "unicornscan", "hping3"],
            "specialized_tools": ["arp-scan", "fping"]
        },
        {
            "category": "web_enumeration",
            "primary_tools": ["ffuf", "gobuster", "feroxbuster"],
            "alternative_tools": ["dirb", "dirbuster", "wfuzz"],
            "specialized_tools": ["cewl", "crunch"]
        },
        {
            "category": "vulnerability_scanning",
            "primary_tools": ["nuclei", "nikto", "openvas"],
            "alternative_tools": ["nessus", "qualys", "rapid7"],
            "specialized_tools": ["sqlmap", "xsser"]
        }
    ],
    "compatibility_matrix": {
        "parameter_compatibility": 0.85,
        "output_format_compatibility": 0.78,
        "workflow_compatibility": 0.92,
        "performance_compatibility": 0.73
    },
    "recommendations": [
        {
            "scenario": "High-speed scanning",
            "recommended_alternative": "masscan",
            "rationale": "Optimized for speed over detail"
        },
        {
            "scenario": "Stealth scanning",
            "recommended_alternative": "nmap with timing options",
            "rationale": "Better stealth capabilities"
        }
    ],
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

### Alternative Tools Retrieval Logic
```python
try:
    # Get query parameters
    tool_name = request.args.get("tool_name", "")
    category = request.args.get("category", "")
    compatibility = request.args.get("compatibility", "")
    
    # Get alternative tools from error handler
    alternatives = error_handler.get_alternative_tools(tool_name, category, compatibility)
    
    # Get category alternatives
    category_alternatives = error_handler.get_category_alternatives()
    
    # Get compatibility matrix
    compatibility_matrix = error_handler.get_compatibility_matrix()
    
    # Generate recommendations
    recommendations = error_handler.generate_alternative_recommendations()
    
    alternatives_info = {
        "total_tools": len(alternatives),
        "categories_covered": len(set(alt.get("category") for alt in alternatives)),
        "compatibility_checked": True,
        "last_updated": error_handler.get_last_update_time()
    }
    
except Exception as e:
    logger.error(f"💥 Error getting alternative tools: {str(e)}")
    return jsonify({"error": f"Server error: {str(e)}"}), 500
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Alternative tools access required

## Error Handling
- **Retrieval Errors:** Handle errors during alternative tools retrieval
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Tool Validation:** Validate alternative tools for security
- **Access Control:** Control access to alternative tools information
- **Configuration Security:** Protect tool configuration information

## Use Cases and Applications

#### Error Recovery
- **Tool Fallbacks:** Provide fallback tools for error recovery
- **Alternative Discovery:** Discover alternative tools for specific use cases
- **Compatibility Planning:** Plan tool compatibility and alternatives

#### System Administration
- **Tool Management:** Manage available tools and alternatives
- **Workflow Planning:** Plan workflows with alternative tools
- **Performance Optimization:** Optimize performance through tool alternatives

## Testing & Validation
- Alternative tools retrieval accuracy testing
- Compatibility matrix verification testing
- Recommendation accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/error-handling/alternative-tools", methods=["GET"])
def get_alternative_tools():
    """Get alternative tools for a given tool"""
    try:
        logger.info("🔧 Retrieving alternative tools")
        
        # Get query parameters
        tool_name = request.args.get("tool_name", "")
        category = request.args.get("category", "")
        compatibility = request.args.get("compatibility", "")
        
        # Get alternative tools from error handler
        alternatives = error_handler.get_alternative_tools(tool_name, category, compatibility)
        
        # Get category alternatives
        category_alternatives = error_handler.get_category_alternatives()
        
        # Get compatibility matrix
        compatibility_matrix = error_handler.get_compatibility_matrix()
        
        # Generate recommendations
        recommendations = error_handler.generate_alternative_recommendations()
        
        alternatives_info = {
            "total_tools": len(alternatives),
            "categories_covered": len(set(alt.get("category") for alt in alternatives)),
            "compatibility_checked": True,
            "last_updated": error_handler.get_last_update_time()
        }
        
        logger.info(f"🔧 Retrieved {len(alternatives)} alternative tools")
        
        return jsonify({
            "success": True,
            "alternatives_info": alternatives_info,
            "tool_alternatives": alternatives,
            "category_alternatives": category_alternatives,
            "compatibility_matrix": compatibility_matrix,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error getting alternative tools: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
