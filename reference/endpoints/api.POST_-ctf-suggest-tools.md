---
title: POST /api/ctf/suggest-tools
group: api
handler: suggest_ctf_tools
module: __main__
line_range: [14357, 14392]
discovered_in_chunk: 15
---

# POST /api/ctf/suggest-tools

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Suggest optimal tools for CTF challenge based on description and category

## Complete Signature & Definition
```python
@app.route("/api/ctf/suggest-tools", methods=["POST"])
def suggest_ctf_tools():
    """Suggest optimal tools for CTF challenge based on description and category"""
```

## Purpose & Behavior
CTF tool suggestion endpoint providing:
- **Intelligent Tool Selection:** AI-powered tool recommendations based on challenge analysis
- **Category-Specific Tools:** Specialized tools for different CTF categories
- **Command Generation:** Generate ready-to-use commands for suggested tools
- **Tool Optimization:** Optimize tool selection based on challenge characteristics

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ctf/suggest-tools
- **Content-Type:** application/json

### Request Body
```json
{
    "description": "string",            // Required: Challenge description
    "category": "string"                // Optional: Challenge category (default: "misc")
}
```

### Parameters
- **description:** Challenge description for analysis (required)
- **category:** Challenge category (optional, default: "misc")

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "suggested_tools": [
        "nmap",
        "gobuster",
        "burpsuite"
    ],
    "category_tools": [
        "tool1",
        "tool2",
        "tool3"
    ],
    "tool_commands": {
        "nmap": "nmap -sV TARGET",
        "gobuster": "gobuster dir -u TARGET -w /usr/share/wordlists/dirb/common.txt",
        "burpsuite": "burpsuite TARGET"
    },
    "category": "web",
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Description (400 Bad Request)
```json
{
    "error": "Challenge description is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/ctf/suggest-tools", methods=["POST"])
def suggest_ctf_tools():
    """Suggest optimal tools for CTF challenge based on description and category"""
    try:
        params = request.json
        description = params.get("description", "")
        category = params.get("category", "misc")
        
        if not description:
            return jsonify({"error": "Challenge description is required"}), 400
        
        # Get tool suggestions
        suggested_tools = ctf_tools.suggest_tools_for_challenge(description, category)
        category_tools = ctf_tools.get_category_tools(f"{category}_recon")
        
        # Get tool commands
        tool_commands = {}
        for tool in suggested_tools:
            try:
                tool_commands[tool] = ctf_tools.get_tool_command(tool, "TARGET")
            except:
                tool_commands[tool] = f"{tool} TARGET"
        
        logger.info(f"🔧 CTF tools suggested | Category: {category} | Tools: {len(suggested_tools)}")
        return jsonify({
            "success": True,
            "suggested_tools": suggested_tools,
            "category_tools": category_tools,
            "tool_commands": tool_commands,
            "category": category,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error suggesting CTF tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
