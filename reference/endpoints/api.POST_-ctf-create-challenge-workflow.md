---
title: POST /api/ctf/create-challenge-workflow
group: api
handler: create_ctf_challenge_workflow
module: __main__
line_range: [14237, 14275]
discovered_in_chunk: 14
---

# POST /api/ctf/create-challenge-workflow

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Create specialized workflow for CTF challenge with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/ctf/create-challenge-workflow", methods=["POST"])
def create_ctf_challenge_workflow():
    """Create specialized workflow for CTF challenge"""
```

## Purpose & Behavior
CTF challenge workflow creation endpoint providing:
- **Challenge Analysis:** Analyze CTF challenge requirements and constraints
- **Workflow Generation:** Create optimized workflow for challenge solving
- **Tool Selection:** Select appropriate tools based on challenge category
- **Enhanced Logging:** Detailed logging of workflow creation process

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ctf/create-challenge-workflow
- **Content-Type:** application/json

### Request Body
```json
{
    "name": "string",                // Required: Challenge name
    "category": "string",            // Optional: Challenge category (default: "misc")
    "difficulty": "string",          // Optional: Challenge difficulty (default: "unknown")
    "points": integer,               // Optional: Challenge points (default: 100)
    "description": "string",         // Optional: Challenge description
    "target": "string"               // Optional: Challenge target/URL
}
```

### Parameters
- **name:** Challenge name (required)
- **category:** Challenge category (optional, default: "misc")
- **difficulty:** Challenge difficulty level (optional, default: "unknown")
- **points:** Point value of challenge (optional, default: 100)
- **description:** Challenge description (optional)
- **target:** Challenge target or URL (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "workflow": {
        "steps": [
            {
                "step": 1,
                "action": "reconnaissance",
                "tools": ["nmap", "gobuster"],
                "description": "Initial target reconnaissance"
            },
            {
                "step": 2,
                "action": "vulnerability_analysis",
                "tools": ["nuclei", "nikto"],
                "description": "Identify potential vulnerabilities"
            }
        ],
        "estimated_time": "30 minutes",
        "success_probability": 0.75
    },
    "challenge": {
        "name": "Web Challenge 1",
        "category": "web",
        "difficulty": "medium",
        "points": 200,
        "description": "Find the hidden flag",
        "target": "http://challenge.ctf.com"
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response (400 Bad Request)
```json
{
    "error": "Challenge name is required"
}
```

### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/ctf/create-challenge-workflow", methods=["POST"])
def create_ctf_challenge_workflow():
    """Create specialized workflow for CTF challenge"""
    try:
        params = request.json
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")
        
        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400
        
        # Create CTF challenge object
        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target
        )
        
        # Generate workflow
        workflow = ctf_manager.create_ctf_challenge_workflow(challenge)
        
        logger.info(f"🎯 CTF workflow created for {challenge_name} | Category: {category} | Difficulty: {difficulty}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error creating CTF workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
