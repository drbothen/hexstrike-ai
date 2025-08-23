---
title: POST /api/ctf/auto-solve-challenge
group: api
handler: auto_solve_ctf_challenge
module: __main__
line_range: [14277, 14315]
discovered_in_chunk: 15
---

# POST /api/ctf/auto-solve-challenge

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Attempt to automatically solve a CTF challenge

## Complete Signature & Definition
```python
@app.route("/api/ctf/auto-solve-challenge", methods=["POST"])
def auto_solve_ctf_challenge():
    """Attempt to automatically solve a CTF challenge"""
```

## Purpose & Behavior
CTF challenge auto-solver endpoint providing:
- **Automated Solving:** AI-powered automatic challenge solving
- **Multi-Category Support:** Support for various CTF challenge categories
- **Solution Validation:** Validate and verify challenge solutions
- **Progress Tracking:** Track solving progress and attempts

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ctf/auto-solve-challenge
- **Content-Type:** application/json

### Request Body
```json
{
    "name": "string",                   // Required: Challenge name
    "category": "string",               // Optional: Challenge category (default: "misc")
    "difficulty": "string",             // Optional: Challenge difficulty (default: "unknown")
    "points": integer,                  // Optional: Challenge points (default: 100)
    "description": "string",            // Optional: Challenge description
    "target": "string"                  // Optional: Challenge target/URL
}
```

### Parameters
- **name:** Challenge name (required)
- **category:** Challenge category (optional, default: "misc")
- **difficulty:** Challenge difficulty level (optional, default: "unknown")
- **points:** Point value of the challenge (optional, default: 100)
- **description:** Challenge description (optional)
- **target:** Challenge target URL or file (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "solve_result": {
        "status": "solved|partial|failed",
        "solution": "string",
        "flag": "string",
        "approach": "string",
        "tools_used": ["tool1", "tool2"],
        "time_taken": 120.5,
        "confidence": 0.85
    },
    "challenge": {
        "name": "string",
        "category": "string",
        "difficulty": "string",
        "points": 100,
        "description": "string",
        "target": "string"
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Challenge Name (400 Bad Request)
```json
{
    "error": "Challenge name is required"
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
@app.route("/api/ctf/auto-solve-challenge", methods=["POST"])
def auto_solve_ctf_challenge():
    """Attempt to automatically solve a CTF challenge"""
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
        
        # Attempt automated solving
        result = ctf_automator.auto_solve_challenge(challenge)
        
        logger.info(f"🤖 CTF auto-solve attempted for {challenge_name} | Status: {result['status']}")
        return jsonify({
            "success": True,
            "solve_result": result,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error in CTF auto-solve: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
