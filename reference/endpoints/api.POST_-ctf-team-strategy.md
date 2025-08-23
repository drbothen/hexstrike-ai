---
title: POST /api/ctf/team-strategy
group: api
handler: create_ctf_team_strategy
module: __main__
line_range: [14317, 14355]
discovered_in_chunk: 15
---

# POST /api/ctf/team-strategy

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Create optimal team strategy for CTF competition

## Complete Signature & Definition
```python
@app.route("/api/ctf/team-strategy", methods=["POST"])
def create_ctf_team_strategy():
    """Create optimal team strategy for CTF competition"""
```

## Purpose & Behavior
CTF team strategy optimization endpoint providing:
- **Team Coordination:** Optimize team member assignments and coordination
- **Challenge Prioritization:** Prioritize challenges based on team skills and points
- **Resource Allocation:** Allocate team resources efficiently across challenges
- **Strategy Optimization:** Create optimal solving strategies for competitions

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ctf/team-strategy
- **Content-Type:** application/json

### Request Body
```json
{
    "challenges": [                     // Required: List of challenges
        {
            "name": "string",
            "category": "string",
            "difficulty": "string",
            "points": integer,
            "description": "string",
            "target": "string"
        }
    ],
    "team_skills": {                    // Optional: Team member skills
        "member1": ["crypto", "web"],
        "member2": ["pwn", "reverse"]
    }
}
```

### Parameters
- **challenges:** List of CTF challenges with details (required)
- **team_skills:** Team member skills and specializations (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "strategy": {
        "challenge_assignments": {
            "member1": ["challenge1", "challenge2"],
            "member2": ["challenge3", "challenge4"]
        },
        "priority_order": ["challenge1", "challenge3", "challenge2"],
        "time_allocation": {
            "challenge1": 60,
            "challenge2": 45,
            "challenge3": 90
        },
        "coordination_plan": {
            "communication_channels": ["discord", "slack"],
            "progress_tracking": "shared_document",
            "knowledge_sharing": "regular_updates"
        }
    },
    "challenges_count": 10,
    "team_size": 4,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Challenges Data (400 Bad Request)
```json
{
    "error": "Challenges data is required"
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
@app.route("/api/ctf/team-strategy", methods=["POST"])
def create_ctf_team_strategy():
    """Create optimal team strategy for CTF competition"""
    try:
        params = request.json
        challenges_data = params.get("challenges", [])
        team_skills = params.get("team_skills", {})
        
        if not challenges_data:
            return jsonify({"error": "Challenges data is required"}), 400
        
        # Convert challenge data to CTFChallenge objects
        challenges = []
        for challenge_data in challenges_data:
            challenge = CTFChallenge(
                name=challenge_data.get("name", ""),
                category=challenge_data.get("category", "misc"),
                difficulty=challenge_data.get("difficulty", "unknown"),
                points=challenge_data.get("points", 100),
                description=challenge_data.get("description", ""),
                target=challenge_data.get("target", "")
            )
            challenges.append(challenge)
        
        # Generate team strategy
        strategy = ctf_coordinator.optimize_team_strategy(challenges, team_skills)
        
        logger.info(f"👥 CTF team strategy created | Challenges: {len(challenges)} | Team members: {len(team_skills)}")
        return jsonify({
            "success": True,
            "strategy": strategy,
            "challenges_count": len(challenges),
            "team_size": len(team_skills),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error creating CTF team strategy: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
