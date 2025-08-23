---
title: POST /api/tools/jwt_analyzer
group: api
handler: jwt_analyzer
module: __main__
line_range: [13446, 13485]
discovered_in_chunk: 13
---

# POST /api/tools/jwt_analyzer

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute JWT analyzer for JWT security testing

## Complete Signature & Definition
```python
@app.route("/api/tools/jwt_analyzer", methods=["POST"])
def jwt_analyzer():
    """Execute JWT analyzer for JWT security testing with enhanced logging"""
```

## Purpose & Behavior
JWT security analysis endpoint providing:
- **JWT Analysis:** Comprehensive JWT token analysis and security testing
- **Signature Verification:** Test JWT signature verification mechanisms
- **Algorithm Testing:** Test JWT algorithm vulnerabilities
- **Enhanced Logging:** Detailed logging of analysis progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/jwt_analyzer
- **Content-Type:** application/json

### Request Body
```json
{
    "token": "string",                // Required: JWT token to analyze
    "secret": "string",               // Optional: Secret key for verification
    "wordlist": "string",             // Optional: Wordlist for secret brute force
    "algorithm": "string",            // Optional: Algorithm to test
    "target_url": "string",           // Optional: Target URL for testing
    "crack_secret": boolean,          // Optional: Attempt to crack secret (default: false)
    "test_algorithms": boolean,       // Optional: Test algorithm vulnerabilities (default: true)
    "verify_signature": boolean,      // Optional: Verify signature (default: true)
    "additional_args": "string"       // Optional: Additional analyzer arguments
}
```

### Parameters
- **token:** JWT token to analyze (required)
- **secret:** Secret key for verification (optional)
- **wordlist:** Wordlist for secret brute force (optional)
- **algorithm:** Algorithm to test (optional) - "HS256", "RS256", "none"
- **target_url:** Target URL for testing (optional)
- **crack_secret:** Attempt to crack secret flag (optional, default: false)
- **test_algorithms:** Test algorithm vulnerabilities flag (optional, default: true)
- **verify_signature:** Verify signature flag (optional, default: true)
- **additional_args:** Additional analyzer arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "jwt_analyzer --token eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "analysis_results": {
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "header": {
            "typ": "JWT",
            "alg": "HS256"
        },
        "payload": {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022,
            "exp": 1516242622
        },
        "signature_valid": false,
        "algorithm_vulnerabilities": [
            {
                "vulnerability": "Algorithm Confusion",
                "description": "Token can be modified to use 'none' algorithm",
                "severity": "High"
            }
        ],
        "secret_cracked": true,
        "secret": "secret123",
        "recommendations": [
            "Use strong secret keys",
            "Implement proper algorithm validation",
            "Set appropriate expiration times"
        ]
    },
    "raw_output": "JWT Analysis Results:\nHeader: {\"typ\":\"JWT\",\"alg\":\"HS256\"}\n",
    "execution_time": 15.7,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Token (400 Bad Request)
```json
{
    "error": "Token parameter is required"
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
token = params.get("token", "")
secret = params.get("secret", "")
wordlist = params.get("wordlist", "")
algorithm = params.get("algorithm", "")
target_url = params.get("target_url", "")
crack_secret = params.get("crack_secret", False)
test_algorithms = params.get("test_algorithms", True)
verify_signature = params.get("verify_signature", True)
additional_args = params.get("additional_args", "")

if not token:
    return jsonify({"error": "Token parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["jwt_analyzer", "--token", token]

# Secret
if secret:
    command.extend(["--secret", secret])

# Wordlist
if wordlist:
    command.extend(["--wordlist", wordlist])

# Algorithm
if algorithm:
    command.extend(["--algorithm", algorithm])

# Target URL
if target_url:
    command.extend(["--url", target_url])

# Crack secret
if crack_secret:
    command.append("--crack")

# Test algorithms
if test_algorithms:
    command.append("--test-alg")

# Verify signature
if verify_signature:
    command.append("--verify")

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** JWT analyzer execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing token
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Token Validation:** Validate JWT tokens before analysis
- **Secret Security:** Secure handling of secret keys
- **Responsible Use:** Emphasize responsible use of JWT analysis capabilities

## Use Cases and Applications

#### JWT Security Testing
- **Token Analysis:** Analyze JWT tokens for security vulnerabilities
- **Algorithm Testing:** Test JWT algorithm implementations
- **Secret Cracking:** Attempt to crack weak JWT secrets

#### Security Assessment
- **Authentication Testing:** Test JWT-based authentication systems
- **Vulnerability Discovery:** Discover JWT-related vulnerabilities
- **Security Validation:** Validate JWT security implementations

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- JWT analysis accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/jwt_analyzer", methods=["POST"])
def jwt_analyzer():
    """Execute JWT analyzer for JWT security testing with enhanced logging"""
    try:
        params = request.json
        token = params.get("token", "")
        secret = params.get("secret", "")
        wordlist = params.get("wordlist", "")
        algorithm = params.get("algorithm", "")
        target_url = params.get("target_url", "")
        crack_secret = params.get("crack_secret", False)
        test_algorithms = params.get("test_algorithms", True)
        verify_signature = params.get("verify_signature", True)
        additional_args = params.get("additional_args", "")
        
        if not token:
            return jsonify({"error": "Token parameter is required"}), 400
        
        # Base command
        command = ["jwt_analyzer", "--token", token]
        
        # Secret
        if secret:
            command.extend(["--secret", secret])
        
        # Wordlist
        if wordlist:
            command.extend(["--wordlist", wordlist])
        
        # Algorithm
        if algorithm:
            command.extend(["--algorithm", algorithm])
        
        # Target URL
        if target_url:
            command.extend(["--url", target_url])
        
        # Crack secret
        if crack_secret:
            command.append("--crack")
        
        # Test algorithms
        if test_algorithms:
            command.append("--test-alg")
        
        # Verify signature
        if verify_signature:
            command.append("--verify")
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing JWT analyzer: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for analysis results
        analysis_results = parse_jwt_analyzer_output(result["output"], token)
        
        logger.info(f"🔍 JWT analyzer completed in {execution_time:.2f}s | Vulnerabilities: {len(analysis_results.get('algorithm_vulnerabilities', []))}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "analysis_results": analysis_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in JWT analyzer endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
