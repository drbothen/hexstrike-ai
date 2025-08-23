---
title: POST /api/ai/test_payload
group: api
handler: ai_test_payload
module: __main__
line_range: [12910, 12969]
discovered_in_chunk: 12
---

# POST /api/ai/test_payload

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Test generated payload against target with AI analysis

## Complete Signature & Definition
```python
@app.route("/api/ai/test_payload", methods=["POST"])
def ai_test_payload():
    """Test generated payload against target with AI analysis"""
```

## Purpose & Behavior
AI-powered payload testing endpoint providing:
- **Payload Testing:** Test generated payloads against target systems
- **AI Analysis:** AI-powered analysis of payload effectiveness
- **Result Interpretation:** Intelligent interpretation of test results
- **Enhanced Logging:** Detailed logging of testing progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ai/test_payload
- **Content-Type:** application/json

### Request Body
```json
{
    "payload": "string",              // Required: Payload to test
    "target": "string",               // Required: Target URL or endpoint
    "payload_type": "string",         // Required: Type of payload (xss, sqli, etc.)
    "method": "string",               // Optional: HTTP method (default: GET)
    "headers": "object",              // Optional: Custom headers
    "parameters": "object",           // Optional: Additional parameters
    "context": "string",              // Optional: Testing context
    "expected_behavior": "string",    // Optional: Expected behavior description
    "timeout": integer,               // Optional: Request timeout (default: 30)
    "follow_redirects": boolean,      // Optional: Follow redirects (default: true)
    "additional_args": "string"       // Optional: Additional testing arguments
}
```

### Parameters
- **payload:** Payload to test (required)
- **target:** Target URL or endpoint (required)
- **payload_type:** Type of payload (required) - "xss", "sqli", "rce", "lfi", etc.
- **method:** HTTP method (optional, default: "GET") - "GET", "POST", "PUT", etc.
- **headers:** Custom headers (optional) - {"User-Agent": "custom"}
- **parameters:** Additional parameters (optional) - {"param1": "value1"}
- **context:** Testing context (optional) - "login form", "search parameter"
- **expected_behavior:** Expected behavior description (optional)
- **timeout:** Request timeout in seconds (optional, default: 30)
- **follow_redirects:** Follow redirects flag (optional, default: true)
- **additional_args:** Additional testing arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "payload_test_results": {
        "payload": "<script>alert('XSS')</script>",
        "target": "https://example.com/search?q=",
        "payload_type": "xss",
        "test_method": "GET",
        "response_analysis": {
            "status_code": 200,
            "response_time": 250,
            "content_length": 1024,
            "payload_reflected": true,
            "payload_executed": false,
            "security_headers": {
                "csp": "default-src 'self'",
                "x_frame_options": "DENY",
                "x_xss_protection": "1; mode=block"
            }
        },
        "ai_analysis": {
            "vulnerability_detected": false,
            "confidence": 0.85,
            "risk_level": "Low",
            "explanation": "Payload was reflected but not executed due to CSP protection",
            "recommendations": [
                "Try CSP bypass techniques",
                "Test with different payload encodings",
                "Look for CSP misconfigurations"
            ],
            "evasion_suggestions": [
                "Use DOM-based XSS vectors",
                "Try JavaScript protocol handlers",
                "Test with event handlers"
            ]
        },
        "testing_metadata": {
            "test_timestamp": "2024-01-01T12:00:00Z",
            "test_duration": 2.5,
            "user_agent": "Mozilla/5.0...",
            "source_ip": "192.168.1.100"
        }
    },
    "raw_response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>...",
    "execution_time": 2.5,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Parameters (400 Bad Request)
```json
{
    "error": "Missing required parameters: payload, target, payload_type"
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
payload = params.get("payload", "")
target = params.get("target", "")
payload_type = params.get("payload_type", "")
method = params.get("method", "GET")
headers = params.get("headers", {})
parameters = params.get("parameters", {})
context = params.get("context", "")
expected_behavior = params.get("expected_behavior", "")
timeout = params.get("timeout", 30)
follow_redirects = params.get("follow_redirects", True)
additional_args = params.get("additional_args", "")

# Validate required parameters
missing_params = []
if not payload:
    missing_params.append("payload")
if not target:
    missing_params.append("target")
if not payload_type:
    missing_params.append("payload_type")
if missing_params:
    return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
```

### Payload Testing
```python
# Use AI payload generator to test payload
result = ai_payload_generator.test_payload(
    payload=payload,
    target=target,
    payload_type=payload_type,
    method=method,
    headers=headers,
    parameters=parameters,
    context=context,
    expected_behavior=expected_behavior,
    timeout=timeout,
    follow_redirects=follow_redirects
)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** AI payload testing access required

## Error Handling
- **Missing Parameters:** 400 error for missing required parameters
- **Testing Errors:** Handled by AIPayloadGenerator
- **Network Errors:** HTTP request and response error handling
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure target is valid and authorized for testing
- **Payload Sanitization:** Sanitize payloads for logging and storage
- **Rate Limiting:** Implement rate limiting for payload testing
- **Responsible Use:** Emphasize responsible use of payload testing capabilities

## Use Cases and Applications

#### Security Testing
- **Payload Validation:** Validate generated payloads against targets
- **Vulnerability Testing:** Test for specific vulnerability types
- **Evasion Testing:** Test payload evasion techniques

#### AI-Powered Analysis
- **Intelligent Analysis:** AI-powered analysis of test results
- **Recommendation Generation:** Generate testing recommendations
- **Pattern Recognition:** Recognize security patterns and behaviors

## Testing & Validation
- Payload testing accuracy testing
- Parameter validation verification
- AI analysis accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/ai/test_payload", methods=["POST"])
def ai_test_payload():
    """Test generated payload against target with AI analysis"""
    try:
        params = request.json
        payload = params.get("payload", "")
        target = params.get("target", "")
        payload_type = params.get("payload_type", "")
        method = params.get("method", "GET")
        headers = params.get("headers", {})
        parameters = params.get("parameters", {})
        context = params.get("context", "")
        expected_behavior = params.get("expected_behavior", "")
        timeout = params.get("timeout", 30)
        follow_redirects = params.get("follow_redirects", True)
        additional_args = params.get("additional_args", "")
        
        # Validate required parameters
        missing_params = []
        if not payload:
            missing_params.append("payload")
        if not target:
            missing_params.append("target")
        if not payload_type:
            missing_params.append("payload_type")
        if missing_params:
            return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
        
        logger.info(f"🤖 Testing AI payload: {payload_type} against {target}")
        
        start_time = time.time()
        result = ai_payload_generator.test_payload(
            payload=payload,
            target=target,
            payload_type=payload_type,
            method=method,
            headers=headers,
            parameters=parameters,
            context=context,
            expected_behavior=expected_behavior,
            timeout=timeout,
            follow_redirects=follow_redirects
        )
        execution_time = time.time() - start_time
        
        logger.info(f"🤖 AI payload testing completed in {execution_time:.2f}s | Vulnerability: {result.get('ai_analysis', {}).get('vulnerability_detected', False)}")
        
        return jsonify({
            "success": True,
            "payload_test_results": result,
            "raw_response": result.get("raw_response", ""),
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in AI payload testing: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
