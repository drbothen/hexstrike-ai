---
title: POST /api/payloads/generate
group: api
handler: generate_payload
module: __main__
line_range: [7358, 7399]
discovered_in_chunk: 7
---

# POST /api/payloads/generate

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Generate security testing payloads

## Complete Signature & Definition
```python
@app.route("/api/payloads/generate", methods=["POST"])
def generate_payload():
    """Generate security testing payloads"""
```

## Purpose & Behavior
Payload generation endpoint providing:
- **Security Payload Generation:** Generate various security testing payloads
- **Multiple Payload Types:** Support for XSS, SQLi, command injection, and other payload types
- **Contextual Generation:** Generate payloads based on target context
- **Evasion Techniques:** Apply evasion techniques to bypass security controls

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/payloads/generate
- **Content-Type:** application/json

### Request Body
```json
{
    "payload_type": "string",       // Required: Type of payload to generate
    "context": "string",            // Optional: Target context information
    "evasion": "string",            // Optional: Evasion technique to apply
    "count": integer,               // Optional: Number of payloads to generate (default: 1)
    "custom_params": {              // Optional: Custom parameters for specific payload types
        "param1": "value1",
        "param2": "value2"
    }
}
```

### Parameters
- **payload_type:** Type of payload to generate (required) - "xss", "sqli", "cmdi", "xxe", "ssti", etc.
- **context:** Target context information (optional) - "html", "javascript", "url", "json", etc.
- **evasion:** Evasion technique to apply (optional) - "encoding", "obfuscation", "fragmentation", etc.
- **count:** Number of payloads to generate (optional, default: 1)
- **custom_params:** Custom parameters for specific payload types (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "payload_type": "xss",
    "context": "html",
    "evasion": "encoding",
    "payloads": [
        {
            "payload": "<script>alert(1)</script>",
            "encoded": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "description": "Basic XSS payload with URL encoding evasion"
        }
    ],
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Payload Type (400 Bad Request)
```json
{
    "error": "Payload type is required"
}
```

#### Invalid Payload Type (400 Bad Request)
```json
{
    "error": "Invalid payload type: {payload_type}"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Request Processing
1. **JSON Parsing:** Extract payload type, context, evasion, count, and custom parameters from request
2. **Parameter Validation:** Ensure payload type is provided and valid
3. **Payload Generation:** Generate payloads based on parameters
4. **Response Generation:** Return generated payloads

### Parameter Extraction
```python
params = request.json
payload_type = params.get("payload_type", "")
context = params.get("context", "")
evasion = params.get("evasion", "")
count = params.get("count", 1)
custom_params = params.get("custom_params", {})
```

### Validation Logic
```python
if not payload_type:
    return jsonify({"error": "Payload type is required"}), 400

valid_types = ["xss", "sqli", "cmdi", "xxe", "ssti", "lfi", "rfi", "ssrf", "jwt", "nosql"]
if payload_type not in valid_types:
    return jsonify({"error": f"Invalid payload type: {payload_type}"}), 400
```

### Payload Generation Logic
```python
payloads = []
for i in range(count):
    payload = generate_payload_by_type(payload_type, context, evasion, custom_params)
    encoded = encode_payload(payload, evasion)
    payloads.append({
        "payload": payload,
        "encoded": encoded,
        "description": f"{payload_type.upper()} payload with {evasion} evasion"
    })
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Payload generation access required

## Error Handling
- **Missing Parameters:** 400 error for missing payload type
- **Invalid Parameters:** 400 error for invalid payload type
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Payload Usage Warning:** Generated payloads are for security testing only
- **Responsible Use:** Emphasize responsible use of generated payloads
- **Disclaimer:** Include disclaimer about authorized use only

## Use Cases and Applications

#### Security Testing
- **Penetration Testing:** Generate payloads for penetration testing
- **Vulnerability Assessment:** Test for various vulnerabilities
- **Security Control Testing:** Test security control effectiveness

#### Education and Training
- **Security Training:** Educational tool for security training
- **Payload Understanding:** Learn about different payload types
- **Evasion Techniques:** Study various evasion techniques

## Testing & Validation
- Payload generation accuracy testing
- Parameter validation verification
- Evasion technique effectiveness testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/payloads/generate", methods=["POST"])
def generate_payload():
    """Generate security testing payloads"""
    try:
        params = request.json
        payload_type = params.get("payload_type", "")
        context = params.get("context", "")
        evasion = params.get("evasion", "")
        count = params.get("count", 1)
        custom_params = params.get("custom_params", {})
        
        if not payload_type:
            return jsonify({"error": "Payload type is required"}), 400
        
        valid_types = ["xss", "sqli", "cmdi", "xxe", "ssti", "lfi", "rfi", "ssrf", "jwt", "nosql"]
        if payload_type not in valid_types:
            return jsonify({"error": f"Invalid payload type: {payload_type}"}), 400
        
        payloads = []
        for i in range(count):
            payload = generate_payload_by_type(payload_type, context, evasion, custom_params)
            encoded = encode_payload(payload, evasion)
            payloads.append({
                "payload": payload,
                "encoded": encoded,
                "description": f"{payload_type.upper()} payload with {evasion} evasion"
            })
        
        return jsonify({
            "success": True,
            "payload_type": payload_type,
            "context": context,
            "evasion": evasion,
            "payloads": payloads,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error generating payload: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
