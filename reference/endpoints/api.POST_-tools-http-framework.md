---
title: POST /api/tools/http-framework
group: api
handler: http_framework_endpoint
module: __main__
line_range: [12170, 12264]
discovered_in_chunk: 12
---

# POST /api/tools/http-framework

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Enhanced HTTP testing framework (Burp Suite alternative)

## Complete Signature & Definition
```python
@app.route("/api/tools/http-framework", methods=["POST"])
def http_framework_endpoint():
    """Enhanced HTTP testing framework (Burp Suite alternative)"""
```

## Purpose & Behavior
HTTP testing framework endpoint providing:
- **Request Interception:** Intercept and analyze HTTP requests and responses
- **Website Spidering:** Automated website crawling and discovery
- **Proxy History:** Request/response history management
- **Match/Replace Rules:** Advanced request modification capabilities
- **Intruder Functionality:** Automated parameter fuzzing and testing

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/http-framework
- **Content-Type:** application/json

### Request Body
```json
{
    "action": "string",                 // Required: Action to perform
    "url": "string",                    // Required for most actions: Target URL
    "method": "string",                 // Optional: HTTP method (default: "GET")
    "data": {},                         // Optional: Request data/parameters
    "headers": {},                      // Optional: Custom headers
    "cookies": {},                      // Optional: Custom cookies
    "max_depth": 3,                     // Optional: Spider max depth
    "max_pages": 100,                   // Optional: Spider max pages
    "rules": [],                        // Optional: Match/replace rules
    "host": "string",                   // Optional: Scope host
    "include_subdomains": boolean,      // Optional: Include subdomains in scope
    "request": {},                      // Optional: Custom request specification
    "location": "string",               // Optional: Intruder injection location
    "params": [],                       // Optional: Parameters to fuzz
    "payloads": [],                     // Optional: Fuzzing payloads
    "base_data": {},                    // Optional: Base request data
    "max_requests": 100                 // Optional: Maximum requests for intruder
}
```

### Actions Supported
- **request:** Send HTTP request with interception and analysis
- **spider:** Automated website spidering and discovery
- **proxy_history:** Retrieve proxy request/response history
- **set_rules:** Configure match/replace rules
- **set_scope:** Configure testing scope
- **repeater:** Send custom request with explicit parameters
- **intruder:** Automated parameter fuzzing (Sniper mode)

## Response

### Success Response (200 OK)
Response varies by action:

#### Request Action
```json
{
    "success": true,
    "request": {
        "id": 1,
        "url": "string",
        "method": "string",
        "headers": {},
        "data": {},
        "timestamp": "2024-01-01T12:00:00Z"
    },
    "response": {
        "status_code": 200,
        "headers": {},
        "content": "string",
        "size": 1024,
        "time": 0.5
    },
    "vulnerabilities": []
}
```

#### Spider Action
```json
{
    "success": true,
    "discovered_urls": [],
    "forms": [],
    "total_pages": 10,
    "vulnerabilities": []
}
```

#### Proxy History Action
```json
{
    "success": true,
    "history": [],
    "total_requests": 50,
    "vulnerabilities": []
}
```

### Error Responses

#### Missing Parameters (400 Bad Request)
```json
{
    "error": "URL parameter is required for request action"
}
```

#### Unknown Action (400 Bad Request)
```json
{
    "error": "Unknown action: {action}"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Action Processing
Each action is processed through a dedicated handler:

#### Request Action
```python
if action == "request":
    result = http_framework.intercept_request(url, method, data, headers, cookies)
```

#### Spider Action
```python
elif action == "spider":
    result = http_framework.spider_website(url, max_depth, max_pages)
```

#### Proxy History Action
```python
elif action == "proxy_history":
    return jsonify({
        "success": True,
        "history": http_framework.proxy_history[-100:],
        "total_requests": len(http_framework.proxy_history),
        "vulnerabilities": http_framework.vulnerabilities,
    })
```

#### Set Rules Action
```python
elif action == "set_rules":
    http_framework.set_match_replace_rules(rules)
```

#### Set Scope Action
```python
elif action == "set_scope":
    http_framework.set_scope(scope_host, include_sub)
```

#### Repeater Action
```python
elif action == "repeater":
    result = http_framework.send_custom_request(request_spec)
```

#### Intruder Action
```python
elif action == "intruder":
    result = http_framework.intruder_sniper(
        url, method, location, fuzz_params, payloads, base_data, max_requests
    )
```

## Key Features

### HTTP Request Interception
- **Request Analysis:** Comprehensive request analysis and modification
- **Response Analysis:** Response content and header analysis
- **Vulnerability Detection:** Automated vulnerability detection in responses

### Website Spidering
- **Automated Discovery:** Automated website crawling and URL discovery
- **Form Extraction:** Automatic form discovery and analysis
- **Depth Control:** Configurable crawling depth and page limits

### Proxy Functionality
- **Request History:** Complete request/response history storage
- **Traffic Analysis:** HTTP traffic analysis and inspection
- **Vulnerability Tracking:** Continuous vulnerability detection and tracking

### Advanced Features
- **Match/Replace Rules:** Advanced request/response modification
- **Scope Management:** Target scope definition and enforcement
- **Intruder Mode:** Automated parameter fuzzing and testing

## AuthN/AuthZ
- **Network Access:** Requires network access to target URLs
- **HTTP Testing Framework:** Comprehensive HTTP testing capabilities

## Observability
- **Framework Logging:** "🔥 HTTP FRAMEWORK" section headers
- **Request Logging:** Command execution logging for requests
- **Success/Failure Logging:** Tool status logging for operations
- **Error Logging:** Comprehensive error logging with visual formatting

## Use Cases and Applications

#### Web Application Security Testing
- **Manual Testing:** Interactive web application security testing
- **Automated Analysis:** Automated vulnerability detection and analysis
- **Request Manipulation:** Advanced request modification and testing

#### Penetration Testing
- **HTTP Proxy:** Professional HTTP proxy for penetration testing
- **Traffic Analysis:** Comprehensive HTTP traffic analysis
- **Vulnerability Assessment:** Automated vulnerability assessment

#### Bug Bounty Hunting
- **Request Fuzzing:** Advanced parameter fuzzing and testing
- **Scope Management:** Efficient scope management for bug bounty programs
- **Vulnerability Discovery:** Automated vulnerability discovery

## Testing & Validation
- Action parameter validation
- HTTP framework functionality testing
- Request interception capability verification
- Spider functionality validation

## Code Reproduction
```python
# From line 12170: Complete Flask endpoint implementation
@app.route("/api/tools/http-framework", methods=["POST"])
def http_framework_endpoint():
    """Enhanced HTTP testing framework (Burp Suite alternative)"""
    try:
        params = request.json
        action = params.get("action", "")
        url = params.get("url", "")
        method = params.get("method", "GET")
        data = params.get("data", {})
        headers = params.get("headers", {})
        cookies = params.get("cookies", {})
        max_depth = params.get("max_depth", 3)
        max_pages = params.get("max_pages", 100)
        rules = params.get("rules", [])
        scope_host = params.get("host", "")
        include_sub = params.get("include_subdomains", False)
        request_spec = params.get("request", {})
        location = params.get("location", "")
        fuzz_params = params.get("params", [])
        payloads = params.get("payloads", [])
        base_data = params.get("base_data", {})
        max_requests = params.get("max_requests", 100)
        
        if not action:
            logger.warning("🔥 HTTP Framework called without action parameter")
            return jsonify({"error": "Action parameter is required"}), 400
        
        logger.info(f"🔥 HTTP FRAMEWORK - Action: {action}")
        
        if action == "request":
            if not url:
                return jsonify({"error": "URL parameter is required for request action"}), 400
            result = http_framework.intercept_request(url, method, data, headers, cookies)
            
        elif action == "spider":
            if not url:
                return jsonify({"error": "URL parameter is required for spider action"}), 400
            result = http_framework.spider_website(url, max_depth, max_pages)
            
        elif action == "proxy_history":
            return jsonify({
                "success": True,
                "history": http_framework.proxy_history[-100:],
                "total_requests": len(http_framework.proxy_history),
                "vulnerabilities": http_framework.vulnerabilities,
            })
            
        elif action == "set_rules":
            http_framework.set_match_replace_rules(rules)
            return jsonify({"success": True, "message": "Match/replace rules updated"})
            
        elif action == "set_scope":
            http_framework.set_scope(scope_host, include_sub)
            return jsonify({"success": True, "message": "Scope updated"})
            
        elif action == "repeater":
            result = http_framework.send_custom_request(request_spec)
            
        elif action == "intruder":
            if not url:
                return jsonify({"error": "URL parameter is required for intruder action"}), 400
            result = http_framework.intruder_sniper(
                url, method, location, fuzz_params, payloads, base_data, max_requests
            )
            
        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400
        
        logger.info(f"📊 HTTP Framework {action} completed")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"💥 Error in http-framework endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
