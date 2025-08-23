---
title: POST /api/tools/browser-agent
group: api
handler: browser_agent_endpoint
module: __main__
line_range: [12266, 12353]
discovered_in_chunk: 12
---

# POST /api/tools/browser-agent

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** AI-powered browser agent for web application inspection

## Complete Signature & Definition
```python
@app.route("/api/tools/browser-agent", methods=["POST"])
def browser_agent_endpoint():
    """AI-powered browser agent for web application inspection"""
```

## Purpose & Behavior
AI-powered browser automation endpoint providing:
- **Automated Navigation:** Navigate to URLs and perform comprehensive inspection
- **Screenshot Capture:** Automated screenshot capture for visual documentation
- **Security Analysis:** Comprehensive security analysis of web applications
- **Browser Management:** Browser lifecycle management and status monitoring

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/browser-agent
- **Content-Type:** application/json

### Request Body
```json
{
    "action": "string",                 // Required: Action to perform
    "url": "string",                    // Required for navigate: Target URL
    "headless": boolean,                // Optional: Headless mode (default: true)
    "wait_time": 5,                     // Optional: Wait time after navigation
    "proxy_port": 8080,                 // Optional: Proxy port for interception
    "active_tests": boolean             // Optional: Enable active testing (default: false)
}
```

### Actions Supported
- **navigate:** Navigate to URL and perform comprehensive inspection
- **screenshot:** Take screenshot of current page
- **close:** Close browser instance
- **status:** Get browser agent status

## Response

### Success Response (200 OK)
Response varies by action:

#### Navigate Action
```json
{
    "success": true,
    "page_info": {
        "title": "string",
        "url": "string",
        "cookies": [],
        "local_storage": {},
        "session_storage": {},
        "forms": [],
        "links": [],
        "inputs": [],
        "scripts": [],
        "network_requests": [],
        "console_errors": []
    },
    "security_analysis": {
        "total_issues": 5,
        "issues": [],
        "security_score": 75,
        "passive_modules": []
    },
    "screenshot": "/tmp/hexstrike_screenshot_1234567890.png",
    "timestamp": "2024-01-01T12:00:00Z",
    "active_tests": {
        "active_findings": [],
        "tested_forms": 3
    }
}
```

#### Screenshot Action
```json
{
    "success": true,
    "screenshot": "/tmp/hexstrike_screenshot_1234567890.png",
    "current_url": "string",
    "timestamp": "2024-01-01T12:00:00Z"
}
```

#### Status Action
```json
{
    "success": true,
    "browser_active": true,
    "screenshots_taken": 5,
    "pages_visited": 10
}
```

### Error Responses

#### Missing URL (400 Bad Request)
```json
{
    "error": "URL parameter is required for navigate action"
}
```

#### Browser Not Initialized (400 Bad Request)
```json
{
    "error": "Browser not initialized. Use navigate action first."
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
Each action is processed through dedicated handlers:

#### Navigate Action
```python
if action == "navigate":
    if not browser_agent.driver:
        setup_success = browser_agent.setup_browser(headless, proxy_port)
    
    result = browser_agent.navigate_and_inspect(url, wait_time)
    
    if active_tests:
        active_results = browser_agent.run_active_tests(result.get("page_info", {}))
        result["active_tests"] = active_results
```

#### Screenshot Action
```python
elif action == "screenshot":
    screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
    browser_agent.driver.save_screenshot(screenshot_path)
```

#### Close Action
```python
elif action == "close":
    browser_agent.close_browser()
```

#### Status Action
```python
elif action == "status":
    return jsonify({
        "success": True,
        "browser_active": browser_agent.driver is not None,
        "screenshots_taken": len(browser_agent.screenshots),
        "pages_visited": len(browser_agent.page_sources),
    })
```

### Browser Setup
Automatic browser setup when needed:
```python
if not browser_agent.driver:
    setup_success = browser_agent.setup_browser(headless, proxy_port)
    if not setup_success:
        return jsonify({"error": "Failed to setup browser"}), 500
```

### Active Testing
Optional active security testing:
```python
if result.get("success") and active_tests:
    active_results = browser_agent.run_active_tests(result.get("page_info", {}))
    result["active_tests"] = active_results
```

## Key Features

### Automated Browser Navigation
- **Chrome Automation:** Selenium-based Chrome browser automation
- **Headless Support:** Support for headless and GUI modes
- **Proxy Integration:** HTTP proxy support for request interception

### Comprehensive Page Analysis
- **Page Information Extraction:** Extract titles, URLs, cookies, storage data
- **Form Analysis:** Discover and analyze web forms
- **Link Discovery:** Extract and catalog page links
- **Script Analysis:** Analyze JavaScript usage and inline scripts

### Security Analysis
- **Passive Security Testing:** Automated passive security analysis
- **Active Security Testing:** Optional active security testing
- **Vulnerability Detection:** Comprehensive vulnerability detection
- **Security Scoring:** Automated security score calculation

### Visual Documentation
- **Screenshot Capture:** Automated screenshot capture and storage
- **Visual Evidence:** Visual documentation of testing results
- **Timestamp Tracking:** Complete timestamp tracking for all activities

## AuthN/AuthZ
- **Network Access:** Requires network access to target URLs
- **Browser Automation:** Chrome browser automation capabilities

## Observability
- **Agent Logging:** "🌐 BROWSER AGENT" section headers
- **Navigation Logging:** Browser navigation and inspection logging
- **Active Test Warnings:** Warning logging for active security findings
- **Error Logging:** Comprehensive error logging with visual formatting

## Use Cases and Applications

#### Web Application Security Testing
- **Automated Security Analysis:** Automated web application security analysis
- **Visual Documentation:** Screenshot-based testing documentation
- **Comprehensive Assessment:** Complete web application assessment

#### Penetration Testing
- **Automated Reconnaissance:** Automated web application reconnaissance
- **Security Analysis:** Comprehensive security analysis and reporting
- **Evidence Collection:** Visual evidence collection for reporting

#### Bug Bounty Hunting
- **Automated Analysis:** Automated security analysis for bug bounty programs
- **Vulnerability Discovery:** Discover security vulnerabilities automatically
- **Efficient Testing:** Efficient web application security testing

## Testing & Validation
- Action parameter validation
- Browser setup functionality testing
- Navigation and inspection capability verification
- Screenshot capture functionality testing

## Code Reproduction
```python
# From line 12266: Complete Flask endpoint implementation
@app.route("/api/tools/browser-agent", methods=["POST"])
def browser_agent_endpoint():
    """AI-powered browser agent for web application inspection"""
    try:
        params = request.json
        action = params.get("action", "")
        url = params.get("url", "")
        headless = params.get("headless", True)
        wait_time = params.get("wait_time", 5)
        proxy_port = params.get("proxy_port", 8080)
        active_tests = params.get("active_tests", False)
        
        if action == "navigate":
            if not url:
                logger.warning("🌐 Browser agent called without URL for navigate action")
                return jsonify({"error": "URL parameter is required for navigate action"}), 400
            
            # Setup browser if not already initialized
            if not browser_agent.driver:
                setup_success = browser_agent.setup_browser(headless, proxy_port)
                if not setup_success:
                    return jsonify({"error": "Failed to setup browser"}), 500
            
            logger.info(f"🌐 BROWSER AGENT: Navigating to {url}")
            result = browser_agent.navigate_and_inspect(url, wait_time)
            
            # Run active tests if requested
            if result.get("success") and active_tests:
                logger.info("🔍 Running active security tests")
                active_results = browser_agent.run_active_tests(result.get("page_info", {}))
                result["active_tests"] = active_results
                
                if active_results.get("active_findings"):
                    logger.warning(f"⚠️ Active security findings detected: {len(active_results['active_findings'])}")
            
            return jsonify(result)
        
        elif action == "screenshot":
            if not browser_agent.driver:
                return jsonify({"error": "Browser not initialized. Use navigate action first."}), 400
            
            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            browser_agent.driver.save_screenshot(screenshot_path)
            
            return jsonify({
                "success": True,
                "screenshot": screenshot_path,
                "current_url": browser_agent.driver.current_url,
                "timestamp": datetime.now().isoformat()
            })
        
        elif action == "close":
            browser_agent.close_browser()
            return jsonify({"success": True, "message": "Browser closed"})
        
        elif action == "status":
            return jsonify({
                "success": True,
                "browser_active": browser_agent.driver is not None,
                "screenshots_taken": len(browser_agent.screenshots),
                "pages_visited": len(browser_agent.page_sources),
            })
        
        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400
    
    except Exception as e:
        logger.error(f"💥 Error in browser-agent endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
