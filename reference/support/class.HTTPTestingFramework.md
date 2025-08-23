---
title: class.HTTPTestingFramework
kind: class
scope: module
module: __main__
line_range: [11412, 11573+]
discovered_in_chunk: 11
---

# HTTPTestingFramework

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced HTTP testing framework as Burp Suite alternative

## Complete Signature & Definition
```python
class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []  # [{'where':'query|headers|body|url','pattern':'regex','replacement':'str'}]
        self.scope = None  # {'host': 'example.com', 'include_subdomains': True}
        self._req_id = 0
```

## Purpose & Behavior
Advanced HTTP testing framework providing:
- **Request Interception:** Intercept and analyze HTTP requests and responses
- **Proxy Functionality:** HTTP proxy capabilities for request/response analysis
- **Match and Replace:** Advanced request/response modification capabilities
- **Vulnerability Detection:** Automated vulnerability detection and analysis
- **Scope Management:** Target scope definition and enforcement

## Class Attributes
- **session:** requests.Session object for HTTP operations
- **proxy_history:** List storing intercepted request/response pairs
- **vulnerabilities:** List storing detected vulnerabilities
- **match_replace_rules:** List of match/replace rules for request modification
- **scope:** Dictionary defining target scope (host, subdomains)
- **_req_id:** Internal request ID counter

## Methods

### __init__(self)
Initialize the HTTP testing framework with default configuration.

### setup_proxy(self, proxy_port: int = 8080)
```python
def setup_proxy(self, proxy_port: int = 8080):
    """Setup HTTP proxy for request interception"""
    self.session.proxies = {
        'http': f'http://127.0.0.1:{proxy_port}',
        'https': f'http://127.0.0.1:{proxy_port}'
    }
```

### intercept_request(self, url: str, method: str = 'GET', data: dict = None, headers: dict = None, cookies: dict = None) -> dict
```python
def intercept_request(self, url: str, method: str = 'GET', data: dict = None, 
                     headers: dict = None, cookies: dict = None) -> dict:
    """Intercept and analyze HTTP requests"""
```

**Purpose:** Intercept HTTP requests, apply modifications, and analyze responses
**Parameters:**
- url: Target URL for the request
- method: HTTP method (GET, POST, PUT, DELETE, etc.)
- data: Request data/parameters
- headers: Custom headers
- cookies: Custom cookies

**Returns:** Dictionary containing request/response data and vulnerability analysis

### set_match_replace_rules(self, rules: list)
```python
def set_match_replace_rules(self, rules: list):
    """Set match/replace rules. Each rule: {'where','pattern','replacement'}"""
    self.match_replace_rules = rules or []
```

### set_scope(self, host: str, include_subdomains: bool = True)
```python
def set_scope(self, host: str, include_subdomains: bool = True):
    self.scope = {'host': host, 'include_subdomains': include_subdomains}
```

### _in_scope(self, url: str) -> bool
```python
def _in_scope(self, url: str) -> bool:
    """Check if URL is within defined scope"""
```

### _apply_match_replace(self, url: str, data, headers: dict)
```python
def _apply_match_replace(self, url: str, data, headers: dict):
    """Apply match/replace rules to request components"""
```

### send_custom_request(self, request_spec: dict) -> dict
```python
def send_custom_request(self, request_spec: dict) -> dict:
    """Send a custom request with explicit fields, applying rules."""
```

### intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query', params: list = None, payloads: list = None, base_data: dict = None, max_requests: int = 100) -> dict
```python
def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                    params: list = None, payloads: list = None, base_data: dict = None,
                    max_requests: int = 100) -> dict:
    """Simple fuzzing: iterate payloads over each parameter individually (Sniper)."""
```

## Key Features

### Request Interception and Analysis
- **HTTP Method Support:** Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)
- **Header Management:** Custom header configuration and modification
- **Cookie Handling:** Cookie management and manipulation
- **Response Analysis:** Comprehensive response analysis and storage

### Match and Replace Functionality
- **URL Modification:** Modify URLs using regex patterns
- **Query Parameter Modification:** Modify query parameters
- **Header Modification:** Modify request/response headers
- **Body Modification:** Modify request body content

### Scope Management
- **Host-based Scoping:** Define target hosts for testing
- **Subdomain Inclusion:** Include/exclude subdomains from scope
- **Scope Enforcement:** Automatic scope validation for requests

### Vulnerability Detection
- **Automated Analysis:** Automatic vulnerability detection in responses
- **Vulnerability Storage:** Store and categorize detected vulnerabilities
- **Pattern Matching:** Use patterns to identify security issues

### Intruder Functionality
- **Sniper Mode:** Single-parameter fuzzing mode
- **Payload Management:** Support for custom payload lists
- **Request Limiting:** Configurable request limits for testing

## Dependencies
- **requests:** HTTP library for request/response handling
- **datetime:** Timestamp generation for request history
- **urllib.parse:** URL parsing and manipulation
- **re:** Regular expression support for match/replace

## Use Cases and Applications

#### Web Application Security Testing
- **Manual Testing:** Interactive web application security testing
- **Automated Scanning:** Automated vulnerability detection
- **Request Manipulation:** Advanced request modification and testing

#### Penetration Testing
- **HTTP Proxy:** Use as HTTP proxy for penetration testing
- **Request Fuzzing:** Fuzz web application parameters
- **Vulnerability Assessment:** Assess web application security

#### Bug Bounty Hunting
- **Request Analysis:** Analyze HTTP requests and responses
- **Parameter Testing:** Test web application parameters for vulnerabilities
- **Scope Management:** Manage testing scope for bug bounty programs

## Testing & Validation
- Request interception functionality testing
- Match/replace rule application verification
- Scope management validation
- Vulnerability detection accuracy testing

## Code Reproduction
Complete HTTP testing framework class providing Burp Suite alternative functionality with request interception, match/replace capabilities, scope management, and automated vulnerability detection. Essential for web application security testing and HTTP traffic analysis.
