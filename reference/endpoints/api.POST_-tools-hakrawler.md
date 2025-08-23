---
title: POST /api/tools/hakrawler
group: api
handler: hakrawler
module: __main__
line_range: [13686, 13720]
discovered_in_chunk: 13
---

# POST /api/tools/hakrawler

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Hakrawler for web crawling and URL discovery

## Complete Signature & Definition
```python
@app.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    """Execute Hakrawler for web crawling and URL discovery with enhanced logging"""
```

## Purpose & Behavior
Web crawling and URL discovery endpoint providing:
- **Web Crawling:** Comprehensive web crawling and URL discovery
- **JavaScript Parsing:** Parse JavaScript files for hidden endpoints
- **Sitemap Discovery:** Discover and parse sitemap files
- **Enhanced Logging:** Detailed logging of crawling progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/hakrawler
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                  // Required: Target URL to crawl
    "depth": integer,                 // Optional: Crawl depth (default: 2)
    "threads": integer,               // Optional: Number of threads (default: 8)
    "timeout": integer,               // Optional: Request timeout (default: 10)
    "user_agent": "string",           // Optional: Custom user agent
    "headers": "object",              // Optional: Custom headers
    "include_subs": boolean,          // Optional: Include subdomains (default: false)
    "include_wayback": boolean,       // Optional: Include Wayback Machine (default: false)
    "output_file": "string",          // Optional: Output file path
    "additional_args": "string"       // Optional: Additional hakrawler arguments
}
```

### Parameters
- **url:** Target URL to crawl (required)
- **depth:** Crawl depth (optional, default: 2)
- **threads:** Number of threads (optional, default: 8)
- **timeout:** Request timeout in seconds (optional, default: 10)
- **user_agent:** Custom user agent (optional)
- **headers:** Custom headers (optional) - {"Authorization": "Bearer token"}
- **include_subs:** Include subdomains flag (optional, default: false)
- **include_wayback:** Include Wayback Machine flag (optional, default: false)
- **output_file:** Output file path (optional)
- **additional_args:** Additional hakrawler arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "hakrawler -url https://example.com -depth 2 -t 8",
    "crawling_results": {
        "target_url": "https://example.com",
        "crawl_depth": 2,
        "urls_discovered": [
            "https://example.com/login",
            "https://example.com/api/users",
            "https://example.com/admin/dashboard",
            "https://example.com/js/app.js"
        ],
        "endpoints_found": [
            {
                "url": "https://example.com/api/users",
                "method": "GET",
                "source": "javascript"
            },
            {
                "url": "https://example.com/api/login",
                "method": "POST",
                "source": "form"
            }
        ],
        "total_urls": 156,
        "unique_urls": 142,
        "javascript_files": 12,
        "forms_found": 8,
        "crawl_time": 45.3
    },
    "raw_output": "https://example.com/login\nhttps://example.com/api/users\nhttps://example.com/admin/dashboard\n",
    "execution_time": 45.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing URL (400 Bad Request)
```json
{
    "error": "URL parameter is required"
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
url = params.get("url", "")
depth = params.get("depth", 2)
threads = params.get("threads", 8)
timeout = params.get("timeout", 10)
user_agent = params.get("user_agent", "")
headers = params.get("headers", {})
include_subs = params.get("include_subs", False)
include_wayback = params.get("include_wayback", False)
output_file = params.get("output_file", "")
additional_args = params.get("additional_args", "")

if not url:
    return jsonify({"error": "URL parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["hakrawler", "-url", url]

# Depth
command.extend(["-depth", str(depth)])

# Threads
command.extend(["-t", str(threads)])

# Timeout
command.extend(["-timeout", str(timeout)])

# User agent
if user_agent:
    command.extend(["-ua", user_agent])

# Headers
if headers:
    for key, value in headers.items():
        command.extend(["-h", f"{key}: {value}"])

# Include subdomains
if include_subs:
    command.append("-subs")

# Include Wayback Machine
if include_wayback:
    command.append("-wayback")

# Output file
if output_file:
    command.extend(["-o", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Hakrawler execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing URL
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **URL Validation:** Validate URLs to prevent SSRF attacks
- **Rate Limiting:** Respect rate limits to avoid overwhelming targets
- **Responsible Use:** Emphasize responsible use of web crawling capabilities

## Use Cases and Applications

#### Web Application Testing
- **URL Discovery:** Discover hidden URLs and endpoints
- **Attack Surface Mapping:** Map web application attack surface
- **Endpoint Enumeration:** Enumerate API endpoints and resources

#### Security Assessment
- **Reconnaissance:** Web application reconnaissance and intelligence gathering
- **Vulnerability Research:** Research potential vulnerabilities through URL discovery
- **Penetration Testing:** Support penetration testing with comprehensive URL discovery

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- URL discovery accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    """Execute Hakrawler for web crawling and URL discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        depth = params.get("depth", 2)
        threads = params.get("threads", 8)
        timeout = params.get("timeout", 10)
        user_agent = params.get("user_agent", "")
        headers = params.get("headers", {})
        include_subs = params.get("include_subs", False)
        include_wayback = params.get("include_wayback", False)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            return jsonify({"error": "URL parameter is required"}), 400
        
        # Base command
        command = ["hakrawler", "-url", url]
        
        # Depth
        command.extend(["-depth", str(depth)])
        
        # Threads
        command.extend(["-t", str(threads)])
        
        # Timeout
        command.extend(["-timeout", str(timeout)])
        
        # User agent
        if user_agent:
            command.extend(["-ua", user_agent])
        
        # Headers
        if headers:
            for key, value in headers.items():
                command.extend(["-h", f"{key}: {value}"])
        
        # Include subdomains
        if include_subs:
            command.append("-subs")
        
        # Include Wayback Machine
        if include_wayback:
            command.append("-wayback")
        
        # Output file
        if output_file:
            command.extend(["-o", output_file])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing Hakrawler: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for crawling results
        crawling_results = parse_hakrawler_output(result["output"], url, depth)
        
        logger.info(f"🔍 Hakrawler completed in {execution_time:.2f}s | URLs: {crawling_results.get('total_urls', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "crawling_results": crawling_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in Hakrawler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
