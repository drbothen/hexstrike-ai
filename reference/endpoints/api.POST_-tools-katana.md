---
title: POST /api/tools/katana
group: api
handler: katana
module: __main__
line_range: [10970, 11006]
discovered_in_chunk: 11
---

# POST /api/tools/katana

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Katana for next-generation crawling and spidering with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/katana", methods=["POST"])
def katana():
    """Execute Katana for next-generation crawling and spidering with enhanced logging"""
```

## Purpose & Behavior
Next-generation web crawling endpoint providing:
- **Advanced Web Crawling:** Execute Katana for comprehensive web application crawling
- **JavaScript Support:** Advanced JavaScript crawling and execution
- **Form Extraction:** Automatic form discovery and extraction
- **Structured Output:** JSON-based structured output for analysis

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/katana
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                    // Required: Target URL to crawl
    "depth": 3,                         // Optional: Crawling depth (default: 3)
    "js_crawl": boolean,                // Optional: Enable JavaScript crawling (default: true)
    "form_extraction": boolean,         // Optional: Enable form extraction (default: true)
    "output_format": "string",          // Optional: Output format (default: "json")
    "additional_args": "string"         // Optional: Additional katana arguments
}
```

### Parameters
- **url:** Target URL to crawl (required)
- **depth:** Maximum crawling depth (optional, default: 3)
- **js_crawl:** Enable JavaScript crawling and execution (optional, default: true)
- **form_extraction:** Enable form discovery and extraction (optional, default: true)
- **output_format:** Output format for results (optional, default: "json")
- **additional_args:** Additional katana arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Katana crawling output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 120.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "katana -u https://example.com -d 3 -jc -fx -jsonl"
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

### Command Construction Process
1. **Base Command:** Start with "katana -u {url} -d {depth}"
2. **JavaScript Configuration:** Add JavaScript crawling if enabled
3. **Form Extraction:** Add form extraction if enabled
4. **Output Configuration:** Configure output format
5. **Additional Arguments:** Append additional arguments

### Command Building Logic
```python
command = f"katana -u {url} -d {depth}"

if js_crawl:
    command += " -jc"

if form_extraction:
    command += " -fx"

if output_format == "json":
    command += " -jsonl"

if additional_args:
    command += f" {additional_args}"
```

### Default Configuration
- **Default Depth:** 3 levels for balanced coverage
- **JavaScript Crawling:** Enabled by default for modern web applications
- **Form Extraction:** Enabled by default for comprehensive discovery
- **JSON Output:** Structured JSON Lines output for analysis

### Katana Features
- **Next-generation Crawling:** Modern web crawling engine
- **JavaScript Support:** Full JavaScript execution and crawling
- **Form Discovery:** Automatic form discovery and extraction
- **High Performance:** Fast and efficient crawling
- **Structured Output:** JSON-based output for integration

### Crawling Capabilities
- **Deep Crawling:** Configurable depth crawling
- **JavaScript Execution:** Execute JavaScript for dynamic content
- **Form Analysis:** Discover and analyze web forms
- **Link Discovery:** Comprehensive link discovery and following

## AuthN/AuthZ
- **Network Access:** Requires network access to target URLs
- **Web Crawling Tool:** Modern web application crawling tool

## Observability
- **Crawling Logging:** "⚔️ Starting Katana crawl: {url}"
- **Completion Logging:** "📊 Katana crawl completed for {url}"
- **Warning Logging:** "🌐 Katana called without URL parameter"
- **Error Logging:** "💥 Error in katana endpoint: {error}"

## Use Cases and Applications

#### Web Application Security Testing
- **Attack Surface Discovery:** Discover web application attack surface
- **Endpoint Discovery:** Find hidden endpoints and resources
- **Form Analysis:** Analyze web forms for security testing

#### Bug Bounty Hunting
- **Reconnaissance:** Comprehensive web application reconnaissance
- **Asset Discovery:** Discover additional assets and endpoints
- **Vulnerability Research:** Support vulnerability research workflows

#### Web Application Analysis
- **Site Mapping:** Create comprehensive site maps
- **Content Discovery:** Discover all accessible content
- **Technology Analysis:** Analyze web application technologies

## Testing & Validation
- URL parameter validation
- Depth configuration testing
- JavaScript crawling functionality verification
- Form extraction capability testing

## Code Reproduction
Complete Flask endpoint implementation for Katana next-generation web crawling with JavaScript support, form extraction, and structured output generation. Essential for modern web application security testing and reconnaissance workflows.
