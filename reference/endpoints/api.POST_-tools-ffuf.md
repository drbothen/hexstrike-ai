---
title: POST /api/tools/ffuf
group: api
handler: ffuf
module: __main__
line_range: [9370, 9411]
discovered_in_chunk: 9
---

# POST /api/tools/ffuf

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute FFuf web fuzzer with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute FFuf web fuzzer with enhanced logging"""
```

## Purpose & Behavior
FFuf web fuzzing endpoint providing:
- **High-Speed Web Fuzzing:** Execute FFuf for fast web content discovery
- **Multi-mode Fuzzing:** Support for directory, vhost, and parameter fuzzing modes
- **Configurable Matching:** Flexible HTTP status code matching
- **Enhanced Performance:** Optimized fuzzing with intelligent filtering

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/ffuf
- **Content-Type:** application/json

### Request Body
```json
{
    "url": "string",                    // Required: Target URL to fuzz
    "wordlist": "string",               // Optional: Wordlist file path
    "mode": "string",                   // Optional: Fuzzing mode (default: "directory")
    "match_codes": "string",            // Optional: HTTP status codes to match
    "additional_args": "string"         // Optional: Additional ffuf arguments
}
```

### Parameters
- **url:** Target URL to fuzz (required)
- **wordlist:** Wordlist file path (optional, default: "/usr/share/wordlists/dirb/common.txt")
- **mode:** Fuzzing mode - "directory", "vhost", "parameter" (optional, default: "directory")
- **match_codes:** HTTP status codes to match (optional, default: "200,204,301,302,307,401,403")
- **additional_args:** Additional ffuf arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // FFuf fuzzing output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 30.5,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403"
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

### Fuzzing Mode Configuration

#### Directory Mode (default)
```python
if mode == "directory":
    command += f" -u {url}/FUZZ -w {wordlist}"
```

#### Virtual Host Mode
```python
elif mode == "vhost":
    command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
```

#### Parameter Mode
```python
elif mode == "parameter":
    command += f" -u {url}?FUZZ=value -w {wordlist}"
```

### Command Construction Process
1. **Base Command:** Start with "ffuf"
2. **Mode Configuration:** Configure fuzzing mode and URL pattern
3. **Wordlist Configuration:** Add wordlist file
4. **Status Code Matching:** Add HTTP status code filters
5. **Additional Arguments:** Append additional arguments

### Default Configuration
- **Default Wordlist:** "/usr/share/wordlists/dirb/common.txt"
- **Default Mode:** "directory" for directory/file discovery
- **Default Match Codes:** "200,204,301,302,307,401,403" for comprehensive discovery

### Status Code Matching
```python
command += f" -mc {match_codes}"
```

### FFuf Features
- **High-Speed Fuzzing:** Fast web content discovery
- **Flexible Fuzzing:** Multiple fuzzing modes and positions
- **Smart Filtering:** Advanced filtering and matching options
- **Performance Optimization:** Optimized for speed and efficiency

## AuthN/AuthZ
- **Network Access:** Requires network access to target URLs
- **Web Fuzzing Tool:** Web content discovery tool

## Observability
- **Fuzzing Logging:** "🔍 Starting FFuf {mode} fuzzing: {url}"
- **Completion Logging:** "📊 FFuf fuzzing completed for {url}"
- **Warning Logging:** "🌐 FFuf called without URL parameter"
- **Error Logging:** "💥 Error in ffuf endpoint: {error}"

## Use Cases and Applications

#### Web Content Discovery
- **Directory Discovery:** Discover hidden directories and files
- **Virtual Host Discovery:** Enumerate virtual hosts
- **Parameter Discovery:** Find hidden parameters

#### Security Assessment
- **Attack Surface Mapping:** Map web application attack surface
- **Hidden Resource Discovery:** Find hidden web resources
- **Configuration Assessment:** Assess web server configurations

## Testing & Validation
- Mode configuration accuracy testing
- URL pattern construction verification
- Status code matching validation
- Wordlist path verification

## Code Reproduction
```python
@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute FFuf web fuzzer with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = params.get("mode", "directory")
        match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("🌐 FFuf called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"ffuf"
        
        if mode == "directory":
            command += f" -u {url}/FUZZ -w {wordlist}"
        elif mode == "vhost":
            command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
        elif mode == "parameter":
            command += f" -u {url}?FUZZ=value -w {wordlist}"
        else:
            command += f" -u {url} -w {wordlist}"
            
        command += f" -mc {match_codes}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = execute_command(command)
        logger.info(f"📊 FFuf fuzzing completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ffuf endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
