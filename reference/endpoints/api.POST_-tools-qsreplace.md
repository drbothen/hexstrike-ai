---
title: POST /api/tools/qsreplace
group: api
handler: qsreplace
module: __main__
line_range: [11345, 11370]
discovered_in_chunk: 11
---

# POST /api/tools/qsreplace

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute qsreplace for query string parameter replacement

## Complete Signature & Definition
```python
@app.route("/api/tools/qsreplace", methods=["POST"])
def qsreplace():
    """Execute qsreplace for query string parameter replacement"""
```

## Purpose & Behavior
Query string manipulation endpoint providing:
- **Parameter Replacement:** Replace query string parameters in URLs
- **URL Manipulation:** Manipulate URLs for testing purposes
- **Payload Injection:** Inject payloads into URL parameters
- **Enhanced Logging:** Detailed logging of processing progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/qsreplace
- **Content-Type:** application/json

### Request Body
```json
{
    "urls": ["string"],               // Required: URLs to process
    "replacement": "string",          // Required: Replacement value for parameters
    "parameter": "string",            // Optional: Specific parameter to replace
    "append": boolean,                // Optional: Append to existing parameters (default: false)
    "additional_args": "string"       // Optional: Additional qsreplace arguments
}
```

### Parameters
- **urls:** URLs to process (required) - ["http://example.com?param=value"]
- **replacement:** Replacement value for parameters (required)
- **parameter:** Specific parameter to replace (optional)
- **append:** Append to existing parameters flag (optional, default: false)
- **additional_args:** Additional qsreplace arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "qsreplace 'FUZZ'",
    "processing_results": {
        "input_urls": [
            "http://example.com?param=value&test=123"
        ],
        "output_urls": [
            "http://example.com?param=FUZZ&test=FUZZ"
        ],
        "total_processed": 1,
        "parameters_replaced": 2
    },
    "raw_output": "http://example.com?param=FUZZ&test=FUZZ\n",
    "execution_time": 0.2,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Parameters (400 Bad Request)
```json
{
    "error": "Missing required parameters: urls, replacement"
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
urls = params.get("urls", [])
replacement = params.get("replacement", "")
parameter = params.get("parameter", "")
append = params.get("append", False)
additional_args = params.get("additional_args", "")

# Validate required parameters
missing_params = []
if not urls:
    missing_params.append("urls")
if not replacement:
    missing_params.append("replacement")
if missing_params:
    return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
```

### Command Construction
```python
# Create URLs file
urls_file = f"/tmp/qsreplace_urls_{int(time.time())}.txt"
with open(urls_file, "w") as f:
    for url in urls:
        f.write(f"{url}\n")

# Base command
command = ["cat", urls_file, "|", "qsreplace", f"'{replacement}'"]

# Specific parameter
if parameter:
    command.extend(["-p", parameter])

# Append mode
if append:
    command.append("-a")

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Qsreplace execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing required parameters
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **URL Validation:** Validate URLs to prevent malicious input
- **Parameter Sanitization:** Sanitize replacement values
- **Responsible Use:** Emphasize responsible use of URL manipulation capabilities

## Use Cases and Applications

#### Web Application Testing
- **Parameter Fuzzing:** Fuzz URL parameters for security testing
- **Payload Injection:** Inject test payloads into URL parameters
- **URL Manipulation:** Manipulate URLs for various testing scenarios

#### Security Assessment
- **XSS Testing:** Test for XSS vulnerabilities in URL parameters
- **SQL Injection Testing:** Test for SQL injection in URL parameters
- **Parameter Pollution:** Test for parameter pollution vulnerabilities

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- URL processing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/qsreplace", methods=["POST"])
def qsreplace():
    """Execute qsreplace for query string parameter replacement"""
    try:
        params = request.json
        urls = params.get("urls", [])
        replacement = params.get("replacement", "")
        parameter = params.get("parameter", "")
        append = params.get("append", False)
        additional_args = params.get("additional_args", "")
        
        # Validate required parameters
        missing_params = []
        if not urls:
            missing_params.append("urls")
        if not replacement:
            missing_params.append("replacement")
        if missing_params:
            return jsonify({"error": f"Missing required parameters: {', '.join(missing_params)}"}), 400
        
        # Create URLs file
        urls_file = f"/tmp/qsreplace_urls_{int(time.time())}.txt"
        with open(urls_file, "w") as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Base command
        command = ["cat", urls_file, "|", "qsreplace", f"'{replacement}'"]
        
        # Specific parameter
        if parameter:
            command.extend(["-p", parameter])
        
        # Append mode
        if append:
            command.append("-a")
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing qsreplace: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for processing results
        output_urls = result["output"].strip().split("\n")
        processing_results = {
            "input_urls": urls,
            "output_urls": [url for url in output_urls if url.strip()],
            "total_processed": len(urls),
            "parameters_replaced": len([url for url in output_urls if replacement in url])
        }
        
        logger.info(f"🔍 Qsreplace completed in {execution_time:.2f}s")
        
        # Cleanup URLs file
        if os.path.exists(urls_file):
            os.remove(urls_file)
        
        return jsonify({
            "success": True,
            "command": command_str,
            "processing_results": processing_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in qsreplace endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
