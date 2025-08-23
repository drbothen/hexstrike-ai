---
title: POST /api/tools/uro
group: api
handler: uro
module: __main__
line_range: [11371, 11400]
discovered_in_chunk: 11
---

# POST /api/tools/uro

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute uro for filtering out similar URLs

## Complete Signature & Definition
```python
@app.route("/api/tools/uro", methods=["POST"])
def uro():
    """Execute uro for filtering out similar URLs"""
```

## Purpose & Behavior
URL filtering endpoint providing:
- **URL Deduplication:** Filter out similar and duplicate URLs
- **Pattern Recognition:** Identify URL patterns for efficient filtering
- **Data Reduction:** Reduce large URL datasets to unique patterns
- **Enhanced Logging:** Detailed logging of filtering progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/uro
- **Content-Type:** application/json

### Request Body
```json
{
    "urls": ["string"],               // Required: URLs to filter
    "input_file": "string",           // Optional: Input file path (alternative to urls)
    "output_file": "string",          // Optional: Output file path
    "whitelist": ["string"],          // Optional: Whitelist patterns
    "blacklist": ["string"],          // Optional: Blacklist patterns
    "filters": ["string"],            // Optional: Custom filters
    "additional_args": "string"       // Optional: Additional uro arguments
}
```

### Parameters
- **urls:** URLs to filter (required if input_file not provided)
- **input_file:** Input file path (optional, alternative to urls)
- **output_file:** Output file path (optional)
- **whitelist:** Whitelist patterns (optional) - ["*.php", "*/admin/*"]
- **blacklist:** Blacklist patterns (optional) - ["*.css", "*.js"]
- **filters:** Custom filters (optional) - ["hasparams", "hasext"]
- **additional_args:** Additional uro arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "uro -i input.txt -o output.txt",
    "filtering_results": {
        "input_urls": 1000,
        "filtered_urls": 250,
        "reduction_percentage": 75.0,
        "patterns_identified": 15,
        "unique_urls": [
            "http://example.com/page?id=FUZZ",
            "http://example.com/admin/login.php",
            "http://example.com/api/v1/users/FUZZ"
        ],
        "filters_applied": ["hasparams", "dedupe"]
    },
    "raw_output": "http://example.com/page?id=FUZZ\nhttp://example.com/admin/login.php\n",
    "execution_time": 2.1,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing URLs (400 Bad Request)
```json
{
    "error": "URLs parameter or input_file is required"
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
input_file = params.get("input_file", "")
output_file = params.get("output_file", "")
whitelist = params.get("whitelist", [])
blacklist = params.get("blacklist", [])
filters = params.get("filters", [])
additional_args = params.get("additional_args", "")

if not urls and not input_file:
    return jsonify({"error": "URLs parameter or input_file is required"}), 400
```

### Command Construction
```python
# Create input file if URLs provided
if urls and not input_file:
    input_file = f"/tmp/uro_input_{int(time.time())}.txt"
    with open(input_file, "w") as f:
        for url in urls:
            f.write(f"{url}\n")

# Base command
command = ["uro"]

# Input file
if input_file:
    command.extend(["-i", input_file])

# Output file
if output_file:
    command.extend(["-o", output_file])

# Whitelist
if whitelist:
    for pattern in whitelist:
        command.extend(["-w", pattern])

# Blacklist
if blacklist:
    for pattern in blacklist:
        command.extend(["-b", pattern])

# Filters
if filters:
    for filter_type in filters:
        command.extend(["-f", filter_type])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Uro execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing URLs or input file
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **File Path Validation:** Validate file paths to prevent directory traversal
- **URL Validation:** Validate URLs to prevent malicious input
- **Responsible Use:** Emphasize responsible use of URL filtering capabilities

## Use Cases and Applications

#### URL Dataset Management
- **Large Dataset Filtering:** Filter large URL datasets for efficiency
- **Pattern Recognition:** Identify URL patterns for targeted testing
- **Data Optimization:** Optimize URL lists for security testing

#### Web Application Testing
- **Efficient Fuzzing:** Create efficient URL lists for fuzzing
- **Target Optimization:** Optimize target lists for web application testing
- **Resource Management:** Manage testing resources by filtering URLs

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- URL filtering accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/uro", methods=["POST"])
def uro():
    """Execute uro for filtering out similar URLs"""
    try:
        params = request.json
        urls = params.get("urls", [])
        input_file = params.get("input_file", "")
        output_file = params.get("output_file", "")
        whitelist = params.get("whitelist", [])
        blacklist = params.get("blacklist", [])
        filters = params.get("filters", [])
        additional_args = params.get("additional_args", "")
        
        if not urls and not input_file:
            return jsonify({"error": "URLs parameter or input_file is required"}), 400
        
        # Create input file if URLs provided
        temp_input_file = None
        if urls and not input_file:
            temp_input_file = f"/tmp/uro_input_{int(time.time())}.txt"
            input_file = temp_input_file
            with open(input_file, "w") as f:
                for url in urls:
                    f.write(f"{url}\n")
        
        # Base command
        command = ["uro"]
        
        # Input file
        if input_file:
            command.extend(["-i", input_file])
        
        # Output file
        if output_file:
            command.extend(["-o", output_file])
        
        # Whitelist
        if whitelist:
            for pattern in whitelist:
                command.extend(["-w", pattern])
        
        # Blacklist
        if blacklist:
            for pattern in blacklist:
                command.extend(["-b", pattern])
        
        # Filters
        if filters:
            for filter_type in filters:
                command.extend(["-f", filter_type])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing uro: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for filtering results
        if output_file and os.path.exists(output_file):
            with open(output_file, "r") as f:
                filtered_urls = f.read().strip().split("\n")
        else:
            filtered_urls = result["output"].strip().split("\n")
        
        input_count = len(urls) if urls else 0
        if input_file and not urls:
            with open(input_file, "r") as f:
                input_count = len(f.readlines())
        
        filtering_results = {
            "input_urls": input_count,
            "filtered_urls": len([url for url in filtered_urls if url.strip()]),
            "reduction_percentage": ((input_count - len(filtered_urls)) / input_count * 100) if input_count > 0 else 0,
            "patterns_identified": len(set([url.split('?')[0] for url in filtered_urls if url.strip()])),
            "unique_urls": [url for url in filtered_urls if url.strip()][:10],  # First 10 for preview
            "filters_applied": filters if filters else ["default"]
        }
        
        logger.info(f"🔍 Uro completed in {execution_time:.2f}s | Filtered: {filtering_results['filtered_urls']} URLs")
        
        # Cleanup temp file
        if temp_input_file and os.path.exists(temp_input_file):
            os.remove(temp_input_file)
        
        return jsonify({
            "success": True,
            "command": command_str,
            "filtering_results": filtering_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in uro endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
