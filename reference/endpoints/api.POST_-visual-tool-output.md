---
title: POST /api/visual/tool-output
group: api
handler: format_tool_output
module: __main__
line_range: [7633, 7658]
discovered_in_chunk: 7
---

# POST /api/visual/tool-output

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Format tool output into visual presentation

## Complete Signature & Definition
```python
@app.route("/api/visual/tool-output", methods=["POST"])
def format_tool_output():
    """Format tool output into visual presentation with enhanced logging"""
```

## Purpose & Behavior
Tool output formatting endpoint providing:
- **Output Formatting:** Format raw tool output into visual presentations
- **Data Visualization:** Create visual representations of tool results
- **Customization:** Customize output appearance and format
- **Enhanced Logging:** Detailed logging of formatting operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/visual/tool-output
- **Content-Type:** application/json

### Request Body
```json
{
    "tool_data": {
        "tool_name": "string",        // Required: Name of the tool
        "command": "string",          // Required: Command executed
        "output": "string",           // Required: Raw tool output
        "return_code": integer,       // Optional: Command return code
        "execution_time": number,     // Optional: Execution time
        "timestamp": "string",        // Optional: Execution timestamp
        "metadata": "object"          // Optional: Additional metadata
    },
    "format_options": {
        "output_type": "string",      // Optional: Output type (default: html)
        "style": "string",            // Optional: Visual style (default: modern)
        "highlight_syntax": boolean,  // Optional: Syntax highlighting (default: true)
        "include_metadata": boolean,  // Optional: Include metadata (default: true)
        "color_scheme": "string",     // Optional: Color scheme (default: dark)
        "font_size": "string"         // Optional: Font size (default: medium)
    },
    "parsing_options": {
        "parse_structured": boolean,  // Optional: Parse structured output (default: true)
        "extract_findings": boolean,  // Optional: Extract findings (default: true)
        "create_summary": boolean,    // Optional: Create summary (default: true)
        "filter_noise": boolean       // Optional: Filter noise (default: true)
    }
}
```

### Parameters
- **tool_data:** Tool execution data (required)
  - **tool_name:** Name of the tool (required)
  - **command:** Command executed (required)
  - **output:** Raw tool output (required)
  - **return_code:** Command return code (optional)
  - **execution_time:** Execution time (optional)
  - **timestamp:** Execution timestamp (optional)
  - **metadata:** Additional metadata (optional)
- **format_options:** Formatting options (optional)
- **parsing_options:** Output parsing options (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "formatted_output": {
        "tool_name": "nmap",
        "command": "nmap -sV 192.168.1.1",
        "output_type": "html",
        "style": "modern",
        "content": "<div class='tool-output'>...</div>",
        "summary": {
            "hosts_scanned": 1,
            "ports_found": 5,
            "services_detected": ["ssh", "http", "https"]
        }
    },
    "parsing_results": {
        "structured_data": {
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "ports": [
                        {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
                        {"port": 80, "service": "http", "version": "Apache 2.4.6"},
                        {"port": 443, "service": "https", "version": "Apache 2.4.6"}
                    ]
                }
            ]
        },
        "findings": [
            {
                "type": "open_port",
                "port": 22,
                "service": "ssh",
                "severity": "info"
            }
        ],
        "statistics": {
            "total_findings": 5,
            "critical": 0,
            "high": 0,
            "medium": 2,
            "low": 3
        }
    },
    "output_files": {
        "html_file": "/tmp/tool_output_1234567890.html",
        "json_file": "/tmp/tool_output_1234567890.json",
        "download_url": "/api/files/download/tool_output_1234567890.html"
    },
    "processing_time": 3.2,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: tool_name, command, output"
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
tool_data = params.get("tool_data", {})
format_options = params.get("format_options", {})
parsing_options = params.get("parsing_options", {})

# Validate required tool data fields
required_fields = ["tool_name", "command", "output"]
missing_fields = [field for field in required_fields if not tool_data.get(field)]
if missing_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
```

### Output Formatting Logic
```python
# Use ModernVisualEngine to format output
formatting_data = {
    "tool": tool_data,
    "format": format_options,
    "parsing": parsing_options
}

# Format output using visual engine
formatted_result = visual_engine.format_tool_output(formatting_data)

# Parse structured data if requested
if parsing_options.get("parse_structured", True):
    structured_data = parse_tool_output(tool_data["tool_name"], tool_data["output"])
    formatted_result["structured_data"] = structured_data

# Extract findings if requested
if parsing_options.get("extract_findings", True):
    findings = extract_findings(tool_data["tool_name"], tool_data["output"])
    formatted_result["findings"] = findings
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Tool output formatting access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Formatting Errors:** Handle errors during output formatting
- **Parsing Errors:** Handle errors during output parsing
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Output Sanitization:** Sanitize tool output for security
- **XSS Prevention:** Prevent XSS in formatted HTML output
- **File Security:** Secure handling of generated output files
- **Access Control:** Control access to formatted outputs

## Use Cases and Applications

#### Tool Output Enhancement
- **Readability:** Improve readability of raw tool output
- **Visualization:** Create visual representations of tool results
- **Reporting:** Format tool output for inclusion in reports

#### Data Processing
- **Structured Parsing:** Parse unstructured tool output into structured data
- **Finding Extraction:** Extract security findings from tool output
- **Summary Generation:** Generate summaries of tool execution results

## Testing & Validation
- Parameter validation accuracy testing
- Output formatting functionality testing
- Parsing accuracy verification testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/visual/tool-output", methods=["POST"])
def format_tool_output():
    """Format tool output into visual presentation with enhanced logging"""
    try:
        params = request.json
        tool_data = params.get("tool_data", {})
        format_options = params.get("format_options", {})
        parsing_options = params.get("parsing_options", {})
        
        # Validate required tool data fields
        required_fields = ["tool_name", "command", "output"]
        missing_fields = [field for field in required_fields if not tool_data.get(field)]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        logger.info(f"🎨 Formatting output for tool: {tool_data['tool_name']}")
        
        start_time = time.time()
        
        # Use ModernVisualEngine to format output
        formatting_data = {
            "tool": tool_data,
            "format": format_options,
            "parsing": parsing_options
        }
        
        # Format output using visual engine
        formatted_result = visual_engine.format_tool_output(formatting_data)
        
        # Parse structured data if requested
        structured_data = None
        if parsing_options.get("parse_structured", True):
            structured_data = parse_tool_output(tool_data["tool_name"], tool_data["output"])
        
        # Extract findings if requested
        findings = []
        if parsing_options.get("extract_findings", True):
            findings = extract_findings(tool_data["tool_name"], tool_data["output"])
        
        # Create summary if requested
        summary = {}
        if parsing_options.get("create_summary", True):
            summary = create_output_summary(tool_data["tool_name"], tool_data["output"])
        
        processing_time = time.time() - start_time
        
        # Save formatted output to files
        output_type = format_options.get("output_type", "html")
        output_file = f"/tmp/tool_output_{int(time.time() * 1000000)}.{output_type}"
        json_file = f"/tmp/tool_output_{int(time.time() * 1000000)}.json"
        
        # Save HTML output
        with open(output_file, "w") as f:
            f.write(formatted_result["content"])
        
        # Save JSON data
        json_data = {
            "tool_data": tool_data,
            "structured_data": structured_data,
            "findings": findings,
            "summary": summary
        }
        with open(json_file, "w") as f:
            json.dump(json_data, f, indent=2)
        
        formatted_output = {
            "tool_name": tool_data["tool_name"],
            "command": tool_data["command"],
            "output_type": output_type,
            "style": format_options.get("style", "modern"),
            "content": formatted_result["content"],
            "summary": summary
        }
        
        parsing_results = {
            "structured_data": structured_data,
            "findings": findings,
            "statistics": {
                "total_findings": len(findings),
                "critical": len([f for f in findings if f.get("severity") == "critical"]),
                "high": len([f for f in findings if f.get("severity") == "high"]),
                "medium": len([f for f in findings if f.get("severity") == "medium"]),
                "low": len([f for f in findings if f.get("severity") == "low"])
            }
        }
        
        output_files = {
            "html_file": output_file,
            "json_file": json_file,
            "download_url": f"/api/files/download/{os.path.basename(output_file)}"
        }
        
        logger.info(f"🎨 Tool output formatted in {processing_time:.2f}s | Findings: {len(findings)}")
        
        return jsonify({
            "success": True,
            "formatted_output": formatted_output,
            "parsing_results": parsing_results,
            "output_files": output_files,
            "processing_time": processing_time,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error formatting tool output: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
