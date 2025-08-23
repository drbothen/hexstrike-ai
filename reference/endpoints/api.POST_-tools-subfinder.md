---
title: POST /api/tools/subfinder
group: api
handler: subfinder
module: __main__
line_range: [9538, 9574]
discovered_in_chunk: 9
---

# POST /api/tools/subfinder

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Subfinder for passive subdomain enumeration

## Complete Signature & Definition
```python
@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Execute Subfinder for passive subdomain enumeration with enhanced logging"""
```

## Purpose & Behavior
Passive subdomain enumeration endpoint providing:
- **Passive Discovery:** Discover subdomains using passive techniques only
- **Multiple Sources:** Utilize multiple data sources for comprehensive coverage
- **Fast Enumeration:** High-speed subdomain discovery
- **Enhanced Logging:** Detailed logging of enumeration progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/subfinder
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",               // Required: Domain to enumerate
    "sources": ["string"],            // Optional: Specific sources to use
    "silent": boolean,                // Optional: Silent mode (default: false)
    "timeout": integer,               // Optional: Timeout in seconds (default: 30)
    "threads": integer,               // Optional: Number of threads (default: 10)
    "output_file": "string",          // Optional: Output file path
    "additional_args": "string"       // Optional: Additional subfinder arguments
}
```

### Parameters
- **domain:** Domain to enumerate (required)
- **sources:** Specific sources to use (optional) - ["virustotal", "shodan", "censys", etc.]
- **silent:** Silent mode flag (optional, default: false)
- **timeout:** Timeout in seconds (optional, default: 30)
- **threads:** Number of threads (optional, default: 10)
- **output_file:** Output file path (optional)
- **additional_args:** Additional subfinder arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "subfinder -d example.com -silent",
    "enumeration_results": {
        "domain": "example.com",
        "subdomains": [
            "www.example.com",
            "mail.example.com",
            "api.example.com"
        ],
        "total_subdomains": 3,
        "sources_used": ["virustotal", "shodan", "censys"],
        "unique_subdomains": 3
    },
    "raw_output": "www.example.com\nmail.example.com\napi.example.com\n",
    "execution_time": 25.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Domain (400 Bad Request)
```json
{
    "error": "Domain parameter is required"
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
domain = params.get("domain", "")
sources = params.get("sources", [])
silent = params.get("silent", False)
timeout = params.get("timeout", 30)
threads = params.get("threads", 10)
output_file = params.get("output_file", "")
additional_args = params.get("additional_args", "")

if not domain:
    return jsonify({"error": "Domain parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["subfinder", "-d", domain]

# Sources
if sources:
    command.extend(["-sources", ",".join(sources)])

# Silent mode
if silent:
    command.append("-silent")

# Timeout
if timeout:
    command.extend(["-timeout", str(timeout)])

# Threads
if threads:
    command.extend(["-t", str(threads)])

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
- **Authorization:** Subfinder execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing domain
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure domain is valid and authorized for enumeration
- **Rate Limiting:** Respect rate limits of passive sources
- **Responsible Use:** Emphasize responsible use of enumeration capabilities

## Use Cases and Applications

#### Passive Reconnaissance
- **Asset Discovery:** Discover subdomains without active scanning
- **Attack Surface Mapping:** Map the attack surface passively
- **Intelligence Gathering:** Gather intelligence about target domains

#### Security Assessment
- **Subdomain Inventory:** Create inventory of subdomains
- **Security Posture Assessment:** Assess subdomain security posture
- **Vulnerability Research:** Research potential vulnerabilities

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Execute Subfinder for passive subdomain enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        sources = params.get("sources", [])
        silent = params.get("silent", False)
        timeout = params.get("timeout", 30)
        threads = params.get("threads", 10)
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        
        # Base command
        command = ["subfinder", "-d", domain]
        
        # Sources
        if sources:
            command.extend(["-sources", ",".join(sources)])
        
        # Silent mode
        if silent:
            command.append("-silent")
        
        # Timeout
        if timeout:
            command.extend(["-timeout", str(timeout)])
        
        # Threads
        if threads:
            command.extend(["-t", str(threads)])
        
        # Output file
        if output_file:
            command.extend(["-o", output_file])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing subfinder: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse subdomains from output
        subdomains = []
        for line in result["output"].split("\n"):
            subdomain = line.strip()
            if subdomain and subdomain != domain:
                subdomains.append(subdomain)
        
        enumeration_results = {
            "domain": domain,
            "subdomains": subdomains,
            "total_subdomains": len(subdomains),
            "sources_used": sources if sources else ["default"],
            "unique_subdomains": len(set(subdomains))
        }
        
        logger.info(f"🔍 Subfinder completed in {execution_time:.2f}s | Found: {len(subdomains)} subdomains")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "enumeration_results": enumeration_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in subfinder endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
