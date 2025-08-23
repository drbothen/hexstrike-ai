---
title: POST /api/tools/amass
group: api
handler: amass
module: __main__
line_range: [9459, 9493]
discovered_in_chunk: 9
---

# POST /api/tools/amass

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Amass for subdomain enumeration with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute Amass for subdomain enumeration with enhanced logging"""
```

## Purpose & Behavior
Subdomain enumeration endpoint providing:
- **Subdomain Discovery:** Discover subdomains using multiple techniques
- **Passive Enumeration:** Perform passive subdomain enumeration
- **Active Enumeration:** Perform active subdomain enumeration
- **Enhanced Logging:** Detailed logging of enumeration progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/amass
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",               // Required: Domain to enumerate
    "mode": "string",                 // Optional: Enumeration mode (default: "enum")
    "passive": boolean,               // Optional: Use passive enumeration (default: false)
    "active": boolean,                // Optional: Use active enumeration (default: true)
    "brute": boolean,                 // Optional: Use brute force enumeration (default: false)
    "wordlist": "string",             // Optional: Path to wordlist for brute force
    "timeout": integer,               // Optional: Timeout in minutes (default: 30)
    "additional_args": "string"       // Optional: Additional amass arguments
}
```

### Parameters
- **domain:** Domain to enumerate (required)
- **mode:** Enumeration mode (optional) - "enum", "intel", "track", "db"
- **passive:** Use passive enumeration (optional, default: false)
- **active:** Use active enumeration (optional, default: true)
- **brute:** Use brute force enumeration (optional, default: false)
- **wordlist:** Path to wordlist for brute force (optional)
- **timeout:** Timeout in minutes (optional, default: 30)
- **additional_args:** Additional amass arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "amass enum -d example.com -active",
    "enumeration_results": {
        "domain": "example.com",
        "subdomains": [
            {
                "subdomain": "www.example.com",
                "ip_addresses": ["93.184.216.34"],
                "source": "DNS"
            },
            {
                "subdomain": "mail.example.com",
                "ip_addresses": ["93.184.216.35"],
                "source": "Certificate"
            }
        ],
        "total_subdomains": 2,
        "sources": ["DNS", "Certificate", "Scraping"]
    },
    "raw_output": "www.example.com\nmail.example.com\n",
    "execution_time": 180.5,
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
mode = params.get("mode", "enum")
passive = params.get("passive", False)
active = params.get("active", True)
brute = params.get("brute", False)
wordlist = params.get("wordlist", "")
timeout = params.get("timeout", 30)
additional_args = params.get("additional_args", "")

if not domain:
    return jsonify({"error": "Domain parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["amass", mode, "-d", domain]

# Enumeration options
if passive:
    command.append("-passive")
if active:
    command.append("-active")
if brute:
    command.append("-brute")
    if wordlist:
        command.extend(["-w", wordlist])

# Timeout
if timeout:
    command.extend(["-timeout", str(timeout)])

# Output file
output_file = f"/tmp/amass_{int(time.time())}.txt"
command.extend(["-o", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

### Execution and Result Parsing
```python
start_time = time.time()
result = execute_command_with_recovery(command_str)
execution_time = time.time() - start_time

# Parse output file
subdomains = []
if os.path.exists(output_file):
    with open(output_file, "r") as f:
        for line in f:
            subdomain = line.strip()
            if subdomain:
                # Resolve IP addresses
                try:
                    ip_addresses = socket.gethostbyname_ex(subdomain)[2]
                except:
                    ip_addresses = []
                
                subdomains.append({
                    "subdomain": subdomain,
                    "ip_addresses": ip_addresses,
                    "source": "Amass"
                })

enumeration_results = {
    "domain": domain,
    "subdomains": subdomains,
    "total_subdomains": len(subdomains),
    "sources": ["DNS", "Certificate", "Scraping"]
}
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Amass execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing domain
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure domain is valid and authorized for enumeration
- **Resource Limits:** Prevent resource exhaustion from intensive enumeration
- **Responsible Use:** Emphasize responsible use of enumeration capabilities

## Use Cases and Applications

#### Subdomain Discovery
- **Asset Discovery:** Discover subdomains for asset inventory
- **Attack Surface Mapping:** Map the attack surface of target domains
- **Security Assessment:** Assess subdomain security posture

#### Reconnaissance
- **Information Gathering:** Gather information about target domains
- **Infrastructure Mapping:** Map target infrastructure
- **Vulnerability Research:** Research potential vulnerabilities

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute Amass for subdomain enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        mode = params.get("mode", "enum")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("🌐 Amass called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400
        
        command = f"amass {mode}"
        
        if mode == "enum":
            command += f" -d {domain}"
        else:
            command += f" -d {domain}"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Amass completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in amass endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
