---
title: POST /api/tools/fierce
group: api
handler: fierce
module: __main__
line_range: [12528, 12560]
discovered_in_chunk: 12
---

# POST /api/tools/fierce

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute fierce for DNS reconnaissance

## Complete Signature & Definition
```python
@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce for DNS reconnaissance with enhanced logging"""
```

## Purpose & Behavior
DNS reconnaissance endpoint providing:
- **DNS Enumeration:** Comprehensive DNS enumeration and reconnaissance
- **Subdomain Discovery:** Discover subdomains through DNS techniques
- **Zone Transfer Testing:** Test for DNS zone transfer vulnerabilities
- **Enhanced Logging:** Detailed logging of reconnaissance progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/fierce
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",               // Required: Domain to enumerate
    "wordlist": "string",             // Optional: Wordlist file path
    "dns_servers": ["string"],        // Optional: DNS servers to use
    "delay": integer,                 // Optional: Delay between requests (default: 1)
    "threads": integer,               // Optional: Number of threads (default: 1)
    "range": "string",                // Optional: IP range for reverse lookups
    "additional_args": "string"       // Optional: Additional fierce arguments
}
```

### Parameters
- **domain:** Domain to enumerate (required)
- **wordlist:** Wordlist file path (optional)
- **dns_servers:** DNS servers to use (optional) - ["8.8.8.8", "1.1.1.1"]
- **delay:** Delay between requests in seconds (optional, default: 1)
- **threads:** Number of threads (optional, default: 1)
- **range:** IP range for reverse lookups (optional)
- **additional_args:** Additional fierce arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "fierce --domain example.com --wordlist /usr/share/fierce/hosts.txt",
    "reconnaissance_results": {
        "domain": "example.com",
        "subdomains": [
            {
                "subdomain": "www.example.com",
                "ip": "93.184.216.34",
                "type": "A"
            },
            {
                "subdomain": "mail.example.com",
                "ip": "93.184.216.35",
                "type": "A"
            }
        ],
        "total_subdomains": 2,
        "dns_servers_used": ["8.8.8.8"],
        "zone_transfer_attempted": true,
        "zone_transfer_successful": false
    },
    "raw_output": "DNS Servers for example.com:\n\tns1.example.com\n\tns2.example.com\n",
    "execution_time": 45.7,
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
wordlist = params.get("wordlist", "")
dns_servers = params.get("dns_servers", [])
delay = params.get("delay", 1)
threads = params.get("threads", 1)
range_param = params.get("range", "")
additional_args = params.get("additional_args", "")

if not domain:
    return jsonify({"error": "Domain parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["fierce", "--domain", domain]

# Wordlist
if wordlist:
    command.extend(["--wordlist", wordlist])

# DNS servers
if dns_servers:
    command.extend(["--dns-servers", ",".join(dns_servers)])

# Delay
if delay != 1:
    command.extend(["--delay", str(delay)])

# Threads
if threads != 1:
    command.extend(["--threads", str(threads)])

# Range
if range_param:
    command.extend(["--range", range_param])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Fierce execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing domain
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure domain is valid and authorized for reconnaissance
- **DNS Rate Limiting:** Respect DNS server rate limits
- **Responsible Use:** Emphasize responsible use of DNS reconnaissance capabilities

## Use Cases and Applications

#### DNS Reconnaissance
- **Subdomain Discovery:** Discover subdomains through DNS enumeration
- **DNS Infrastructure Mapping:** Map DNS infrastructure and servers
- **Zone Transfer Testing:** Test for DNS zone transfer vulnerabilities

#### Security Assessment
- **Attack Surface Discovery:** Discover attack surface through DNS
- **Information Gathering:** Gather information about target domains
- **Vulnerability Research:** Research DNS-related vulnerabilities

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- DNS enumeration accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce for DNS reconnaissance with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        wordlist = params.get("wordlist", "")
        dns_servers = params.get("dns_servers", [])
        delay = params.get("delay", 1)
        threads = params.get("threads", 1)
        range_param = params.get("range", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        
        # Base command
        command = ["fierce", "--domain", domain]
        
        # Wordlist
        if wordlist:
            command.extend(["--wordlist", wordlist])
        
        # DNS servers
        if dns_servers:
            command.extend(["--dns-servers", ",".join(dns_servers)])
        
        # Delay
        if delay != 1:
            command.extend(["--delay", str(delay)])
        
        # Threads
        if threads != 1:
            command.extend(["--threads", str(threads)])
        
        # Range
        if range_param:
            command.extend(["--range", range_param])
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing fierce: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for reconnaissance results
        reconnaissance_results = parse_fierce_output(result["output"], domain)
        
        logger.info(f"🔍 Fierce completed in {execution_time:.2f}s | Subdomains: {reconnaissance_results.get('total_subdomains', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "reconnaissance_results": reconnaissance_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in fierce endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
