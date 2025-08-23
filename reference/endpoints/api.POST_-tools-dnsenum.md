---
title: POST /api/tools/dnsenum
group: api
handler: dnsenum
module: __main__
line_range: [12561, 12597]
discovered_in_chunk: 12
---

# POST /api/tools/dnsenum

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute dnsenum for DNS enumeration

## Complete Signature & Definition
```python
@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum for DNS enumeration with enhanced logging"""
```

## Purpose & Behavior
DNS enumeration endpoint providing:
- **Comprehensive DNS Enumeration:** Complete DNS enumeration and analysis
- **Zone Transfer Testing:** Test for DNS zone transfer vulnerabilities
- **Brute Force Enumeration:** Brute force subdomain enumeration
- **Enhanced Logging:** Detailed logging of enumeration progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/dnsenum
- **Content-Type:** application/json

### Request Body
```json
{
    "domain": "string",               // Required: Domain to enumerate
    "dns_server": "string",           // Optional: DNS server to use
    "output_file": "string",          // Optional: Output file path
    "threads": integer,               // Optional: Number of threads (default: 5)
    "timeout": integer,               // Optional: Timeout in seconds (default: 10)
    "brute_force": boolean,           // Optional: Enable brute force (default: true)
    "zone_transfer": boolean,         // Optional: Attempt zone transfer (default: true)
    "reverse_lookup": boolean,        // Optional: Enable reverse lookup (default: true)
    "additional_args": "string"       // Optional: Additional dnsenum arguments
}
```

### Parameters
- **domain:** Domain to enumerate (required)
- **dns_server:** DNS server to use (optional) - "8.8.8.8"
- **output_file:** Output file path (optional)
- **threads:** Number of threads (optional, default: 5)
- **timeout:** Timeout in seconds (optional, default: 10)
- **brute_force:** Enable brute force enumeration flag (optional, default: true)
- **zone_transfer:** Attempt zone transfer flag (optional, default: true)
- **reverse_lookup:** Enable reverse lookup flag (optional, default: true)
- **additional_args:** Additional dnsenum arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "dnsenum --threads 5 --timeout 10 example.com",
    "enumeration_results": {
        "domain": "example.com",
        "name_servers": [
            "ns1.example.com",
            "ns2.example.com"
        ],
        "mail_servers": [
            {
                "server": "mail.example.com",
                "priority": 10,
                "ip": "93.184.216.35"
            }
        ],
        "subdomains": [
            {
                "subdomain": "www.example.com",
                "ip": "93.184.216.34",
                "type": "A"
            }
        ],
        "zone_transfer": {
            "attempted": true,
            "successful": false,
            "error": "Transfer failed"
        },
        "total_records": 15,
        "enumeration_time": 45.2
    },
    "raw_output": "dnsenum VERSION:1.2.6\n-----   example.com   -----\n",
    "execution_time": 45.2,
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
dns_server = params.get("dns_server", "")
output_file = params.get("output_file", "")
threads = params.get("threads", 5)
timeout = params.get("timeout", 10)
brute_force = params.get("brute_force", True)
zone_transfer = params.get("zone_transfer", True)
reverse_lookup = params.get("reverse_lookup", True)
additional_args = params.get("additional_args", "")

if not domain:
    return jsonify({"error": "Domain parameter is required"}), 400
```

### Command Construction
```python
# Base command
command = ["dnsenum"]

# Threads
command.extend(["--threads", str(threads)])

# Timeout
command.extend(["--timeout", str(timeout)])

# DNS server
if dns_server:
    command.extend(["--dnsserver", dns_server])

# Output file
if output_file:
    command.extend(["-o", output_file])

# Brute force
if not brute_force:
    command.append("--noreverse")

# Zone transfer
if not zone_transfer:
    command.append("--nocolor")

# Reverse lookup
if not reverse_lookup:
    command.append("--noreverse")

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Domain
command.append(domain)

# Convert to string
command_str = " ".join(command)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Dnsenum execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing domain
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Target Validation:** Ensure domain is valid and authorized for enumeration
- **DNS Rate Limiting:** Respect DNS server rate limits
- **Responsible Use:** Emphasize responsible use of DNS enumeration capabilities

## Use Cases and Applications

#### DNS Security Assessment
- **Comprehensive DNS Analysis:** Complete DNS infrastructure analysis
- **Zone Transfer Testing:** Test for DNS zone transfer vulnerabilities
- **DNS Configuration Review:** Review DNS configuration and security

#### Information Gathering
- **Subdomain Discovery:** Discover subdomains through DNS enumeration
- **Mail Server Discovery:** Discover mail servers and infrastructure
- **Name Server Analysis:** Analyze name server configuration

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- DNS enumeration accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum for DNS enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        output_file = params.get("output_file", "")
        threads = params.get("threads", 5)
        timeout = params.get("timeout", 10)
        brute_force = params.get("brute_force", True)
        zone_transfer = params.get("zone_transfer", True)
        reverse_lookup = params.get("reverse_lookup", True)
        additional_args = params.get("additional_args", "")
        
        if not domain:
            return jsonify({"error": "Domain parameter is required"}), 400
        
        # Base command
        command = ["dnsenum"]
        
        # Threads
        command.extend(["--threads", str(threads)])
        
        # Timeout
        command.extend(["--timeout", str(timeout)])
        
        # DNS server
        if dns_server:
            command.extend(["--dnsserver", dns_server])
        
        # Output file
        if output_file:
            command.extend(["-o", output_file])
        
        # Brute force
        if not brute_force:
            command.append("--noreverse")
        
        # Zone transfer
        if not zone_transfer:
            command.append("--nocolor")
        
        # Reverse lookup
        if not reverse_lookup:
            command.append("--noreverse")
        
        # Additional arguments
        if additional_args:
            command.extend(additional_args.split())
        
        # Domain
        command.append(domain)
        
        # Convert to string
        command_str = " ".join(command)
        
        logger.info(f"🔍 Executing dnsenum: {command_str}")
        
        start_time = time.time()
        result = execute_command_with_recovery(command_str)
        execution_time = time.time() - start_time
        
        # Parse output for enumeration results
        enumeration_results = parse_dnsenum_output(result["output"], domain)
        
        logger.info(f"🔍 Dnsenum completed in {execution_time:.2f}s | Records: {enumeration_results.get('total_records', 0)}")
        
        return jsonify({
            "success": True,
            "command": command_str,
            "enumeration_results": enumeration_results,
            "raw_output": result["output"],
            "execution_time": execution_time,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in dnsenum endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
