---
title: POST /api/tools/metasploit
group: api
handler: metasploit
module: __main__
line_range: [9180, 9222]
discovered_in_chunk: 9
---

# POST /api/tools/metasploit

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute metasploit module with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with enhanced logging"""
```

## Purpose & Behavior
Metasploit exploitation framework endpoint providing:
- **Module Execution:** Execute Metasploit modules for exploitation and testing
- **Resource Script Generation:** Automatic MSF resource script creation
- **Option Configuration:** Configurable module options and parameters
- **Automated Exploitation:** Streamlined exploitation workflow execution

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/metasploit
- **Content-Type:** application/json

### Request Body
```json
{
    "module": "string",                 // Required: Metasploit module to execute
    "options": {                        // Optional: Module options and parameters
        "RHOSTS": "192.168.1.1",
        "RPORT": "80",
        "LHOST": "192.168.1.100",
        "LPORT": "4444"
    }
}
```

### Parameters
- **module:** Metasploit module path to execute (required)
- **options:** Dictionary of module options and their values (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Metasploit module output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 45.2,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "msfconsole -q -r /tmp/mcp_msf_resource.rc"
}
```

### Error Responses

#### Missing Module (400 Bad Request)
```json
{
    "error": "Module parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Resource Script Generation Process
1. **Module Selection:** Use specified Metasploit module
2. **Option Configuration:** Set module options from parameters
3. **Script Creation:** Generate MSF resource script
4. **Execution:** Execute via msfconsole with resource script
5. **Cleanup:** Remove temporary resource script file

### Resource Script Format
```ruby
use {module}
set {option} {value}
set {option} {value}
exploit
```

### Resource Script Creation
```python
resource_content = f"use {module}\n"
for key, value in options.items():
    resource_content += f"set {key} {value}\n"
resource_content += "exploit\n"

resource_file = "/tmp/mcp_msf_resource.rc"
with open(resource_file, "w") as f:
    f.write(resource_content)
```

### Command Execution
```python
command = f"msfconsole -q -r {resource_file}"
```

### File Cleanup
```python
try:
    os.remove(resource_file)
except Exception as e:
    logger.warning(f"Error removing temporary resource file: {str(e)}")
```

### Parameter Validation
- **Module Validation:** Ensure module parameter is provided
- **Warning Logging:** Log warning for missing module parameter
- **Error Response:** Return 400 error for missing module

### Common Metasploit Modules
- **Exploits:** exploit/windows/smb/ms17_010_eternalblue
- **Auxiliary:** auxiliary/scanner/portscan/tcp
- **Post:** post/windows/gather/hashdump
- **Payloads:** payload/windows/meterpreter/reverse_tcp
- **Encoders:** encoder/x86/shikata_ga_nai

### Common Module Options
- **RHOSTS:** Remote host(s) to target
- **RPORT:** Remote port to target
- **LHOST:** Local host for reverse connections
- **LPORT:** Local port for reverse connections
- **PAYLOAD:** Payload to use with exploit
- **TARGET:** Specific target for exploit

## AuthN/AuthZ
- **System Access:** Requires system access for Metasploit execution
- **Exploitation Framework:** Access to Metasploit Framework required

## Observability
- **Module Logging:** "🚀 Starting Metasploit module: {module}"
- **Completion Logging:** "📊 Metasploit module completed: {module}"
- **Warning Logging:** "🚀 Metasploit called without module parameter"
- **Error Logging:** "💥 Error in metasploit endpoint: {error}"

## Security Considerations
- **Exploitation Tool:** Metasploit is a penetration testing and exploitation framework
- **Authorized Use:** Should only be used in authorized testing environments
- **Impact Assessment:** Consider potential impact of exploitation modules

## Use Cases and Applications

#### Penetration Testing
- **Exploitation:** Execute exploits against vulnerable systems
- **Post-Exploitation:** Perform post-exploitation activities
- **Payload Delivery:** Deliver payloads to compromised systems

#### Security Assessment
- **Vulnerability Validation:** Validate discovered vulnerabilities
- **Impact Assessment:** Assess potential impact of security vulnerabilities
- **Security Testing:** Test security controls and defenses

#### Red Team Operations
- **Adversary Simulation:** Simulate adversary tactics and techniques
- **Attack Simulation:** Simulate real-world attack scenarios
- **Security Validation:** Validate security detection and response capabilities

## Testing & Validation
- Module parameter validation testing
- Resource script generation verification
- Option configuration accuracy testing
- File cleanup functionality validation

## Code Reproduction
Complete Flask endpoint implementation for Metasploit module execution with automatic resource script generation, configurable options, and comprehensive logging. Essential for penetration testing and security assessment workflows.
