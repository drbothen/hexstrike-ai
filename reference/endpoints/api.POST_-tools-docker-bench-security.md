---
title: POST /api/tools/docker-bench-security
group: api
handler: docker_bench_security
module: __main__
line_range: [8917, 8948]
discovered_in_chunk: 9
---

# POST /api/tools/docker-bench-security

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Docker Bench for Security for Docker security assessment

## Complete Signature & Definition
```python
@app.route("/api/tools/docker-bench-security", methods=["POST"])
def docker_bench_security():
    """Execute Docker Bench for Security for Docker security assessment"""
```

## Purpose & Behavior
Docker security assessment endpoint providing:
- **Docker Security Assessment:** Execute Docker Bench for Security for comprehensive Docker security evaluation
- **CIS Docker Benchmark:** Validate Docker configurations against CIS Docker Benchmark
- **Configurable Checks:** Support for specific checks and exclusions
- **Output File Generation:** Generate structured output files for analysis

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/docker-bench-security
- **Content-Type:** application/json

### Request Body
```json
{
    "checks": "string",                 // Optional: Specific checks to run
    "exclude": "string",                // Optional: Checks to exclude
    "output_file": "string",            // Optional: Output file path (default: "/tmp/docker-bench-results.json")
    "additional_args": "string"         // Optional: Additional docker-bench-security arguments
}
```

### Parameters
- **checks:** Specific security checks to execute (optional)
- **exclude:** Security checks to exclude from execution (optional)
- **output_file:** Output file path for results (optional, default: "/tmp/docker-bench-results.json")
- **additional_args:** Additional docker-bench-security arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Docker Bench Security output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 60.5,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "output_file": "/tmp/docker-bench-results.json", // Output file path
    "command": "docker-bench-security -l /tmp/docker-bench-results.json"
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Command Construction Process
1. **Base Command:** Start with "docker-bench-security"
2. **Check Selection:** Add specific checks if specified
3. **Exclusion Configuration:** Add exclusions if specified
4. **Output Configuration:** Configure output file
5. **Additional Arguments:** Append additional arguments

### Command Building Logic
```python
command = "docker-bench-security"

if checks:
    command += f" -c {checks}"

if exclude:
    command += f" -e {exclude}"

if output_file:
    command += f" -l {output_file}"

if additional_args:
    command += f" {additional_args}"
```

### Default Configuration
- **Default Output File:** "/tmp/docker-bench-results.json"
- **Output Format:** JSON for structured analysis
- **Log File:** -l flag for output file generation

### Docker Bench for Security Features
- **CIS Docker Benchmark:** Based on CIS Docker Benchmark standards
- **Comprehensive Checks:** 100+ security checks across multiple categories
- **Host Configuration:** Docker host security configuration checks
- **Container Security:** Running container security validation
- **Image Security:** Docker image security assessment

### Check Categories
- **Host Configuration:** Docker daemon and host security
- **Docker Daemon Configuration:** Daemon security settings
- **Docker Daemon Configuration Files:** Configuration file permissions
- **Container Images and Build Files:** Image security and build practices
- **Container Runtime:** Runtime security configurations
- **Docker Security Operations:** Operational security practices

## AuthN/AuthZ
- **Docker Access:** Requires access to Docker daemon
- **System Permissions:** May require elevated permissions for comprehensive checks

## Observability
- **Assessment Logging:** "🐳 Starting Docker Bench Security assessment"
- **Completion Logging:** "📊 Docker Bench Security completed"
- **Error Logging:** "💥 Error in docker-bench-security endpoint: {error}"

## Use Cases and Applications

#### Docker Security Assessment
- **Security Posture:** Comprehensive Docker security posture evaluation
- **Compliance Validation:** Validate Docker configurations against CIS benchmarks
- **Configuration Review:** Review Docker security configurations

#### DevSecOps Integration
- **CI/CD Security:** Integrate Docker security checks into deployment pipelines
- **Automated Assessment:** Automated Docker security assessment
- **Container Security:** Ongoing container security monitoring

#### Audit and Compliance
- **Security Audits:** Support Docker security audit requirements
- **Compliance Reporting:** Generate Docker compliance reports
- **Risk Assessment:** Identify Docker security risks and misconfigurations

## Testing & Validation
- Command construction accuracy testing
- Check selection and exclusion validation
- Output file generation verification
- Docker daemon access testing

## Code Reproduction
Complete Flask endpoint implementation for Docker Bench for Security assessment with configurable checks, exclusions, and structured output generation. Essential for Docker security assessment and CIS benchmark compliance validation.
