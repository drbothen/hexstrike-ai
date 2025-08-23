---
title: POST /api/tools/kube-bench
group: api
handler: kube_bench
module: __main__
line_range: [8881, 8915]
discovered_in_chunk: 8
---

# POST /api/tools/kube-bench

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute kube-bench for CIS Kubernetes benchmark checks

## Complete Signature & Definition
```python
@app.route("/api/tools/kube-bench", methods=["POST"])
def kube_bench():
    """Execute kube-bench for CIS Kubernetes benchmark checks"""
```

## Purpose & Behavior
Kubernetes security benchmark endpoint providing:
- **CIS Benchmark Compliance:** Execute kube-bench for CIS Kubernetes benchmark validation
- **Target-specific Testing:** Support for master, node, etcd, and policy checks
- **Version-specific Benchmarks:** Support for specific Kubernetes versions
- **Configurable Output:** Flexible output formats and file generation

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/kube-bench
- **Content-Type:** application/json

### Request Body
```json
{
    "targets": "string",                // Optional: Benchmark targets (master, node, etcd, policies)
    "version": "string",                // Optional: Kubernetes version
    "config_dir": "string",             // Optional: Configuration directory
    "output_format": "string",          // Optional: Output format (default: "json")
    "additional_args": "string"         // Optional: Additional kube-bench arguments
}
```

### Parameters
- **targets:** Benchmark targets to check (optional)
- **version:** Kubernetes version for version-specific benchmarks (optional)
- **config_dir:** Configuration directory path (optional)
- **output_format:** Output format for results (optional, default: "json")
- **additional_args:** Additional kube-bench arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Kube-bench benchmark output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 30.5,             // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "command": "kube-bench --targets master,node --json"
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
1. **Base Command:** Start with "kube-bench"
2. **Target Configuration:** Add targets if specified
3. **Version Configuration:** Add version if specified
4. **Config Directory:** Add config directory if specified
5. **Output Configuration:** Configure output format and file
6. **Additional Arguments:** Append additional arguments

### Command Building Logic
```python
command = "kube-bench"

if targets:
    command += f" --targets {targets}"

if version:
    command += f" --version {version}"

if config_dir:
    command += f" --config-dir {config_dir}"

if output_format:
    command += f" --outputfile /tmp/kube-bench-results.{output_format} --json"

if additional_args:
    command += f" {additional_args}"
```

### Benchmark Targets
- **master:** Master node security checks
- **node:** Worker node security checks
- **etcd:** etcd security configuration checks
- **policies:** Security policy checks

### Output Configuration
- **Default Format:** JSON output for machine readability
- **Output File:** `/tmp/kube-bench-results.{format}`
- **JSON Flag:** Always include --json for structured output

### CIS Kubernetes Benchmark
- **Security Standards:** Based on CIS Kubernetes Benchmark
- **Compliance Checking:** Validate Kubernetes security configurations
- **Best Practices:** Check against security best practices
- **Remediation Guidance:** Provide remediation recommendations

## AuthN/AuthZ
- **Kubernetes Access:** Requires access to Kubernetes cluster
- **RBAC Permissions:** May require specific RBAC permissions for cluster access

## Observability
- **Benchmark Logging:** "☁️ Starting kube-bench CIS benchmark"
- **Completion Logging:** "📊 kube-bench benchmark completed"
- **Error Logging:** "💥 Error in kube-bench endpoint: {error}"

## Use Cases and Applications

#### Kubernetes Security Assessment
- **Compliance Validation:** Validate CIS Kubernetes benchmark compliance
- **Security Configuration:** Check Kubernetes security configurations
- **Best Practice Verification:** Verify security best practices implementation

#### DevSecOps Integration
- **CI/CD Security:** Integrate security checks into Kubernetes deployments
- **Automated Compliance:** Automated compliance checking for Kubernetes clusters
- **Security Monitoring:** Ongoing security monitoring for Kubernetes environments

#### Audit and Compliance
- **Security Audits:** Support Kubernetes security audit requirements
- **Compliance Reporting:** Generate compliance reports for Kubernetes
- **Risk Assessment:** Identify Kubernetes security risks and misconfigurations

## Testing & Validation
- Command construction accuracy testing
- Target specification validation
- Output format functionality verification
- Kubernetes cluster access testing

## Code Reproduction
Complete Flask endpoint implementation for kube-bench CIS Kubernetes benchmark checks with configurable targets, version-specific benchmarks, and structured output generation. Essential for Kubernetes security assessment and compliance validation.
