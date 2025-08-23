---
title: POST /api/tools/prowler
group: api
handler: prowler
module: __main__
line_range: [8620, 8662]
discovered_in_chunk: 8
---

# POST /api/tools/prowler

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Prowler for AWS security assessment

## Complete Signature & Definition
```python
@app.route("/api/tools/prowler", methods=["POST"])
def prowler():
    """Execute Prowler for AWS security assessment"""
```

## Purpose & Behavior
Prowler cloud security assessment endpoint providing:
- **AWS Security Assessment:** Execute Prowler for comprehensive AWS security evaluation
- **Multi-provider Support:** Support for AWS and other cloud providers
- **Configurable Output:** Flexible output formats and directory management
- **Profile-based Authentication:** Support for AWS profiles and regions

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/prowler
- **Content-Type:** application/json

### Request Body
```json
{
    "provider": "string",               // Optional: Cloud provider (default: "aws")
    "profile": "string",                // Optional: AWS profile (default: "default")
    "region": "string",                 // Optional: AWS region
    "checks": "string",                 // Optional: Specific checks to run
    "output_dir": "string",             // Optional: Output directory (default: "/tmp/prowler_output")
    "output_format": "string",          // Optional: Output format (default: "json")
    "additional_args": "string"         // Optional: Additional prowler arguments
}
```

### Parameters
- **provider:** Cloud provider to assess (optional, default: "aws")
- **profile:** AWS profile for authentication (optional, default: "default")
- **region:** AWS region to assess (optional)
- **checks:** Specific security checks to execute (optional)
- **output_dir:** Output directory for reports (optional, default: "/tmp/prowler_output")
- **output_format:** Report output format (optional, default: "json")
- **additional_args:** Additional prowler arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "stdout": "string",                 // Prowler assessment output
    "stderr": "string",                 // Error output if any
    "return_code": 0,                   // Process exit code
    "success": true,                    // Execution success flag
    "timed_out": false,                 // Timeout flag
    "partial_results": false,           // Partial results flag
    "execution_time": 120.5,            // Execution duration in seconds
    "timestamp": "2024-01-01T12:00:00Z", // ISO timestamp
    "output_directory": "/tmp/prowler_output", // Output directory path
    "command": "prowler aws --profile default --output-directory /tmp/prowler_output --output-format json"
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
1. **Base Command:** Start with "prowler" and provider
2. **Profile Configuration:** Add AWS profile if specified
3. **Region Configuration:** Add region if specified
4. **Check Selection:** Add specific checks if specified
5. **Output Configuration:** Configure output directory and format
6. **Additional Arguments:** Append additional arguments

### Command Building Logic
```python
command = f"prowler {provider}"

if profile:
    command += f" --profile {profile}"
    
if region:
    command += f" --region {region}"
    
if checks:
    command += f" --checks {checks}"
    
command += f" --output-directory {output_dir}"
command += f" --output-format {output_format}"

if additional_args:
    command += f" {additional_args}"
```

### Output Directory Management
```python
Path(output_dir).mkdir(parents=True, exist_ok=True)
```

### Default Configuration
- **Default Provider:** "aws"
- **Default Profile:** "default"
- **Default Output Directory:** "/tmp/prowler_output"
- **Default Output Format:** "json"

### Prowler Features
- **Multi-cloud Support:** AWS, Azure, GCP, and other cloud providers
- **Comprehensive Checks:** 200+ security checks across multiple categories
- **Compliance Frameworks:** CIS, NIST, SOC2, and other compliance standards
- **Flexible Output:** JSON, CSV, HTML, and other output formats

### Cloud Provider Support
- **AWS:** Amazon Web Services (primary support)
- **Azure:** Microsoft Azure
- **GCP:** Google Cloud Platform
- **Aliyun:** Alibaba Cloud
- **OCI:** Oracle Cloud Infrastructure

### Output Formats
- **JSON:** Machine-readable structured output (default)
- **CSV:** Comma-separated values for spreadsheet analysis
- **HTML:** Human-readable web reports
- **Text:** Plain text output

## AuthN/AuthZ
- **AWS Authentication:** Uses AWS profiles and credentials
- **Profile-based Access:** Supports multiple AWS profiles
- **Region-specific:** Can target specific AWS regions

## Observability
- **Assessment Logging:** "☁️ Starting Prowler {provider} security assessment"
- **Completion Logging:** "📊 Prowler assessment completed"
- **Error Logging:** "💥 Error in prowler endpoint: {error}"

## Use Cases and Applications

#### Cloud Security Assessment
- **AWS Security Posture:** Comprehensive AWS security evaluation
- **Compliance Checking:** Verify compliance with security frameworks
- **Configuration Review:** Review cloud resource configurations

#### DevSecOps Integration
- **CI/CD Security:** Integrate security checks into deployment pipelines
- **Automated Assessment:** Automated cloud security assessment
- **Continuous Monitoring:** Ongoing cloud security monitoring

#### Audit and Compliance
- **Security Audits:** Support security audit requirements
- **Compliance Reporting:** Generate compliance reports
- **Risk Assessment:** Identify cloud security risks

## Testing & Validation
- Command construction accuracy testing
- Output directory creation verification
- AWS profile and region configuration testing
- Output format functionality validation

## Code Reproduction
Complete Flask endpoint implementation for Prowler cloud security assessment with multi-provider support, configurable output, and comprehensive AWS security evaluation capabilities. Essential for cloud security assessment and compliance workflows.
