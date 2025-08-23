---
title: POST /api/tools/trivy
group: api
handler: trivy
module: __main__
line_range: [8664, 8700]
discovered_in_chunk: 8
---

# POST /api/tools/trivy

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Trivy for container/filesystem vulnerability scanning

## Complete Signature & Definition
```python
@app.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Execute Trivy for container/filesystem vulnerability scanning"""
```

## Purpose & Behavior
Trivy execution endpoint providing:
- **Container Scanning:** Scan container images for vulnerabilities
- **Filesystem Scanning:** Scan filesystems for security issues
- **Dependency Analysis:** Analyze dependencies for known vulnerabilities
- **Enhanced Logging:** Detailed logging of Trivy operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/trivy
- **Content-Type:** application/json

### Request Body
```json
{
    "target": {
        "type": "string",             // Required: Scan type (image, fs, repo)
        "target_path": "string",      // Required: Target path or image name
        "registry_auth": "object"     // Optional: Registry authentication
    },
    "scan_options": {
        "severity": ["string"],       // Optional: Severity levels to report
        "vuln_type": ["string"],      // Optional: Vulnerability types
        "security_checks": ["string"], // Optional: Security checks to perform
        "skip_update": boolean,       // Optional: Skip database update
        "offline_scan": boolean,      // Optional: Offline scanning mode
        "ignore_unfixed": boolean     // Optional: Ignore unfixed vulnerabilities
    },
    "output_options": {
        "format": "string",           // Optional: Output format (default: json)
        "template": "string",         // Optional: Output template
        "output_file": "string",      // Optional: Output file path
        "exit_code": integer          // Optional: Exit code for vulnerabilities
    }
}
```

### Parameters
- **target:** Target information (required)
- **scan_options:** Scanning configuration options (optional)
- **output_options:** Output formatting options (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "scan_info": {
        "target_type": "image",
        "target_path": "nginx:latest",
        "scan_duration": 45.7,
        "vulnerabilities_found": 25,
        "database_version": "2024-01-01"
    },
    "scan_results": {
        "schema_version": 2,
        "artifact_name": "nginx:latest",
        "artifact_type": "container_image",
        "metadata": {
            "os": {
                "family": "debian",
                "name": "11.8"
            },
            "image_id": "sha256:abc123...",
            "diff_ids": ["sha256:def456..."],
            "repo_tags": ["nginx:latest"]
        },
        "results": [
            {
                "target": "nginx:latest (debian 11.8)",
                "class": "os-pkgs",
                "type": "debian",
                "vulnerabilities": [
                    {
                        "vulnerability_id": "CVE-2023-1234",
                        "pkg_name": "libssl1.1",
                        "installed_version": "1.1.1n-0+deb11u4",
                        "fixed_version": "1.1.1n-0+deb11u5",
                        "severity": "HIGH",
                        "title": "OpenSSL vulnerability",
                        "description": "Buffer overflow in OpenSSL",
                        "cvss": {
                            "nvd": {
                                "v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "v3_score": 9.8
                            }
                        }
                    }
                ]
            }
        ]
    },
    "summary": {
        "by_severity": {
            "CRITICAL": 2,
            "HIGH": 8,
            "MEDIUM": 12,
            "LOW": 3,
            "UNKNOWN": 0
        },
        "total_vulnerabilities": 25,
        "fixed_vulnerabilities": 18,
        "unfixed_vulnerabilities": 7
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Invalid Target (400 Bad Request)
```json
{
    "error": "Invalid target type or path"
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
target = params.get("target", {})
scan_options = params.get("scan_options", {})
output_options = params.get("output_options", {})

target_type = target.get("type", "")
target_path = target.get("target_path", "")

if not target_type or not target_path:
    return jsonify({"error": "Target type and path are required"}), 400

valid_types = ["image", "fs", "repo", "config"]
if target_type not in valid_types:
    return jsonify({"error": f"Invalid target type. Must be one of: {', '.join(valid_types)}"}), 400
```

### Trivy Execution Logic
```python
# Build Trivy command
cmd = ["trivy", target_type, target_path, "--format", "json"]

# Add scan options
if scan_options.get("severity"):
    cmd.extend(["--severity", ",".join(scan_options["severity"])])

if scan_options.get("vuln_type"):
    cmd.extend(["--vuln-type", ",".join(scan_options["vuln_type"])])

if scan_options.get("skip_update"):
    cmd.append("--skip-update")

# Execute Trivy
result = execute_command_with_recovery(cmd)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Container scanning access required

## Error Handling
- **Missing Parameters:** 400 error for missing target information
- **Invalid Target Type:** 400 error for invalid scan types
- **Execution Errors:** Handle Trivy execution failures
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Registry Access:** Secure handling of registry authentication
- **Resource Limits:** Implement resource limits for scanning operations
- **Data Security:** Secure handling of scan results and vulnerability data

## Use Cases and Applications

#### Container Security
- **Image Scanning:** Scan container images for vulnerabilities
- **CI/CD Integration:** Integrate vulnerability scanning into CI/CD pipelines
- **Compliance Checking:** Check containers for compliance requirements

#### Infrastructure Security
- **Filesystem Scanning:** Scan filesystems for security issues
- **Dependency Analysis:** Analyze application dependencies
- **Security Auditing:** Audit infrastructure for security vulnerabilities

## Testing & Validation
- Parameter validation accuracy testing
- Trivy execution verification testing
- Vulnerability detection accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Execute Trivy for container/filesystem vulnerability scanning"""
    try:
        params = request.json
        target = params.get("target", {})
        scan_options = params.get("scan_options", {})
        output_options = params.get("output_options", {})
        
        target_type = target.get("type", "")
        target_path = target.get("target_path", "")
        
        if not target_type or not target_path:
            return jsonify({"error": "Target type and path are required"}), 400
        
        valid_types = ["image", "fs", "repo", "config"]
        if target_type not in valid_types:
            return jsonify({"error": f"Invalid target type. Must be one of: {', '.join(valid_types)}"}), 400
        
        logger.info(f"🔍 Starting Trivy scan | Type: {target_type} | Target: {target_path}")
        
        start_time = time.time()
        
        # Build Trivy command
        cmd = ["trivy", target_type, target_path, "--format", "json"]
        
        # Add scan options
        if scan_options.get("severity"):
            cmd.extend(["--severity", ",".join(scan_options["severity"])])
        
        if scan_options.get("vuln_type"):
            cmd.extend(["--vuln-type", ",".join(scan_options["vuln_type"])])
        
        if scan_options.get("security_checks"):
            cmd.extend(["--security-checks", ",".join(scan_options["security_checks"])])
        
        if scan_options.get("skip_update"):
            cmd.append("--skip-update")
        
        if scan_options.get("offline_scan"):
            cmd.append("--offline-scan")
        
        if scan_options.get("ignore_unfixed"):
            cmd.append("--ignore-unfixed")
        
        # Execute Trivy
        result = execute_command_with_recovery(cmd)
        
        scan_duration = time.time() - start_time
        
        # Parse Trivy output
        scan_results = {}
        if result.stdout:
            try:
                scan_results = json.loads(result.stdout)
            except json.JSONDecodeError:
                scan_results = {"raw_output": result.stdout}
        
        # Calculate summary statistics
        total_vulns = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        if "results" in scan_results:
            for result_item in scan_results["results"]:
                if "vulnerabilities" in result_item:
                    for vuln in result_item["vulnerabilities"]:
                        total_vulns += 1
                        severity = vuln.get("severity", "UNKNOWN")
                        if severity in severity_counts:
                            severity_counts[severity] += 1
        
        scan_info = {
            "target_type": target_type,
            "target_path": target_path,
            "scan_duration": scan_duration,
            "vulnerabilities_found": total_vulns,
            "database_version": scan_results.get("metadata", {}).get("next_update", "unknown")
        }
        
        summary = {
            "by_severity": severity_counts,
            "total_vulnerabilities": total_vulns,
            "fixed_vulnerabilities": 0,  # Would need to parse fixed vs unfixed
            "unfixed_vulnerabilities": total_vulns
        }
        
        logger.info(f"🔍 Trivy scan completed in {scan_duration:.2f}s | Vulnerabilities: {total_vulns}")
        
        return jsonify({
            "success": True,
            "scan_info": scan_info,
            "scan_results": scan_results,
            "summary": summary,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error executing Trivy: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
