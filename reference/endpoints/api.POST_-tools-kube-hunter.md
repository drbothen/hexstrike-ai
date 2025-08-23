---
title: POST /api/tools/kube-hunter
group: api
handler: kube_hunter
module: __main__
line_range: [8837, 8880]
discovered_in_chunk: 9
---

# POST /api/tools/kube-hunter

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute kube-hunter for Kubernetes penetration testing

## Complete Signature & Definition
```python
@app.route("/api/tools/kube-hunter", methods=["POST"])
def kube_hunter():
    """Execute kube-hunter for Kubernetes penetration testing"""
```

## Purpose & Behavior
Kube-hunter Kubernetes security testing endpoint providing:
- **Multi-Target Support:** Remote hosts, CIDR ranges, network interfaces, or pod scanning
- **Active/Passive Modes:** Choose between passive reconnaissance or active testing
- **Flexible Reporting:** JSON and other report formats
- **Comprehensive Coverage:** Kubernetes cluster security assessment

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/kube-hunter
- **Content-Type:** application/json

### Request Body
```json
{
    "target": "string",                 // Optional: Specific target host
    "remote": "string",                 // Optional: Remote host to scan
    "cidr": "string",                   // Optional: CIDR range to scan
    "interface": "string",              // Optional: Network interface to scan
    "active": boolean,                  // Optional: Enable active testing - default: false
    "report": "string",                 // Optional: Report format - default: "json"
    "additional_args": "string"         // Optional: Additional kube-hunter arguments
}
```

### Parameters
- **target:** Specific target host to scan (optional)
- **remote:** Remote host for scanning (optional)
- **cidr:** CIDR range for network scanning (optional)
- **interface:** Network interface for scanning (optional)
- **active:** Enable active testing mode (optional, default: false)
- **report:** Output report format (optional, default: "json")
- **additional_args:** Additional command-line arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "output": "kube-hunter scan results with Kubernetes vulnerabilities...",
    "command": "kube-hunter --remote target.example.com --report json",
    "execution_time": 30.5,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/tools/kube-hunter", methods=["POST"])
def kube_hunter():
    """Execute kube-hunter for Kubernetes penetration testing"""
    try:
        params = request.json
        target = params.get("target", "")
        remote = params.get("remote", "")
        cidr = params.get("cidr", "")
        interface = params.get("interface", "")
        active = params.get("active", False)
        report = params.get("report", "json")
        additional_args = params.get("additional_args", "")
        
        command = "kube-hunter"
        
        if target:
            command += f" --remote {target}"
        elif remote:
            command += f" --remote {remote}"
        elif cidr:
            command += f" --cidr {cidr}"
        elif interface:
            command += f" --interface {interface}"
        else:
            # Default to pod scanning
            command += " --pod"
        
        if active:
            command += " --active"
        
        if report:
            command += f" --report {report}"
        
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"☁️  Starting kube-hunter Kubernetes scan")
        result = execute_command(command)
        logger.info(f"📊 kube-hunter scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in kube-hunter endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
