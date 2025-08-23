---
title: POST /api/visual/summary-report
group: api
handler: generate_summary_report
module: __main__
line_range: [7607, 7632]
discovered_in_chunk: 7
---

# POST /api/visual/summary-report

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Generate visual summary report for security assessments

## Complete Signature & Definition
```python
@app.route("/api/visual/summary-report", methods=["POST"])
def generate_summary_report():
    """Generate visual summary report for security assessments with enhanced logging"""
```

## Purpose & Behavior
Visual summary report generation endpoint providing:
- **Report Generation:** Generate comprehensive visual summary reports
- **Data Aggregation:** Aggregate security assessment data into visual format
- **Customization:** Customize report appearance and content
- **Enhanced Logging:** Detailed logging of report generation operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/visual/summary-report
- **Content-Type:** application/json

### Request Body
```json
{
    "assessment_data": {
        "title": "string",            // Required: Report title
        "scope": "string",            // Required: Assessment scope
        "vulnerabilities": ["object"], // Required: Vulnerability data
        "statistics": "object",       // Required: Assessment statistics
        "recommendations": ["string"], // Optional: Recommendations
        "executive_summary": "string", // Optional: Executive summary
        "methodology": "string",      // Optional: Assessment methodology
        "timeline": "object"          // Optional: Assessment timeline
    },
    "report_options": {
        "template": "string",         // Optional: Report template (default: executive)
        "format": "string",           // Optional: Output format (default: pdf)
        "include_charts": boolean,    // Optional: Include charts (default: true)
        "include_details": boolean,   // Optional: Include detailed findings (default: true)
        "color_scheme": "string",     // Optional: Color scheme (default: professional)
        "page_size": "string"         // Optional: Page size (default: A4)
    },
    "branding": {
        "organization": "string",     // Optional: Organization name
        "logo_url": "string",         // Optional: Logo URL
        "contact_info": "string",     // Optional: Contact information
        "report_id": "string",        // Optional: Report ID
        "classification": "string"    // Optional: Security classification
    }
}
```

### Parameters
- **assessment_data:** Assessment data (required)
  - **title:** Report title (required)
  - **scope:** Assessment scope (required)
  - **vulnerabilities:** Vulnerability data (required)
  - **statistics:** Assessment statistics (required)
  - **recommendations:** Recommendations (optional)
  - **executive_summary:** Executive summary (optional)
  - **methodology:** Assessment methodology (optional)
  - **timeline:** Assessment timeline (optional)
- **report_options:** Report customization options (optional)
- **branding:** Branding information (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "report_info": {
        "title": "Security Assessment Report",
        "scope": "Web Application Security Assessment",
        "template": "executive",
        "format": "pdf",
        "pages": 25,
        "vulnerabilities_count": 15
    },
    "output": {
        "file_path": "/tmp/summary_report_1234567890.pdf",
        "file_size": "2.5MB",
        "download_url": "/api/files/download/summary_report_1234567890.pdf",
        "preview_url": "/api/files/preview/summary_report_1234567890.pdf"
    },
    "generation_details": {
        "template_used": "executive",
        "charts_generated": 8,
        "sections_included": ["executive_summary", "findings", "recommendations"],
        "generation_time": 15.7
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: title, scope, vulnerabilities, statistics"
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
assessment_data = params.get("assessment_data", {})
report_options = params.get("report_options", {})
branding = params.get("branding", {})

# Validate required assessment data fields
required_fields = ["title", "scope", "vulnerabilities", "statistics"]
missing_fields = [field for field in required_fields if not assessment_data.get(field)]
if missing_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
```

### Report Generation Logic
```python
# Use ModernVisualEngine to generate report
report_data = {
    "assessment": assessment_data,
    "options": report_options,
    "branding": branding
}

# Generate report using visual engine
report_result = visual_engine.generate_summary_report(report_data)

# Save report to file
output_format = report_options.get("format", "pdf")
output_file = f"/tmp/summary_report_{int(time.time() * 1000000)}.{output_format}"
report_result.save(output_file)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Visual report generation access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Generation Errors:** Handle errors during report generation
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Data Security:** Secure handling of sensitive assessment data
- **File Security:** Secure handling of generated report files
- **Access Control:** Control access to generated reports
- **Information Classification:** Handle classified information appropriately

## Use Cases and Applications

#### Executive Reporting
- **Executive Summaries:** Generate executive-level security reports
- **Board Presentations:** Create reports for board presentations
- **Stakeholder Communication:** Communicate security posture to stakeholders

#### Client Deliverables
- **Assessment Reports:** Generate professional assessment reports for clients
- **Compliance Reports:** Create compliance and audit reports
- **Security Briefings:** Generate security briefing materials

## Testing & Validation
- Parameter validation accuracy testing
- Report generation functionality testing
- Output format verification testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/visual/summary-report", methods=["POST"])
def generate_summary_report():
    """Generate visual summary report for security assessments with enhanced logging"""
    try:
        params = request.json
        assessment_data = params.get("assessment_data", {})
        report_options = params.get("report_options", {})
        branding = params.get("branding", {})
        
        # Validate required assessment data fields
        required_fields = ["title", "scope", "vulnerabilities", "statistics"]
        missing_fields = [field for field in required_fields if not assessment_data.get(field)]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        logger.info(f"🎨 Generating summary report: {assessment_data['title']}")
        
        start_time = time.time()
        
        # Use ModernVisualEngine to generate report
        report_data = {
            "assessment": assessment_data,
            "options": report_options,
            "branding": branding
        }
        
        # Generate report using visual engine
        report_result = visual_engine.generate_summary_report(report_data)
        
        # Save report to file
        output_format = report_options.get("format", "pdf")
        output_file = f"/tmp/summary_report_{int(time.time() * 1000000)}.{output_format}"
        report_result.save(output_file)
        
        generation_time = time.time() - start_time
        
        # Get file info
        file_size = os.path.getsize(output_file)
        file_size_str = f"{file_size / (1024*1024):.1f}MB"
        
        report_info = {
            "title": assessment_data["title"],
            "scope": assessment_data["scope"],
            "template": report_options.get("template", "executive"),
            "format": output_format,
            "pages": report_result.get_page_count(),
            "vulnerabilities_count": len(assessment_data.get("vulnerabilities", []))
        }
        
        output = {
            "file_path": output_file,
            "file_size": file_size_str,
            "download_url": f"/api/files/download/{os.path.basename(output_file)}",
            "preview_url": f"/api/files/preview/{os.path.basename(output_file)}"
        }
        
        generation_details = {
            "template_used": report_options.get("template", "executive"),
            "charts_generated": report_result.get_chart_count(),
            "sections_included": report_result.get_sections(),
            "generation_time": generation_time
        }
        
        logger.info(f"🎨 Summary report generated in {generation_time:.2f}s | File: {output_file}")
        
        return jsonify({
            "success": True,
            "report_info": report_info,
            "output": output,
            "generation_details": generation_details,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error generating summary report: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
