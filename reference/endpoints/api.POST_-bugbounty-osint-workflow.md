---
title: POST /api/bugbounty/osint-workflow
group: api
handler: osint_workflow
module: __main__
line_range: [8309, 8334]
discovered_in_chunk: 8
---

# POST /api/bugbounty/osint-workflow

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute OSINT workflow for bug bounty intelligence gathering

## Complete Signature & Definition
```python
@app.route("/api/bugbounty/osint-workflow", methods=["POST"])
def osint_workflow():
    """Execute OSINT workflow for bug bounty intelligence gathering with enhanced logging"""
```

## Purpose & Behavior
OSINT workflow endpoint providing:
- **Intelligence Gathering:** Execute comprehensive OSINT intelligence gathering
- **Multi-Source Collection:** Collect intelligence from multiple OSINT sources
- **Data Correlation:** Correlate and analyze collected intelligence data
- **Enhanced Logging:** Detailed logging of OSINT operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/bugbounty/osint-workflow
- **Content-Type:** application/json

### Request Body
```json
{
    "target_info": {
        "organization": "string",     // Required: Target organization
        "domains": ["string"],        // Optional: Known domains
        "keywords": ["string"],       // Optional: Search keywords
        "employees": ["string"],      // Optional: Known employees
        "locations": ["string"]       // Optional: Physical locations
    },
    "osint_sources": {
        "search_engines": boolean,    // Optional: Use search engines (default: true)
        "social_media": boolean,      // Optional: Use social media (default: true)
        "public_records": boolean,    // Optional: Use public records (default: true)
        "code_repositories": boolean, // Optional: Use code repos (default: true)
        "certificate_transparency": boolean, // Optional: Use CT logs (default: true)
        "dns_records": boolean,       // Optional: Use DNS records (default: true)
        "whois_data": boolean,        // Optional: Use WHOIS data (default: true)
        "breach_databases": boolean   // Optional: Use breach databases (default: false)
    },
    "collection_options": {
        "depth_level": "string",      // Optional: Collection depth (default: standard)
        "time_range": "string",       // Optional: Time range for data
        "language_filter": ["string"], // Optional: Language filters
        "geographic_filter": ["string"], // Optional: Geographic filters
        "data_types": ["string"],     // Optional: Specific data types
        "stealth_mode": boolean       // Optional: Stealth collection (default: true)
    }
}
```

### Parameters
- **target_info:** Target information (required)
  - **organization:** Target organization (required)
  - **domains:** Known domains (optional)
  - **keywords:** Search keywords (optional)
  - **employees:** Known employees (optional)
  - **locations:** Physical locations (optional)
- **osint_sources:** OSINT source configuration (optional)
- **collection_options:** Collection configuration (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "osint_info": {
        "target_organization": "Example Corp",
        "sources_used": ["search_engines", "social_media", "ct_logs", "dns_records"],
        "total_execution_time": 2145.7,
        "depth_level": "standard",
        "stealth_mode": true
    },
    "intelligence_data": {
        "organizational_info": {
            "company_name": "Example Corp",
            "industry": "Technology",
            "size": "1000-5000 employees",
            "headquarters": "San Francisco, CA",
            "subsidiaries": ["Example Labs", "Example Security"],
            "key_personnel": [
                {
                    "name": "John Smith",
                    "title": "CTO",
                    "linkedin": "https://linkedin.com/in/johnsmith",
                    "email_pattern": "john.smith@example.com"
                }
            ]
        },
        "digital_footprint": {
            "domains": [
                {
                    "domain": "example.com",
                    "registrar": "GoDaddy",
                    "creation_date": "2010-01-15",
                    "expiration_date": "2025-01-15",
                    "nameservers": ["ns1.example.com", "ns2.example.com"]
                }
            ],
            "subdomains": ["www.example.com", "api.example.com", "staging.example.com"],
            "ip_ranges": ["192.168.1.0/24", "10.0.0.0/16"],
            "certificates": [
                {
                    "subject": "*.example.com",
                    "issuer": "Let's Encrypt",
                    "valid_from": "2024-01-01",
                    "valid_to": "2024-04-01"
                }
            ]
        },
        "social_media_presence": {
            "platforms": ["Twitter", "LinkedIn", "GitHub"],
            "accounts": [
                {
                    "platform": "Twitter",
                    "handle": "@examplecorp",
                    "followers": 15000,
                    "verified": true
                }
            ],
            "employee_profiles": 250,
            "recent_posts": [
                {
                    "platform": "LinkedIn",
                    "content": "Hiring security engineers",
                    "date": "2024-01-01",
                    "engagement": 45
                }
            ]
        },
        "technical_intelligence": {
            "technologies": ["AWS", "Docker", "Kubernetes", "React"],
            "code_repositories": [
                {
                    "platform": "GitHub",
                    "repository": "example/public-api",
                    "language": "Python",
                    "last_updated": "2024-01-01"
                }
            ],
            "job_postings": [
                {
                    "title": "Senior Security Engineer",
                    "platform": "LinkedIn",
                    "technologies": ["Python", "AWS", "Security"],
                    "posted_date": "2024-01-01"
                }
            ]
        }
    },
    "security_insights": {
        "potential_attack_vectors": [
            {
                "vector": "Social Engineering",
                "confidence": 0.8,
                "description": "Multiple employee profiles with detailed information"
            },
            {
                "vector": "Subdomain Takeover",
                "confidence": 0.6,
                "description": "Unused subdomains pointing to cloud services"
            }
        ],
        "exposed_information": [
            {
                "type": "Email Patterns",
                "data": "firstname.lastname@example.com",
                "risk": "Medium"
            },
            {
                "type": "Technology Stack",
                "data": "AWS, Docker, Kubernetes",
                "risk": "Low"
            }
        ],
        "breach_data": {
            "found_in_breaches": false,
            "employee_emails_found": 0,
            "password_patterns": []
        }
    },
    "recommendations": [
        {
            "category": "Information Security",
            "priority": "Medium",
            "action": "Review employee social media guidelines",
            "rationale": "Employees sharing detailed technical information"
        },
        {
            "category": "Infrastructure",
            "priority": "High",
            "action": "Audit unused subdomains",
            "rationale": "Potential subdomain takeover opportunities"
        }
    ],
    "osint_metadata": {
        "collection_methodology": "OSINT_Framework_v2",
        "sources_queried": 25,
        "data_points_collected": 1250,
        "collection_phases": [
            {
                "phase": "domain_intelligence",
                "duration": 450.2,
                "data_points": 156
            },
            {
                "phase": "social_media_collection",
                "duration": 680.5,
                "data_points": 342
            }
        ]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Organization (400 Bad Request)
```json
{
    "error": "Target organization is required"
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
target_info = params.get("target_info", {})
osint_sources = params.get("osint_sources", {})
collection_options = params.get("collection_options", {})

organization = target_info.get("organization", "")
if not organization:
    return jsonify({"error": "Target organization is required"}), 400
```

### OSINT Collection Logic
```python
# Use BugBountyWorkflowManager for OSINT collection
osint_request = {
    "target": target_info,
    "sources": osint_sources,
    "options": collection_options
}

# Execute OSINT collection workflow
osint_result = bugbounty_manager.execute_osint_workflow(osint_request)

# Analyze collected intelligence
intelligence_analysis = bugbounty_manager.analyze_osint_data(osint_result)

# Generate security insights
security_insights = bugbounty_manager.generate_security_insights(intelligence_analysis)

# Generate recommendations
recommendations = bugbounty_manager.generate_osint_recommendations(security_insights)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** OSINT collection access required

## Error Handling
- **Missing Parameters:** 400 error for missing organization
- **Collection Errors:** Handle errors during OSINT collection
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Legal Compliance:** Ensure compliance with OSINT collection laws
- **Data Privacy:** Respect privacy and data protection regulations
- **Ethical Collection:** Implement ethical OSINT collection practices
- **Source Reliability:** Validate reliability of OSINT sources

## Use Cases and Applications

#### Bug Bounty Programs
- **Target Intelligence:** Gather intelligence about bug bounty targets
- **Attack Surface Discovery:** Discover attack surface through OSINT
- **Social Engineering Prep:** Prepare for social engineering assessments

#### Security Research
- **Threat Intelligence:** Collect threat intelligence about organizations
- **Risk Assessment:** Assess organizational security risks
- **Vulnerability Research:** Research potential vulnerabilities through OSINT

## Testing & Validation
- Parameter validation accuracy testing
- OSINT collection verification testing
- Data correlation accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/bugbounty/osint-workflow", methods=["POST"])
def osint_workflow():
    """Execute OSINT workflow for bug bounty intelligence gathering with enhanced logging"""
    try:
        params = request.json
        target_info = params.get("target_info", {})
        osint_sources = params.get("osint_sources", {})
        collection_options = params.get("collection_options", {})
        
        organization = target_info.get("organization", "")
        if not organization:
            return jsonify({"error": "Target organization is required"}), 400
        
        logger.info(f"🔍 Starting OSINT workflow for organization: {organization}")
        
        start_time = time.time()
        
        # Use BugBountyWorkflowManager for OSINT collection
        osint_request = {
            "target": target_info,
            "sources": osint_sources,
            "options": collection_options
        }
        
        # Execute OSINT collection workflow
        osint_result = bugbounty_manager.execute_osint_workflow(osint_request)
        
        # Analyze collected intelligence
        intelligence_analysis = bugbounty_manager.analyze_osint_data(osint_result)
        
        # Generate security insights
        security_insights = bugbounty_manager.generate_security_insights(intelligence_analysis)
        
        # Generate recommendations
        recommendations = bugbounty_manager.generate_osint_recommendations(security_insights)
        
        execution_time = time.time() - start_time
        
        osint_info = {
            "target_organization": organization,
            "sources_used": osint_result.get("sources_used", []),
            "total_execution_time": execution_time,
            "depth_level": collection_options.get("depth_level", "standard"),
            "stealth_mode": collection_options.get("stealth_mode", True)
        }
        
        osint_metadata = {
            "collection_methodology": "OSINT_Framework_v2",
            "sources_queried": osint_result.get("sources_queried", 0),
            "data_points_collected": osint_result.get("data_points_collected", 0),
            "collection_phases": osint_result.get("collection_phases", [])
        }
        
        logger.info(f"🔍 OSINT workflow completed in {execution_time:.2f}s | Data points: {osint_result.get('data_points_collected', 0)}")
        
        return jsonify({
            "success": True,
            "osint_info": osint_info,
            "intelligence_data": intelligence_analysis,
            "security_insights": security_insights,
            "recommendations": recommendations,
            "osint_metadata": osint_metadata,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error in OSINT workflow: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
