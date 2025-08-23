---
title: POST /api/tools/graphql_scanner
group: api
handler: graphql_scanner
module: __main__
line_range: [13029, 13134]
discovered_in_chunk: 13
---

# POST /api/tools/graphql_scanner

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced GraphQL security scanning and introspection

## Complete Signature & Definition
```python
@app.route("/api/tools/graphql_scanner", methods=["POST"])
def graphql_scanner():
    """Advanced GraphQL security scanning and introspection"""
```

## Purpose & Behavior
GraphQL security scanning endpoint providing:
- **Introspection Testing:** Test GraphQL introspection capabilities
- **Query Depth Analysis:** Analyze query depth limitations
- **Batch Query Testing:** Test batch query handling and rate limiting
- **Vulnerability Detection:** Comprehensive GraphQL security vulnerability detection

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/graphql_scanner
- **Content-Type:** application/json

### Request Body
```json
{
    "endpoint": "string",               // Required: GraphQL endpoint URL
    "introspection": boolean,           // Optional: Enable introspection testing (default: true)
    "query_depth": 10,                  // Optional: Query depth for testing (default: 10)
    "test_mutations": boolean           // Optional: Test mutations (default: true)
}
```

### Parameters
- **endpoint:** GraphQL endpoint URL for testing (required)
- **introspection:** Enable introspection query testing (optional, default: true)
- **query_depth:** Maximum query depth for depth analysis testing (optional, default: 10)
- **test_mutations:** Enable mutation testing (optional, default: true)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "graphql_scan_results": {
        "endpoint": "string",
        "tests_performed": [
            "introspection_query",
            "query_depth_analysis",
            "batch_query_testing"
        ],
        "vulnerabilities": [
            {
                "type": "introspection_enabled",
                "severity": "MEDIUM",
                "description": "GraphQL introspection is enabled"
            },
            {
                "type": "no_query_depth_limit",
                "severity": "HIGH",
                "description": "No query depth limiting detected (tested depth: 10)"
            },
            {
                "type": "batch_queries_allowed",
                "severity": "MEDIUM",
                "description": "Batch queries are allowed without rate limiting"
            }
        ],
        "recommendations": [
            "Disable introspection in production",
            "Implement query depth limiting",
            "Add rate limiting for batch queries",
            "Implement query complexity analysis",
            "Add authentication for sensitive operations"
        ]
    }
}
```

### Error Responses

#### Missing Endpoint (400 Bad Request)
```json
{
    "error": "GraphQL endpoint parameter is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Test 1: Introspection Query Testing
```python
if introspection:
    introspection_query = '''
    {
        __schema {
            types {
                name
                fields {
                    name
                    type {
                        name
                    }
                }
            }
        }
    }
    '''
    
    clean_query = introspection_query.replace('\n', ' ').replace('  ', ' ').strip()
    command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{clean_query}\"}}' '{endpoint}'"
    result = execute_command(command, use_cache=False)
```

### Test 2: Query Depth Analysis
```python
deep_query = "{ " * query_depth + "field" + " }" * query_depth
command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{deep_query}\"}}' {endpoint}"
depth_result = execute_command(command, use_cache=False)
```

### Test 3: Batch Query Testing
```python
batch_query = '[' + ','.join(['{\"query\":\"{field}\"}' for _ in range(10)]) + ']'
command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{batch_query}' {endpoint}"
batch_result = execute_command(command, use_cache=False)
```

### Vulnerability Detection Logic

#### Introspection Enabled
```python
if "data" in result.get("stdout", ""):
    results["vulnerabilities"].append({
        "type": "introspection_enabled",
        "severity": "MEDIUM",
        "description": "GraphQL introspection is enabled"
    })
```

#### No Query Depth Limit
```python
if "error" not in depth_result.get("stdout", "").lower():
    results["vulnerabilities"].append({
        "type": "no_query_depth_limit",
        "severity": "HIGH",
        "description": f"No query depth limiting detected (tested depth: {query_depth})"
    })
```

#### Batch Queries Allowed
```python
if "data" in batch_result.get("stdout", "") and batch_result.get("success"):
    results["vulnerabilities"].append({
        "type": "batch_queries_allowed",
        "severity": "MEDIUM",
        "description": "Batch queries are allowed without rate limiting"
    })
```

## Key Features

### Comprehensive GraphQL Testing
- **Introspection Analysis:** Test GraphQL schema introspection capabilities
- **Depth Limit Testing:** Analyze query depth limitations and DoS protection
- **Batch Query Analysis:** Test batch query handling and rate limiting

### Vulnerability Detection
- **Security Misconfiguration:** Detect common GraphQL security misconfigurations
- **DoS Vulnerabilities:** Identify potential denial of service vulnerabilities
- **Information Disclosure:** Detect information disclosure through introspection

### Automated Recommendations
- **Security Hardening:** Provide specific security hardening recommendations
- **Best Practices:** Recommend GraphQL security best practices
- **Production Readiness:** Assess production readiness of GraphQL endpoints

## GraphQL Security Tests

### Introspection Testing
- **Schema Discovery:** Test ability to discover GraphQL schema
- **Type Information:** Extract type and field information
- **Security Impact:** Assess information disclosure risk

### Query Depth Analysis
- **DoS Protection:** Test query depth limiting mechanisms
- **Resource Exhaustion:** Assess potential for resource exhaustion attacks
- **Performance Impact:** Analyze performance impact of deep queries

### Batch Query Testing
- **Rate Limiting:** Test rate limiting for batch queries
- **Resource Consumption:** Assess resource consumption of batch operations
- **DoS Potential:** Evaluate denial of service potential

## AuthN/AuthZ
- **Network Access:** Requires network access to GraphQL endpoints
- **GraphQL Security Testing:** Advanced GraphQL security assessment capabilities

## Observability
- **Scan Logging:** "🔍 Starting GraphQL security scan: {endpoint}"
- **Completion Logging:** "📊 GraphQL scan completed | Vulnerabilities found: {count}"
- **Warning Logging:** "🌐 GraphQL Scanner called without endpoint parameter"
- **Error Logging:** "💥 Error in GraphQL scanner: {error}"

## Use Cases and Applications

#### GraphQL Security Assessment
- **Security Auditing:** Comprehensive GraphQL security auditing
- **Vulnerability Assessment:** Identify GraphQL-specific vulnerabilities
- **Configuration Review:** Review GraphQL security configurations

#### Penetration Testing
- **GraphQL Testing:** Specialized GraphQL penetration testing
- **API Security Assessment:** Assess GraphQL API security posture
- **Vulnerability Discovery:** Discover GraphQL security vulnerabilities

#### DevSecOps Integration
- **Automated Security Testing:** Integrate into CI/CD pipelines
- **Security Validation:** Validate GraphQL security configurations
- **Continuous Monitoring:** Monitor GraphQL endpoints for security issues

## Testing & Validation
- Endpoint parameter validation
- Introspection testing functionality verification
- Query depth analysis accuracy testing
- Batch query testing capability validation

## Code Reproduction
Complete Flask endpoint implementation for advanced GraphQL security scanning with introspection testing, query depth analysis, batch query testing, and comprehensive vulnerability detection. Essential for GraphQL security assessment and API security testing workflows.
