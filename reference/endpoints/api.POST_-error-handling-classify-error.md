---
title: POST /api/error-handling/classify-error
group: api
handler: classify_error_endpoint
module: __main__
line_range: [15286, 15316]
discovered_in_chunk: 15
---

# POST /api/error-handling/classify-error

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Classify an error message

## Complete Signature & Definition
```python
@app.route("/api/error-handling/classify-error", methods=["POST"])
def classify_error_endpoint():
    """Classify an error message"""
```

## Purpose & Behavior
Error classification endpoint providing:
- **Error Classification:** Classify error messages into predefined categories
- **Pattern Recognition:** Recognize error patterns and types
- **Recovery Suggestion:** Suggest appropriate recovery strategies
- **Enhanced Logging:** Detailed logging of error classification operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/error-handling/classify-error
- **Content-Type:** application/json

### Request Body
```json
{
    "error_data": {
        "error_message": "string",    // Required: Error message to classify
        "error_code": "string",       // Optional: Error code if available
        "context": "object",          // Optional: Error context information
        "tool_name": "string",        // Optional: Tool that generated the error
        "command": "string",          // Optional: Command that caused the error
        "timestamp": "string"         // Optional: Error timestamp
    },
    "classification_options": {
        "detailed_analysis": boolean, // Optional: Perform detailed analysis (default: true)
        "suggest_recovery": boolean,  // Optional: Suggest recovery strategies (default: true)
        "confidence_threshold": number, // Optional: Confidence threshold (default: 0.7)
        "include_similar": boolean    // Optional: Include similar errors (default: false)
    }
}
```

### Parameters
- **error_data:** Error information (required)
  - **error_message:** Error message to classify (required)
  - **error_code:** Error code if available (optional)
  - **context:** Error context information (optional)
  - **tool_name:** Tool that generated the error (optional)
  - **command:** Command that caused the error (optional)
  - **timestamp:** Error timestamp (optional)
- **classification_options:** Classification configuration (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "classification_info": {
        "error_message": "Connection timed out after 30 seconds",
        "classification_confidence": 0.95,
        "processing_time": 0.8,
        "analysis_depth": "detailed"
    },
    "error_classification": {
        "primary_category": "network_error",
        "secondary_category": "timeout",
        "error_type": "TIMEOUT",
        "severity": "medium",
        "confidence_score": 0.95,
        "classification_reasoning": "Error message contains timeout keywords and network-related context",
        "error_patterns": [
            {
                "pattern": "timeout",
                "match_strength": 0.9,
                "pattern_type": "keyword"
            },
            {
                "pattern": "connection.*timed out",
                "match_strength": 0.95,
                "pattern_type": "regex"
            }
        ]
    },
    "recovery_suggestions": [
        {
            "strategy": "increase_timeout",
            "priority": "high",
            "confidence": 0.88,
            "description": "Increase command timeout value",
            "parameters": {
                "suggested_timeout": 60,
                "current_timeout": 30
            },
            "success_probability": 0.75
        },
        {
            "strategy": "retry_with_backoff",
            "priority": "medium",
            "confidence": 0.82,
            "description": "Retry with exponential backoff",
            "parameters": {
                "initial_delay": 5,
                "max_retries": 3,
                "backoff_factor": 2
            },
            "success_probability": 0.68
        },
        {
            "strategy": "network_diagnostics",
            "priority": "low",
            "confidence": 0.65,
            "description": "Run network connectivity diagnostics",
            "parameters": {
                "ping_test": true,
                "dns_test": true,
                "traceroute": false
            },
            "success_probability": 0.45
        }
    ],
    "error_context": {
        "tool_specific": {
            "tool_name": "nmap",
            "common_causes": ["network_congestion", "firewall_blocking", "target_unreachable"],
            "tool_specific_solutions": ["adjust_timing", "use_different_scan_type"]
        },
        "environmental_factors": {
            "network_conditions": "unstable",
            "system_load": "normal",
            "resource_availability": "sufficient"
        },
        "historical_data": {
            "similar_errors_count": 15,
            "most_successful_recovery": "increase_timeout",
            "average_resolution_time": 120
        }
    },
    "similar_errors": [
        {
            "error_message": "Read timeout after 30 seconds",
            "similarity_score": 0.85,
            "classification": "network_error",
            "successful_recovery": "increase_timeout"
        }
    ],
    "recommendations": [
        {
            "category": "Prevention",
            "suggestion": "Implement adaptive timeout based on network conditions",
            "priority": "medium"
        },
        {
            "category": "Monitoring",
            "suggestion": "Add network latency monitoring",
            "priority": "low"
        }
    ],
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Error Message (400 Bad Request)
```json
{
    "error": "Error message is required for classification"
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
error_data = params.get("error_data", {})
classification_options = params.get("classification_options", {})

error_message = error_data.get("error_message", "")
if not error_message:
    return jsonify({"error": "Error message is required for classification"}), 400
```

### Error Classification Logic
```python
# Use IntelligentErrorHandler for classification
classification_request = {
    "error_data": error_data,
    "options": classification_options
}

# Classify error using error handler
classification_result = error_handler.classify_error(classification_request)

# Generate recovery suggestions
recovery_suggestions = error_handler.suggest_recovery_strategies(classification_result)

# Get error context and historical data
error_context = error_handler.get_error_context(classification_result)

# Find similar errors if requested
similar_errors = []
if classification_options.get("include_similar", False):
    similar_errors = error_handler.find_similar_errors(classification_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Error classification access required

## Error Handling
- **Missing Parameters:** 400 error for missing error message
- **Classification Errors:** Handle errors during error classification
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Data Privacy:** Protect sensitive information in error messages
- **Access Control:** Control access to error classification capabilities
- **Information Disclosure:** Limit sensitive information exposure

## Use Cases and Applications

#### Error Analysis
- **Automated Classification:** Automatically classify errors for analysis
- **Pattern Recognition:** Recognize error patterns and trends
- **Recovery Planning:** Plan recovery strategies based on error types

#### System Monitoring
- **Error Tracking:** Track and categorize system errors
- **Performance Analysis:** Analyze error impact on system performance
- **Alerting:** Generate alerts based on error classifications

## Testing & Validation
- Parameter validation accuracy testing
- Error classification accuracy testing
- Recovery suggestion effectiveness testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/error-handling/classify-error", methods=["POST"])
def classify_error_endpoint():
    """Classify an error message"""
    try:
        params = request.json
        error_data = params.get("error_data", {})
        classification_options = params.get("classification_options", {})
        
        error_message = error_data.get("error_message", "")
        if not error_message:
            return jsonify({"error": "Error message is required for classification"}), 400
        
        logger.info(f"🔍 Classifying error message: {error_message[:100]}...")
        
        start_time = time.time()
        
        # Use IntelligentErrorHandler for classification
        classification_request = {
            "error_data": error_data,
            "options": classification_options
        }
        
        # Classify error using error handler
        classification_result = error_handler.classify_error(classification_request)
        
        # Generate recovery suggestions
        recovery_suggestions = error_handler.suggest_recovery_strategies(classification_result)
        
        # Get error context and historical data
        error_context = error_handler.get_error_context(classification_result)
        
        # Find similar errors if requested
        similar_errors = []
        if classification_options.get("include_similar", False):
            similar_errors = error_handler.find_similar_errors(classification_result)
        
        # Generate recommendations
        recommendations = error_handler.generate_error_recommendations(classification_result)
        
        processing_time = time.time() - start_time
        
        classification_info = {
            "error_message": error_message,
            "classification_confidence": classification_result.get("confidence", 0.0),
            "processing_time": processing_time,
            "analysis_depth": classification_options.get("detailed_analysis", True) and "detailed" or "basic"
        }
        
        logger.info(f"🔍 Error classified as {classification_result.get('primary_category', 'unknown')} | Confidence: {classification_result.get('confidence', 0):.2f}")
        
        return jsonify({
            "success": True,
            "classification_info": classification_info,
            "error_classification": classification_result,
            "recovery_suggestions": recovery_suggestions,
            "error_context": error_context,
            "similar_errors": similar_errors,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error classifying error: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
