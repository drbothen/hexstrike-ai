---
title: POST /api/error-handling/parameter-adjustments
group: api
handler: get_parameter_adjustments
module: __main__
line_range: [15318, 15348]
discovered_in_chunk: 15
---

# POST /api/error-handling/parameter-adjustments

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Get parameter adjustments for a tool and error type

## Complete Signature & Definition
```python
@app.route("/api/error-handling/parameter-adjustments", methods=["POST"])
def get_parameter_adjustments():
    """Get parameter adjustments for a tool and error type"""
```

## Purpose & Behavior
Parameter adjustment endpoint providing:
- **Adjustment Recommendations:** Recommend parameter adjustments for error recovery
- **Tool-Specific Tuning:** Provide tool-specific parameter tuning suggestions
- **Error-Based Optimization:** Optimize parameters based on error types
- **Enhanced Logging:** Detailed logging of parameter adjustment operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/error-handling/parameter-adjustments
- **Content-Type:** application/json

### Request Body
```json
{
    "adjustment_request": {
        "tool_name": "string",        // Required: Tool name
        "error_type": "string",       // Required: Error type
        "current_parameters": "object", // Required: Current tool parameters
        "error_context": "object",    // Optional: Error context information
        "target_info": "object"       // Optional: Target information
    },
    "adjustment_options": {
        "optimization_goal": "string", // Optional: Optimization goal (default: success_rate)
        "aggressiveness": "string",   // Optional: Adjustment aggressiveness (default: moderate)
        "preserve_parameters": ["string"], // Optional: Parameters to preserve
        "max_adjustments": integer,   // Optional: Maximum adjustments (default: 5)
        "confidence_threshold": number // Optional: Confidence threshold (default: 0.7)
    }
}
```

### Parameters
- **adjustment_request:** Adjustment request information (required)
  - **tool_name:** Tool name (required)
  - **error_type:** Error type (required)
  - **current_parameters:** Current tool parameters (required)
  - **error_context:** Error context information (optional)
  - **target_info:** Target information (optional)
- **adjustment_options:** Adjustment configuration (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "adjustment_info": {
        "tool_name": "nmap",
        "error_type": "timeout",
        "adjustments_generated": 4,
        "optimization_goal": "success_rate",
        "confidence_score": 0.88
    },
    "parameter_adjustments": [
        {
            "parameter": "timing",
            "current_value": "-T4",
            "suggested_value": "-T3",
            "adjustment_type": "decrease_aggressiveness",
            "confidence": 0.92,
            "rationale": "Reduce timing aggressiveness to avoid timeouts",
            "expected_impact": {
                "success_rate_improvement": 0.25,
                "execution_time_increase": 1.4,
                "resource_usage_change": -0.15
            },
            "priority": "high"
        },
        {
            "parameter": "timeout",
            "current_value": "30",
            "suggested_value": "60",
            "adjustment_type": "increase_timeout",
            "confidence": 0.89,
            "rationale": "Increase timeout to accommodate slower responses",
            "expected_impact": {
                "success_rate_improvement": 0.30,
                "execution_time_increase": 0.0,
                "resource_usage_change": 0.0
            },
            "priority": "high"
        },
        {
            "parameter": "max_retries",
            "current_value": "0",
            "suggested_value": "2",
            "adjustment_type": "add_retries",
            "confidence": 0.75,
            "rationale": "Add retries to handle intermittent failures",
            "expected_impact": {
                "success_rate_improvement": 0.15,
                "execution_time_increase": 0.8,
                "resource_usage_change": 0.10
            },
            "priority": "medium"
        },
        {
            "parameter": "host_timeout",
            "current_value": "1000",
            "suggested_value": "2000",
            "adjustment_type": "increase_host_timeout",
            "confidence": 0.82,
            "rationale": "Increase per-host timeout for better reliability",
            "expected_impact": {
                "success_rate_improvement": 0.20,
                "execution_time_increase": 1.2,
                "resource_usage_change": 0.05
            },
            "priority": "medium"
        }
    ],
    "adjustment_combinations": [
        {
            "combination_id": "combo_1",
            "parameters": ["timing", "timeout"],
            "combined_confidence": 0.90,
            "expected_improvement": 0.45,
            "synergy_score": 0.85,
            "recommended": true
        },
        {
            "combination_id": "combo_2",
            "parameters": ["timeout", "max_retries", "host_timeout"],
            "combined_confidence": 0.78,
            "expected_improvement": 0.52,
            "synergy_score": 0.72,
            "recommended": false
        }
    ],
    "historical_data": {
        "similar_adjustments": 45,
        "success_rate": 0.82,
        "most_effective_adjustment": "increase_timeout",
        "average_improvement": 0.28
    },
    "validation_suggestions": [
        {
            "test_scenario": "timeout_prone_target",
            "validation_method": "controlled_test",
            "expected_outcome": "reduced_timeout_errors",
            "confidence": 0.85
        }
    ],
    "recommendations": [
        {
            "category": "Implementation",
            "priority": "high",
            "suggestion": "Apply timing and timeout adjustments together",
            "rationale": "These parameters work synergistically"
        },
        {
            "category": "Monitoring",
            "priority": "medium",
            "suggestion": "Monitor success rate after applying adjustments",
            "rationale": "Validate effectiveness of parameter changes"
        }
    ],
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: tool_name, error_type, current_parameters"
}
```

#### Unknown Tool (400 Bad Request)
```json
{
    "error": "Unknown tool: {tool_name}"
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
adjustment_request = params.get("adjustment_request", {})
adjustment_options = params.get("adjustment_options", {})

tool_name = adjustment_request.get("tool_name", "")
error_type = adjustment_request.get("error_type", "")
current_parameters = adjustment_request.get("current_parameters", {})

required_fields = []
if not tool_name:
    required_fields.append("tool_name")
if not error_type:
    required_fields.append("error_type")
if not current_parameters:
    required_fields.append("current_parameters")

if required_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400
```

### Parameter Adjustment Logic
```python
# Use ParameterOptimizer for adjustments
adjustment_request_data = {
    "tool": tool_name,
    "error": error_type,
    "parameters": current_parameters,
    "context": adjustment_request.get("error_context", {}),
    "target": adjustment_request.get("target_info", {}),
    "options": adjustment_options
}

# Generate parameter adjustments
adjustments_result = parameter_optimizer.generate_parameter_adjustments(adjustment_request_data)

# Analyze adjustment combinations
combinations = parameter_optimizer.analyze_adjustment_combinations(adjustments_result)

# Get historical data
historical_data = parameter_optimizer.get_historical_adjustment_data(tool_name, error_type)

# Generate validation suggestions
validation_suggestions = parameter_optimizer.generate_validation_suggestions(adjustments_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Parameter adjustment access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Unknown Tool:** 400 error for unknown tools
- **Adjustment Errors:** Handle errors during parameter adjustment generation
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Parameter Validation:** Validate parameter adjustments for security
- **Access Control:** Control access to parameter adjustment capabilities
- **Configuration Security:** Protect sensitive configuration information

## Use Cases and Applications

#### Error Recovery
- **Automatic Tuning:** Automatically tune parameters for error recovery
- **Performance Optimization:** Optimize tool performance through parameter adjustment
- **Reliability Improvement:** Improve tool reliability through parameter optimization

#### System Administration
- **Configuration Management:** Manage tool configurations and parameters
- **Performance Tuning:** Tune system performance through parameter optimization
- **Troubleshooting:** Troubleshoot issues through parameter adjustment

## Testing & Validation
- Parameter validation accuracy testing
- Adjustment generation effectiveness testing
- Historical data accuracy verification testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/error-handling/parameter-adjustments", methods=["POST"])
def get_parameter_adjustments():
    """Get parameter adjustments for a tool and error type"""
    try:
        params = request.json
        adjustment_request = params.get("adjustment_request", {})
        adjustment_options = params.get("adjustment_options", {})
        
        tool_name = adjustment_request.get("tool_name", "")
        error_type = adjustment_request.get("error_type", "")
        current_parameters = adjustment_request.get("current_parameters", {})
        
        required_fields = []
        if not tool_name:
            required_fields.append("tool_name")
        if not error_type:
            required_fields.append("error_type")
        if not current_parameters:
            required_fields.append("current_parameters")
        
        if required_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(required_fields)}"}), 400
        
        logger.info(f"🔧 Generating parameter adjustments | Tool: {tool_name} | Error: {error_type}")
        
        # Use ParameterOptimizer for adjustments
        adjustment_request_data = {
            "tool": tool_name,
            "error": error_type,
            "parameters": current_parameters,
            "context": adjustment_request.get("error_context", {}),
            "target": adjustment_request.get("target_info", {}),
            "options": adjustment_options
        }
        
        # Generate parameter adjustments
        adjustments_result = parameter_optimizer.generate_parameter_adjustments(adjustment_request_data)
        
        # Analyze adjustment combinations
        combinations = parameter_optimizer.analyze_adjustment_combinations(adjustments_result)
        
        # Get historical data
        historical_data = parameter_optimizer.get_historical_adjustment_data(tool_name, error_type)
        
        # Generate validation suggestions
        validation_suggestions = parameter_optimizer.generate_validation_suggestions(adjustments_result)
        
        # Generate recommendations
        recommendations = parameter_optimizer.generate_adjustment_recommendations(adjustments_result)
        
        adjustment_info = {
            "tool_name": tool_name,
            "error_type": error_type,
            "adjustments_generated": len(adjustments_result.get("adjustments", [])),
            "optimization_goal": adjustment_options.get("optimization_goal", "success_rate"),
            "confidence_score": adjustments_result.get("overall_confidence", 0.0)
        }
        
        logger.info(f"🔧 Generated {len(adjustments_result.get('adjustments', []))} parameter adjustments | Confidence: {adjustments_result.get('overall_confidence', 0):.2f}")
        
        return jsonify({
            "success": True,
            "adjustment_info": adjustment_info,
            "parameter_adjustments": adjustments_result.get("adjustments", []),
            "adjustment_combinations": combinations,
            "historical_data": historical_data,
            "validation_suggestions": validation_suggestions,
            "recommendations": recommendations,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error getting parameter adjustments: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
