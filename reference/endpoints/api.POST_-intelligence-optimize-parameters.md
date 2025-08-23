---
title: POST /api/intelligence/optimize-parameters
group: api
handler: optimize_parameters
module: __main__
line_range: [7711, 7736]
discovered_in_chunk: 7
---

# POST /api/intelligence/optimize-parameters

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Optimize tool parameters using AI intelligence

## Complete Signature & Definition
```python
@app.route("/api/intelligence/optimize-parameters", methods=["POST"])
def optimize_parameters():
    """Optimize tool parameters using AI intelligence with enhanced logging"""
```

## Purpose & Behavior
AI-powered parameter optimization endpoint providing:
- **Parameter Optimization:** Optimize tool parameters for maximum effectiveness
- **Performance Tuning:** Tune parameters based on target characteristics
- **Adaptive Configuration:** Adapt parameters based on real-time feedback
- **Enhanced Logging:** Detailed logging of optimization operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/intelligence/optimize-parameters
- **Content-Type:** application/json

### Request Body
```json
{
    "tool_config": {
        "tool_name": "string",        // Required: Tool name
        "current_parameters": "object", // Required: Current parameters
        "target_profile": "object",   // Required: Target profile
        "objectives": ["string"],     // Required: Optimization objectives
        "constraints": "object"       // Optional: Parameter constraints
    },
    "optimization_options": {
        "algorithm": "string",        // Optional: Optimization algorithm (default: genetic)
        "iterations": integer,        // Optional: Number of iterations (default: 100)
        "population_size": integer,   // Optional: Population size (default: 50)
        "mutation_rate": number,      // Optional: Mutation rate (default: 0.1)
        "crossover_rate": number,     // Optional: Crossover rate (default: 0.8)
        "convergence_threshold": number // Optional: Convergence threshold (default: 0.001)
    },
    "feedback_data": {
        "previous_results": ["object"], // Optional: Previous execution results
        "performance_metrics": "object", // Optional: Performance metrics
        "success_criteria": "object"   // Optional: Success criteria
    }
}
```

### Parameters
- **tool_config:** Tool configuration (required)
  - **tool_name:** Tool name (required)
  - **current_parameters:** Current parameters (required)
  - **target_profile:** Target profile (required)
  - **objectives:** Optimization objectives (required)
  - **constraints:** Parameter constraints (optional)
- **optimization_options:** Optimization configuration (optional)
- **feedback_data:** Historical feedback data (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "optimization_info": {
        "tool_name": "nmap",
        "algorithm": "genetic",
        "iterations_completed": 100,
        "convergence_achieved": true,
        "improvement_percentage": 25.3
    },
    "optimized_parameters": {
        "scan_type": "-sS",
        "timing": "-T4",
        "threads": 64,
        "timeout": 30,
        "rate_limit": 1000,
        "additional_flags": ["--script=vuln", "--version-intensity=5"]
    },
    "optimization_results": {
        "fitness_score": 0.87,
        "predicted_performance": {
            "execution_time": "3.2 minutes",
            "accuracy": 0.92,
            "coverage": 0.89,
            "stealth": 0.75
        },
        "parameter_analysis": {
            "most_impactful": ["timing", "threads"],
            "least_impactful": ["timeout"],
            "optimal_ranges": {
                "threads": [32, 128],
                "rate_limit": [500, 2000]
            }
        }
    },
    "comparison": {
        "original_fitness": 0.65,
        "optimized_fitness": 0.87,
        "improvement": 0.22,
        "key_changes": [
            {
                "parameter": "timing",
                "old_value": "-T3",
                "new_value": "-T4",
                "impact": "Increased speed by 40%"
            }
        ]
    },
    "recommendations": [
        {
            "category": "Performance",
            "suggestion": "Consider using -T5 for faster scanning if stealth is not critical",
            "confidence": 0.8
        }
    ],
    "optimization_metadata": {
        "algorithm_version": "v3.2",
        "optimization_time": 45.7,
        "convergence_generation": 78,
        "total_evaluations": 5000
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Required Fields (400 Bad Request)
```json
{
    "error": "Missing required fields: tool_config.tool_name, tool_config.current_parameters"
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
tool_config = params.get("tool_config", {})
optimization_options = params.get("optimization_options", {})
feedback_data = params.get("feedback_data", {})

# Validate required tool config fields
required_fields = ["tool_name", "current_parameters", "target_profile", "objectives"]
missing_fields = [field for field in required_fields if not tool_config.get(field)]
if missing_fields:
    return jsonify({"error": f"Missing required fields: {', '.join(['tool_config.' + field for field in missing_fields])}"}), 400
```

### Optimization Logic
```python
# Use ParameterOptimizer for optimization
optimization_request = {
    "tool": tool_config,
    "options": optimization_options,
    "feedback": feedback_data
}

# Perform optimization using parameter optimizer
optimization_result = parameter_optimizer.optimize_parameters(optimization_request)

# Analyze optimization results
analysis = parameter_optimizer.analyze_optimization(optimization_result)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Parameter optimization access required

## Error Handling
- **Missing Parameters:** 400 error for missing required fields
- **Optimization Errors:** Handle errors during parameter optimization
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Parameter Validation:** Validate optimized parameters for security
- **Resource Limits:** Implement resource limits for optimization
- **Access Control:** Control access to optimization capabilities

## Use Cases and Applications

#### Performance Optimization
- **Tool Tuning:** Optimize tool parameters for maximum performance
- **Efficiency Improvement:** Improve assessment efficiency through optimization
- **Adaptive Configuration:** Adapt configurations based on target characteristics

#### Automated Testing
- **Parameter Discovery:** Discover optimal parameters automatically
- **Continuous Improvement:** Continuously improve parameter configurations
- **Performance Benchmarking:** Benchmark parameter performance

## Testing & Validation
- Parameter validation accuracy testing
- Optimization algorithm verification testing
- Performance improvement measurement testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/intelligence/optimize-parameters", methods=["POST"])
def optimize_parameters():
    """Optimize tool parameters using AI intelligence with enhanced logging"""
    try:
        params = request.json
        tool_config = params.get("tool_config", {})
        optimization_options = params.get("optimization_options", {})
        feedback_data = params.get("feedback_data", {})
        
        # Validate required tool config fields
        required_fields = ["tool_name", "current_parameters", "target_profile", "objectives"]
        missing_fields = [field for field in required_fields if not tool_config.get(field)]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(['tool_config.' + field for field in missing_fields])}"}), 400
        
        logger.info(f"🤖 Optimizing parameters for tool: {tool_config['tool_name']}")
        
        start_time = time.time()
        
        # Use ParameterOptimizer for optimization
        optimization_request = {
            "tool": tool_config,
            "options": optimization_options,
            "feedback": feedback_data
        }
        
        # Perform optimization using parameter optimizer
        optimization_result = parameter_optimizer.optimize_parameters(optimization_request)
        
        # Analyze optimization results
        analysis = parameter_optimizer.analyze_optimization(optimization_result)
        
        optimization_time = time.time() - start_time
        
        optimization_info = {
            "tool_name": tool_config["tool_name"],
            "algorithm": optimization_options.get("algorithm", "genetic"),
            "iterations_completed": optimization_result.get("iterations", 0),
            "convergence_achieved": optimization_result.get("converged", False),
            "improvement_percentage": analysis.get("improvement_percentage", 0.0)
        }
        
        optimization_metadata = {
            "algorithm_version": "v3.2",
            "optimization_time": optimization_time,
            "convergence_generation": optimization_result.get("convergence_generation", 0),
            "total_evaluations": optimization_result.get("total_evaluations", 0)
        }
        
        logger.info(f"🤖 Parameter optimization completed in {optimization_time:.2f}s | Improvement: {analysis.get('improvement_percentage', 0):.1f}%")
        
        return jsonify({
            "success": True,
            "optimization_info": optimization_info,
            "optimized_parameters": optimization_result["parameters"],
            "optimization_results": optimization_result["results"],
            "comparison": analysis["comparison"],
            "recommendations": analysis["recommendations"],
            "optimization_metadata": optimization_metadata,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error optimizing parameters: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
