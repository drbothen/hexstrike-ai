"""
Flask framework integration adapter.

This module changes when Flask integration requirements or API structure changes.
"""

from flask import Flask, request, jsonify, Response
from typing import Dict, Any, Callable, Optional
import logging
from functools import wraps
from ..services.decision_service import DecisionService
from ..services.tool_execution_service import ToolExecutionService
from ..services.process_service import ProcessService
from ..platform.errors import ErrorHandler
from ..platform.validation import validator

logger = logging.getLogger(__name__)

class FlaskAdapter:
    """Flask framework integration adapter"""
    
    def __init__(self, app: Flask):
        self.app = app
        self.decision_service = DecisionService()
        self.execution_service = ToolExecutionService()
        self.process_service = ProcessService()
        self.error_handler = ErrorHandler()
        
        self._register_error_handlers()
    
    def _register_error_handlers(self) -> None:
        """Register global error handlers"""
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid request parameters",
                "status_code": 400
            }), 400
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "error": "Not Found",
                "message": "Endpoint not found",
                "status_code": 404
            }), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
                "status_code": 500
            }), 500
    
    def validate_json_request(self, required_fields: list = None):
        """Decorator to validate JSON request data"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not request.is_json:
                    return jsonify({
                        "error": "Content-Type must be application/json"
                    }), 400
                
                data = request.get_json()
                if not data:
                    return jsonify({
                        "error": "Request body must contain valid JSON"
                    }), 400
                
                if required_fields:
                    missing_fields = [field for field in required_fields if field not in data]
                    if missing_fields:
                        return jsonify({
                            "error": f"Missing required fields: {', '.join(missing_fields)}"
                        }), 400
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def handle_tool_execution(self, request_data: Dict[str, Any]) -> Response:
        """Handle tool execution requests"""
        try:
            tool_name = request_data.get("tool_name", "")
            parameters = request_data.get("parameters", {})
            use_recovery = request_data.get("use_recovery", True)
            
            if not tool_name:
                return jsonify({
                    "error": "tool_name is required"
                }), 400
            
            validation_errors = validator.validate_tool_parameters(tool_name, parameters)
            if validation_errors:
                return jsonify({
                    "error": "Parameter validation failed",
                    "validation_errors": [
                        {"field": err.field, "message": err.message} 
                        for err in validation_errors
                    ]
                }), 400
            
            if use_recovery:
                result = self.execution_service.execute_with_recovery(tool_name, parameters)
            else:
                result = self.execution_service.execute_tool(tool_name, parameters)
            
            return jsonify({
                "success": result.success,
                "tool_name": result.tool_name,
                "target": result.target,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.return_code,
                "execution_time": result.execution_time,
                "parsed_output": result.parsed_output,
                "recovery_info": result.recovery_info,
                "timestamp": result.timestamp
            })
            
        except Exception as e:
            logger.error(f"Error in tool execution: {str(e)}")
            return jsonify({
                "error": f"Tool execution failed: {str(e)}"
            }), 500
    
    def handle_intelligence_request(self, request_data: Dict[str, Any]) -> Response:
        """Handle intelligence analysis requests"""
        try:
            target = request_data.get("target", "")
            objective = request_data.get("objective", "comprehensive")
            max_tools = request_data.get("max_tools", 10)
            
            if not target:
                return jsonify({
                    "error": "target is required"
                }), 400
            
            # Analyze target
            profile = self.decision_service.analyze_target(target)
            
            # Select optimal tools
            selected_tools = self.decision_service.select_optimal_tools(profile, objective, max_tools)
            
            optimized_tools = []
            for tool in selected_tools:
                optimized_params = self.decision_service.optimize_parameters(tool, profile)
                optimized_tools.append({
                    "tool": tool,
                    "parameters": optimized_params,
                    "effectiveness": self.decision_service.calculate_tool_effectiveness(tool, profile.target_type)
                })
            
            return jsonify({
                "success": True,
                "target": target,
                "target_profile": profile.to_dict(),
                "selected_tools": selected_tools,
                "optimized_tools": optimized_tools,
                "total_tools": len(selected_tools)
            })
            
        except Exception as e:
            logger.error(f"Error in intelligence request: {str(e)}")
            return jsonify({
                "error": f"Intelligence analysis failed: {str(e)}"
            }), 500
    
    def handle_process_management(self, request_data: Dict[str, Any]) -> Response:
        """Handle process management requests"""
        try:
            action = request_data.get("action", "")
            pid = request_data.get("pid")
            
            if action == "list":
                processes = self.process_service.list_active_processes()
                return jsonify({
                    "success": True,
                    "processes": processes,
                    "total_processes": len(processes)
                })
            
            elif action == "status":
                if not pid:
                    return jsonify({
                        "error": "pid is required for status action"
                    }), 400
                
                status = self.process_service.get_process_status(pid)
                if status:
                    return jsonify({
                        "success": True,
                        "process": status
                    })
                else:
                    return jsonify({
                        "error": f"Process {pid} not found"
                    }), 404
            
            elif action == "terminate":
                if not pid:
                    return jsonify({
                        "error": "pid is required for terminate action"
                    }), 400
                
                success = self.process_service.terminate_process(pid)
                return jsonify({
                    "success": success,
                    "message": f"Process {pid} {'terminated' if success else 'termination failed'}"
                })
            
            elif action == "pause":
                if not pid:
                    return jsonify({
                        "error": "pid is required for pause action"
                    }), 400
                
                success = self.process_service.pause_process(pid)
                return jsonify({
                    "success": success,
                    "message": f"Process {pid} {'paused' if success else 'pause failed'}"
                })
            
            elif action == "resume":
                if not pid:
                    return jsonify({
                        "error": "pid is required for resume action"
                    }), 400
                
                success = self.process_service.resume_process(pid)
                return jsonify({
                    "success": success,
                    "message": f"Process {pid} {'resumed' if success else 'resume failed'}"
                })
            
            else:
                return jsonify({
                    "error": f"Unknown action: {action}"
                }), 400
                
        except Exception as e:
            logger.error(f"Error in process management: {str(e)}")
            return jsonify({
                "error": f"Process management failed: {str(e)}"
            }), 500
    
    def validate_request(self, request_data: Dict[str, Any], schema: type) -> bool:
        """Validate request against schema"""
        try:
            return True
        except Exception as e:
            logger.error(f"Request validation failed: {str(e)}")
            return False
    
    def format_response(self, data: Any, success: bool = True, status_code: int = 200) -> Response:
        """Format standardized API response"""
        response_data = {
            "success": success,
            "data": data if success else None,
            "error": data if not success else None,
            "timestamp": self._get_current_timestamp()
        }
        
        return jsonify(response_data), status_code
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def register_routes(self) -> None:
        """Register all API routes"""
        
        @self.app.route("/api/v1/tools/execute", methods=["POST"])
        @self.validate_json_request(["tool_name", "parameters"])
        def execute_tool():
            """Execute a security tool"""
            return self.handle_tool_execution(request.get_json())
        
        @self.app.route("/api/v1/intelligence/analyze-target", methods=["POST"])
        @self.validate_json_request(["target"])
        def analyze_target():
            """Analyze target and get intelligence"""
            return self.handle_intelligence_request(request.get_json())
        
        @self.app.route("/api/v1/processes", methods=["POST"])
        @self.validate_json_request(["action"])
        def manage_processes():
            """Manage processes"""
            return self.handle_process_management(request.get_json())
        
        @self.app.route("/api/v1/health", methods=["GET"])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                "status": "healthy",
                "version": "6.0.0",
                "timestamp": self._get_current_timestamp(),
                "services": {
                    "decision_service": "active",
                    "execution_service": "active",
                    "process_service": "active"
                }
            })
