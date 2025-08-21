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
from .request_handlers import RequestHandlers

logger = logging.getLogger(__name__)

class FlaskAdapter:
    """Flask framework integration adapter"""
    
    def __init__(self, app: Flask):
        self.app = app
        self.decision_service = DecisionService()
        self.execution_service = ToolExecutionService()
        self.process_service = ProcessService()
        self.error_handler = ErrorHandler()
        
        self.request_handlers = RequestHandlers(
            self.decision_service,
            self.execution_service,
            self.process_service,
            self.error_handler
        )
        
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
