"""
Flask request handler utilities.

This module changes when request handling logic changes.
"""

from flask import request, jsonify, Response
from typing import Dict, Any, List
import logging
from functools import wraps

logger = logging.getLogger(__name__)

class RequestHandlers:
    """Request handling utilities for Flask adapter"""
    
    def __init__(self, decision_service, execution_service, process_service, error_handler):
        self.decision_service = decision_service
        self.execution_service = execution_service
        self.process_service = process_service
        self.error_handler = error_handler
    
    def handle_tool_execution(self, request_data: Dict[str, Any]) -> Response:
        """Handle tool execution requests"""
        try:
            from ..platform.validation import validator
            
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
