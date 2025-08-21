"""
Utility tool endpoint handlers.

This module handles endpoints for utility tools.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class UtilityToolEndpoints:
    """Utility tool endpoint handlers"""
    
    def __init__(self):
        self.tool_executor = ToolExecutionService()
    
    def _execute_tool_endpoint(self, tool_name: str) -> Dict[str, Any]:
        """Generic tool execution endpoint"""
        try:
            data = request.get_json() or {}
            
            result = self.tool_executor.execute_tool(tool_name, data)
            
            if result.success:
                logger.info(f"✅ {tool_name} executed successfully")
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "result": result.stdout,
                    "execution_time": result.execution_time,
                    "message": f"{tool_name} execution completed"
                })
            else:
                logger.error(f"❌ {tool_name} execution failed: {result.stderr}")
                return jsonify({
                    "success": False,
                    "tool": tool_name,
                    "error": result.stderr,
                    "message": f"{tool_name} execution failed"
                }), 500
                
        except Exception as e:
            logger.error(f"💥 Error in {tool_name} endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def anew(self):
        """Execute anew data processing"""
        return self._execute_tool_endpoint("anew")
    
    def qsreplace(self):
        """Execute qsreplace query parameter replacement"""
        return self._execute_tool_endpoint("qsreplace")
    
    def uro(self):
        """Execute uro URL filtering"""
        return self._execute_tool_endpoint("uro")
