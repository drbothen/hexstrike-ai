"""
Comprehensive cloud security tool endpoint handlers.

This module handles comprehensive cloud security tool endpoints.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class ComprehensiveCloudToolEndpoints:
    """Comprehensive cloud security tool endpoint handlers"""
    
    def __init__(self):
        self.execution_service = ToolExecutionService()
    
    def _execute_tool_endpoint(self, tool_name: str) -> Dict[str, Any]:
        """Generic tool execution endpoint handler"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Request body must contain valid JSON"}), 400
            
            result = self.execution_service.execute_tool(tool_name, data)
            
            if result.success:
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "output": result.stdout,
                    "execution_time": result.execution_time,
                    "command": ""
                })
            else:
                return jsonify({
                    "success": False,
                    "error": result.stderr,
                    "tool": tool_name
                }), 500
                
        except Exception as e:
            logger.error(f"💥 Error in {tool_name} endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def prowler(self):
        """Execute prowler AWS security assessment"""
        return self._execute_tool_endpoint("prowler")
    
    def scout_suite(self):
        """Execute scout-suite multi-cloud assessment"""
        return self._execute_tool_endpoint("scout-suite")
    
    def trivy(self):
        """Execute trivy container scanner"""
        return self._execute_tool_endpoint("trivy")
    
    def checkov(self):
        """Execute checkov IaC scanner"""
        return self._execute_tool_endpoint("checkov")
    
    def terrascan(self):
        """Execute terrascan"""
        return self._execute_tool_endpoint("terrascan")
    
    def kube_hunter(self):
        """Execute kube-hunter"""
        return self._execute_tool_endpoint("kube-hunter")
    
    def kube_bench(self):
        """Execute kube-bench"""
        return self._execute_tool_endpoint("kube-bench")
    
    def docker_bench_security(self):
        """Execute docker-bench-security"""
        return self._execute_tool_endpoint("docker-bench-security")
    
    def clair(self):
        """Execute clair container scanner"""
        return self._execute_tool_endpoint("clair")
    
    def falco(self):
        """Execute falco runtime security"""
        return self._execute_tool_endpoint("falco")
