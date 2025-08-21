"""
Cloud security tool endpoint handlers.

This module handles endpoints for cloud security tools.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class CloudToolEndpoints:
    """Cloud security tool endpoint handlers"""
    
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
    
    def trivy(self):
        """Execute Trivy container scanner"""
        return self._execute_tool_endpoint("trivy")
    
    def prowler(self):
        """Execute Prowler cloud security scanner"""
        return self._execute_tool_endpoint("prowler")
    
    def scout_suite(self):
        """Execute Scout Suite cloud security"""
        return self._execute_tool_endpoint("scout-suite")
    
    def kube_hunter(self):
        """Execute kube-hunter Kubernetes scanner"""
        return self._execute_tool_endpoint("kube-hunter")
    
    def kube_bench(self):
        """Execute kube-bench CIS benchmarks"""
        return self._execute_tool_endpoint("kube-bench")
    
    def checkov(self):
        """Execute Checkov IaC scanner"""
        return self._execute_tool_endpoint("checkov")
    
    def terrascan(self):
        """Execute Terrascan IaC security"""
        return self._execute_tool_endpoint("terrascan")
