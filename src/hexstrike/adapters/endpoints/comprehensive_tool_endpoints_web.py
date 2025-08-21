"""
Comprehensive web security tool endpoint handlers.

This module handles comprehensive web application security tool endpoints.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class ComprehensiveWebToolEndpoints:
    """Comprehensive web security tool endpoint handlers"""
    
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
    
    def gobuster(self):
        """Execute gobuster directory brute force"""
        return self._execute_tool_endpoint("gobuster")
    
    def dirsearch(self):
        """Execute dirsearch"""
        return self._execute_tool_endpoint("dirsearch")
    
    def feroxbuster(self):
        """Execute feroxbuster"""
        return self._execute_tool_endpoint("feroxbuster")
    
    def ffuf(self):
        """Execute ffuf fuzzer"""
        return self._execute_tool_endpoint("ffuf")
    
    def nuclei(self):
        """Execute nuclei vulnerability scanner"""
        return self._execute_tool_endpoint("nuclei")
    
    def nikto(self):
        """Execute nikto web scanner"""
        return self._execute_tool_endpoint("nikto")
    
    def sqlmap(self):
        """Execute sqlmap SQL injection tool"""
        return self._execute_tool_endpoint("sqlmap")
    
    def dalfox(self):
        """Execute dalfox XSS scanner"""
        return self._execute_tool_endpoint("dalfox")
    
    def httpx(self):
        """Execute httpx HTTP toolkit"""
        return self._execute_tool_endpoint("httpx")
    
    def katana(self):
        """Execute katana web crawler"""
        return self._execute_tool_endpoint("katana")
    
    def gau(self):
        """Execute gau URL fetcher"""
        return self._execute_tool_endpoint("gau")
    
    def waybackurls(self):
        """Execute waybackurls"""
        return self._execute_tool_endpoint("waybackurls")
    
    def arjun(self):
        """Execute arjun parameter discovery"""
        return self._execute_tool_endpoint("arjun")
    
    def paramspider(self):
        """Execute paramspider"""
        return self._execute_tool_endpoint("paramspider")
