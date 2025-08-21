"""
Web security tool endpoint handlers.

This module handles endpoints for web application security tools.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class WebToolEndpoints:
    """Web security tool endpoint handlers"""
    
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
    
    def nuclei(self):
        """Execute Nuclei vulnerability scanner"""
        return self._execute_tool_endpoint("nuclei")
    
    def gobuster(self):
        """Execute Gobuster directory/file brute-forcer"""
        return self._execute_tool_endpoint("gobuster")
    
    def sqlmap(self):
        """Execute SQLMap SQL injection tool"""
        return self._execute_tool_endpoint("sqlmap")
    
    def nikto(self):
        """Execute Nikto web server scanner"""
        return self._execute_tool_endpoint("nikto")
    
    def ffuf(self):
        """Execute FFuf web fuzzer"""
        return self._execute_tool_endpoint("ffuf")
    
    def wpscan(self):
        """Execute WPScan WordPress scanner"""
        return self._execute_tool_endpoint("wpscan")
    
    def feroxbuster(self):
        """Execute Feroxbuster content discovery"""
        return self._execute_tool_endpoint("feroxbuster")
    
    def dotdotpwn(self):
        """Execute DotDotPwn directory traversal"""
        return self._execute_tool_endpoint("dotdotpwn")
    
    def xsser(self):
        """Execute XSSer XSS scanner"""
        return self._execute_tool_endpoint("xsser")
    
    def wfuzz(self):
        """Execute Wfuzz web fuzzer"""
        return self._execute_tool_endpoint("wfuzz")
    
    def dirsearch(self):
        """Execute Dirsearch directory scanner"""
        return self._execute_tool_endpoint("dirsearch")
    
    def katana(self):
        """Execute Katana web crawler"""
        return self._execute_tool_endpoint("katana")
    
    def gau(self):
        """Execute Gau URL discovery"""
        return self._execute_tool_endpoint("gau")
    
    def waybackurls(self):
        """Execute Waybackurls historical URL discovery"""
        return self._execute_tool_endpoint("waybackurls")
    
    def arjun(self):
        """Execute Arjun parameter discovery"""
        return self._execute_tool_endpoint("arjun")
    
    def paramspider(self):
        """Execute ParamSpider parameter mining"""
        return self._execute_tool_endpoint("paramspider")
    
    def x8(self):
        """Execute x8 hidden parameter discovery"""
        return self._execute_tool_endpoint("x8")
    
    def jaeles(self):
        """Execute Jaeles vulnerability scanner"""
        return self._execute_tool_endpoint("jaeles")
    
    def dalfox(self):
        """Execute Dalfox XSS scanner"""
        return self._execute_tool_endpoint("dalfox")
    
    def httpx(self):
        """Execute httpx HTTP toolkit"""
        return self._execute_tool_endpoint("httpx")
    
    def zap(self):
        """Execute OWASP ZAP"""
        return self._execute_tool_endpoint("zap")
    
    def wafw00f(self):
        """Execute wafw00f WAF detection"""
        return self._execute_tool_endpoint("wafw00f")
    
    def hakrawler(self):
        """Execute Hakrawler web endpoint discovery"""
        return self._execute_tool_endpoint("hakrawler")
