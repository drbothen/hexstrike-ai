"""
Network security tool endpoint handlers.

This module handles endpoints for network security tools.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class NetworkToolEndpoints:
    """Network security tool endpoint handlers"""
    
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
    
    def nmap(self):
        """Execute Nmap network scanner"""
        return self._execute_tool_endpoint("nmap")
    
    def rustscan(self):
        """Execute Rustscan ultra-fast port scanner"""
        return self._execute_tool_endpoint("rustscan")
    
    def masscan(self):
        """Execute Masscan high-speed port scanner"""
        return self._execute_tool_endpoint("masscan")
    
    def nmap_advanced(self):
        """Execute advanced Nmap with NSE scripts"""
        return self._execute_tool_endpoint("nmap-advanced")
    
    def autorecon(self):
        """Execute AutoRecon automated reconnaissance"""
        return self._execute_tool_endpoint("autorecon")
    
    def enum4linux_ng(self):
        """Execute Enum4linux-ng advanced SMB enumeration"""
        return self._execute_tool_endpoint("enum4linux-ng")
    
    def enum4linux(self):
        """Execute enum4linux SMB enumeration tool"""
        return self._execute_tool_endpoint("enum4linux")
    
    def smbmap(self):
        """Execute SMBMap SMB share enumeration"""
        return self._execute_tool_endpoint("smbmap")
    
    def rpcclient(self):
        """Execute rpcclient RPC enumeration"""
        return self._execute_tool_endpoint("rpcclient")
    
    def nbtscan(self):
        """Execute nbtscan NetBIOS scanner"""
        return self._execute_tool_endpoint("nbtscan")
    
    def arp_scan(self):
        """Execute arp-scan network discovery"""
        return self._execute_tool_endpoint("arp-scan")
    
    def responder(self):
        """Execute Responder credential harvesting"""
        return self._execute_tool_endpoint("responder")
    
    def netexec(self):
        """Execute NetExec (formerly CrackMapExec)"""
        return self._execute_tool_endpoint("netexec")
    
    def amass(self):
        """Execute Amass subdomain enumeration"""
        return self._execute_tool_endpoint("amass")
    
    def subfinder(self):
        """Execute Subfinder subdomain discovery"""
        return self._execute_tool_endpoint("subfinder")
    
    def fierce(self):
        """Execute fierce DNS reconnaissance"""
        return self._execute_tool_endpoint("fierce")
    
    def dnsenum(self):
        """Execute dnsenum DNS enumeration"""
        return self._execute_tool_endpoint("dnsenum")
