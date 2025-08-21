"""
Comprehensive network security tool endpoint handlers.

This module handles comprehensive network security tool endpoints.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class ComprehensiveNetworkToolEndpoints:
    """Comprehensive network security tool endpoint handlers"""
    
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
    
    def nmap(self):
        """Execute nmap scan"""
        return self._execute_tool_endpoint("nmap")
    
    def rustscan(self):
        """Execute rustscan"""
        return self._execute_tool_endpoint("rustscan")
    
    def masscan(self):
        """Execute masscan"""
        return self._execute_tool_endpoint("masscan")
    
    def naabu(self):
        """Execute naabu port scanner"""
        return self._execute_tool_endpoint("naabu")
    
    def amass(self):
        """Execute amass subdomain enumeration"""
        return self._execute_tool_endpoint("amass")
    
    def subfinder(self):
        """Execute subfinder"""
        return self._execute_tool_endpoint("subfinder")
    
    def assetfinder(self):
        """Execute assetfinder"""
        return self._execute_tool_endpoint("assetfinder")
    
    def findomain(self):
        """Execute findomain"""
        return self._execute_tool_endpoint("findomain")
    
    def shodan(self):
        """Execute shodan search"""
        return self._execute_tool_endpoint("shodan")
    
    def censys(self):
        """Execute censys search"""
        return self._execute_tool_endpoint("censys")
    
    def enum4linux_ng(self):
        """Execute enum4linux-ng"""
        return self._execute_tool_endpoint("enum4linux-ng")
    
    def smbmap(self):
        """Execute smbmap"""
        return self._execute_tool_endpoint("smbmap")
    
    def rpcclient(self):
        """Execute rpcclient"""
        return self._execute_tool_endpoint("rpcclient")
    
    def ldapsearch(self):
        """Execute ldapsearch"""
        return self._execute_tool_endpoint("ldapsearch")
    
    def snmpwalk(self):
        """Execute snmpwalk"""
        return self._execute_tool_endpoint("snmpwalk")
    
    def responder(self):
        """Execute responder"""
        return self._execute_tool_endpoint("responder")
    
    def impacket(self):
        """Execute impacket tools"""
        return self._execute_tool_endpoint("impacket")
    
    def bloodhound(self):
        """Execute bloodhound"""
        return self._execute_tool_endpoint("bloodhound")
    
    def crackmapexec(self):
        """Execute crackmapexec"""
        return self._execute_tool_endpoint("crackmapexec")
    
    def evil_winrm(self):
        """Execute evil-winrm"""
        return self._execute_tool_endpoint("evil-winrm")
    
    def wireshark(self):
        """Execute wireshark/tshark"""
        return self._execute_tool_endpoint("wireshark")
    
    def tcpdump(self):
        """Execute tcpdump"""
        return self._execute_tool_endpoint("tcpdump")
    
    def ngrep(self):
        """Execute ngrep"""
        return self._execute_tool_endpoint("ngrep")
    
    def aircrack_ng(self):
        """Execute aircrack-ng"""
        return self._execute_tool_endpoint("aircrack-ng")
    
    def reaver(self):
        """Execute reaver WPS attack"""
        return self._execute_tool_endpoint("reaver")
    
    def kismet(self):
        """Execute kismet wireless detector"""
        return self._execute_tool_endpoint("kismet")
