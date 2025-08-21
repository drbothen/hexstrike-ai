"""
Nmap tool adapter for network scanning.

This module changes when Nmap integration or parameter mappings change.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import re
import logging
from ...services.tool_execution_service import ExecutionResult, ToolExecutionService
from ...platform.validation import validator

logger = logging.getLogger(__name__)

class ToolAdapter(ABC):
    """Base adapter interface for all tools"""
    
    def __init__(self, execution_service: ToolExecutionService):
        self.execution_service = execution_service
    
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute tool with parameters"""
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        pass
    
    @abstractmethod
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate tool parameters"""
        pass

class NmapAdapter(ToolAdapter):
    """Nmap tool integration adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute nmap scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="nmap"
            )
        
        return self.execution_service.execute_tool("nmap", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        parsed = {
            "open_ports": [],
            "services": {},
            "os_detection": "",
            "script_results": [],
            "host_status": "unknown"
        }
        
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            if "Host is up" in line:
                parsed["host_status"] = "up"
            elif "Host seems down" in line:
                parsed["host_status"] = "down"
            
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    if '/' in port_info:
                        port = int(port_info.split('/')[0])
                        parsed["open_ports"].append(port)
                        parsed["services"][port] = {
                            "service": service,
                            "state": state,
                            "version": parts[3] if len(parts) > 3 else ""
                        }
            
            if "OS details:" in line:
                parsed["os_detection"] = line.replace("OS details:", "").strip()
            
            if line.startswith("|"):
                parsed["script_results"].append(line)
        
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate nmap parameters"""
        required_params = ["target"]
        
        for param in required_params:
            if param not in params:
                logger.error(f"Missing required parameter: {param}")
                return False
        
        target_result = validator.validate_domain(params["target"])
        if not target_result.is_valid:
            ip_result = validator.validate_ip_address(params["target"])
            if not ip_result.is_valid:
                logger.error(f"Invalid target: {params['target']}")
                return False
        
        return True
    
    def get_default_parameters(self, target_type: str) -> Dict[str, Any]:
        """Get default parameters for target type"""
        defaults = {
            "scan_type": "-sV -sC",
            "additional_args": "-T4 -Pn",
            "timeout": 300
        }
        
        if target_type == "web_application":
            defaults["ports"] = "80,443,8080,8443,8000,8888"
        elif target_type == "network_host":
            defaults["ports"] = "1-1000"
            defaults["scan_type"] = "-sS -sV -sC"
        
        return defaults
