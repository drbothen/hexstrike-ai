"""
Web scanning tool adapters (Gobuster, Nuclei, SQLMap).

This module changes when web scanning tool integrations change.
"""

from typing import Dict, Any, List
import re
import logging
from .nmap_adapter import ToolAdapter
from ...services.tool_execution_service import ExecutionResult
from ...platform.validation import validator

logger = logging.getLogger(__name__)

class GobusterAdapter(ToolAdapter):
    """Gobuster tool integration adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute gobuster scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="gobuster"
            )
        
        return self.execution_service.execute_tool("gobuster", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        parsed = {
            "found_paths": [],
            "status_codes": {},
            "total_requests": 0,
            "errors": []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('/') and '(Status:' in line:
                match = re.search(r'^(/[^\s]*)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    path = match.group(1)
                    status_code = int(match.group(2))
                    
                    parsed["found_paths"].append(path)
                    parsed["status_codes"][path] = status_code
            
            elif "Progress:" in line:
                match = re.search(r'Progress:\s*(\d+)', line)
                if match:
                    parsed["total_requests"] = int(match.group(1))
            
            elif "Error:" in line or "error" in line.lower():
                parsed["errors"].append(line)
        
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate gobuster parameters"""
        required_params = ["target"]
        
        for param in required_params:
            if param not in params:
                logger.error(f"Missing required parameter: {param}")
                return False
        
        url_result = validator.validate_url(params["target"])
        if not url_result.is_valid:
            logger.error(f"Invalid URL: {params['target']}")
            return False
        
        if "mode" in params:
            valid_modes = ["dir", "dns", "fuzz", "vhost"]
            if params["mode"] not in valid_modes:
                logger.error(f"Invalid mode: {params['mode']}")
                return False
        
        return True

class NucleiAdapter(ToolAdapter):
    """Nuclei vulnerability scanner adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute nuclei scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="nuclei"
            )
        
        return self.execution_service.execute_tool("nuclei", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei output"""
        parsed = {
            "vulnerabilities": [],
            "total_templates": 0,
            "total_requests": 0,
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if '[' in line and ']' in line:
                severity_match = re.search(r'\[([^\]]+)\]', line)
                if severity_match:
                    severity = severity_match.group(1).lower()
                    
                    if severity in parsed["findings_by_severity"]:
                        parsed["findings_by_severity"][severity] += 1
                        
                        vulnerability = {
                            "severity": severity,
                            "raw_line": line,
                            "template": "",
                            "url": ""
                        }
                        
                        template_match = re.search(r'\[([^\]]+)\]\s+\[([^\]]+)\]', line)
                        if template_match:
                            vulnerability["template"] = template_match.group(2)
                        
                        url_match = re.search(r'(https?://[^\s]+)', line)
                        if url_match:
                            vulnerability["url"] = url_match.group(1)
                        
                        parsed["vulnerabilities"].append(vulnerability)
            
            elif "Templates loaded" in line:
                match = re.search(r'(\d+)', line)
                if match:
                    parsed["total_templates"] = int(match.group(1))
            
            elif "requests" in line and "made" in line:
                match = re.search(r'(\d+)\s+requests', line)
                if match:
                    parsed["total_requests"] = int(match.group(1))
        
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate nuclei parameters"""
        required_params = ["target"]
        
        for param in required_params:
            if param not in params:
                logger.error(f"Missing required parameter: {param}")
                return False
        
        url_result = validator.validate_url(params["target"])
        if not url_result.is_valid:
            logger.error(f"Invalid URL: {params['target']}")
            return False
        
        if "severity" in params:
            valid_severities = ["critical", "high", "medium", "low", "info"]
            severities = params["severity"].split(",")
            for sev in severities:
                if sev.strip() not in valid_severities:
                    logger.error(f"Invalid severity: {sev}")
                    return False
        
        return True
    
    def get_template_categories(self) -> List[str]:
        """Get available template categories"""
        return [
            "cve", "oast", "default-logins", "exposures", "misconfiguration",
            "takeovers", "vulnerabilities", "workflows", "file", "dns",
            "http", "network", "ssl"
        ]

class SqlmapAdapter(ToolAdapter):
    """SQLMap tool integration adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute sqlmap scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="sqlmap"
            )
        
        return self.execution_service.execute_tool("sqlmap", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output"""
        parsed = {
            "injectable_parameters": [],
            "databases": [],
            "tables": [],
            "vulnerabilities": [],
            "injection_types": [],
            "dbms": "",
            "is_vulnerable": False
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if "Parameter:" in line and "is vulnerable" in line:
                param_match = re.search(r"Parameter:\s*([^\s]+)", line)
                if param_match:
                    parsed["injectable_parameters"].append(param_match.group(1))
                    parsed["is_vulnerable"] = True
            
            elif "back-end DBMS:" in line:
                dbms_match = re.search(r"back-end DBMS:\s*([^\n]+)", line)
                if dbms_match:
                    parsed["dbms"] = dbms_match.group(1).strip()
            
            elif "Type:" in line:
                type_match = re.search(r"Type:\s*([^\n]+)", line)
                if type_match:
                    parsed["injection_types"].append(type_match.group(1).strip())
            
            elif "available databases" in line.lower():
                parsed["databases"] = self._extract_list_items(lines, lines.index(line))
            
            elif "database tables" in line.lower():
                parsed["tables"] = self._extract_list_items(lines, lines.index(line))
        
        return parsed
    
    def _extract_list_items(self, lines: List[str], start_index: int) -> List[str]:
        """Extract list items from sqlmap output"""
        items = []
        for i in range(start_index + 1, len(lines)):
            line = lines[i].strip()
            if line.startswith('[') and line.endswith(']'):
                content = line[1:-1]
                items.extend([item.strip() for item in content.split(',')])
                break
            elif line.startswith('*') or line.startswith('-'):
                item = line[1:].strip()
                if item:
                    items.append(item)
            elif not line or line.startswith('['):
                break
        
        return items
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate sqlmap parameters"""
        required_params = ["target"]
        
        for param in required_params:
            if param not in params:
                logger.error(f"Missing required parameter: {param}")
                return False
        
        url_result = validator.validate_url(params["target"])
        if not url_result.is_valid:
            logger.error(f"Invalid URL: {params['target']}")
            return False
        
        return True
    
    def detect_sql_injection(self, output: str) -> List[Dict[str, Any]]:
        """Detect SQL injection vulnerabilities from output"""
        vulnerabilities = []
        
        if "is vulnerable" in output:
            vulnerabilities.append({
                "type": "sql_injection",
                "severity": "high",
                "description": "SQL injection vulnerability detected",
                "evidence": output
            })
        
        return vulnerabilities
