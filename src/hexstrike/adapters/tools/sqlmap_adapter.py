"""
SQLMap tool integration adapter.

This module changes when SQLMap tool integration changes.
"""

from typing import Dict, Any, List
import re
import logging
from .nmap_adapter import ToolAdapter
from ...services.tool_execution_service import ExecutionResult
from ...platform.validation import validator

logger = logging.getLogger(__name__)

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
