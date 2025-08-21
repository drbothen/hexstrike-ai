"""
Tool output parsing logic.

This module changes when tool output parsing logic changes.
"""

from typing import Dict, Any, List
import re
import logging

logger = logging.getLogger(__name__)

class OutputParser:
    """Tool output parsing logic"""
    
    def parse_tool_output(self, tool_name: str, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        parsed = {"raw_output": output}
        
        if tool_name == "nmap":
            parsed.update(self._parse_nmap_output(output))
        elif tool_name == "nuclei":
            parsed.update(self._parse_nuclei_output(output))
        elif tool_name == "gobuster":
            parsed.update(self._parse_gobuster_output(output))
        elif tool_name == "sqlmap":
            parsed.update(self._parse_sqlmap_output(output))
        elif tool_name == "rustscan":
            parsed.update(self._parse_rustscan_output(output))
        elif tool_name == "subfinder":
            parsed.update(self._parse_subfinder_output(output))
        elif tool_name == "amass":
            parsed.update(self._parse_amass_output(output))
        elif tool_name == "hydra":
            parsed.update(self._parse_hydra_output(output))
        elif tool_name == "prowler":
            parsed.update(self._parse_prowler_output(output))
        
        return parsed
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        parsed = {
            "open_ports": [],
            "services": {},
            "os_detection": "",
            "script_results": []
        }
        
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    parsed["open_ports"].append(int(port))
                    parsed["services"][int(port)] = service
        
        return parsed
    
    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei output"""
        parsed = {
            "vulnerabilities": [],
            "total_requests": 0,
            "templates_loaded": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            if '[' in line and ']' in line:
                if any(sev in line.lower() for sev in ['info', 'low', 'medium', 'high', 'critical']):
                    parsed["vulnerabilities"].append({
                        "raw_line": line,
                        "severity": "unknown"
                    })
        
        return parsed
    
    def _parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        parsed = {
            "found_paths": [],
            "status_codes": {}
        }
        
        lines = output.split('\n')
        for line in lines:
            if 'Status:' in line:
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0]
                    status = parts[1].replace('Status:', '').strip()
                    parsed["found_paths"].append(path)
                    parsed["status_codes"][path] = status
        
        return parsed
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output"""
        parsed = {
            "injectable_parameters": [],
            "databases": [],
            "vulnerabilities": [],
            "is_vulnerable": False
        }
        
        if "is vulnerable" in output:
            parsed["is_vulnerable"] = True
            
        lines = output.split('\n')
        for line in lines:
            if "Parameter:" in line and "is vulnerable" in line:
                param_match = re.search(r"Parameter:\s*([^\s]+)", line)
                if param_match:
                    parsed["injectable_parameters"].append(param_match.group(1))
        
        return parsed
    
    def _parse_rustscan_output(self, output: str) -> Dict[str, Any]:
        """Parse rustscan output"""
        parsed = {
            "open_ports": [],
            "scan_time": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            if "Open" in line:
                port_match = re.search(r'(\d+)', line)
                if port_match:
                    parsed["open_ports"].append(int(port_match.group(1)))
        
        return parsed
    
    def _parse_subfinder_output(self, output: str) -> Dict[str, Any]:
        """Parse subfinder output"""
        parsed = {
            "subdomains": [],
            "total_found": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and '.' in line and not line.startswith('['):
                parsed["subdomains"].append(line)
        
        parsed["total_found"] = len(parsed["subdomains"])
        return parsed
    
    def _parse_amass_output(self, output: str) -> Dict[str, Any]:
        """Parse amass output"""
        parsed = {
            "subdomains": [],
            "total_found": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and '.' in line:
                parsed["subdomains"].append(line)
        
        parsed["total_found"] = len(parsed["subdomains"])
        return parsed
    
    def _parse_hydra_output(self, output: str) -> Dict[str, Any]:
        """Parse hydra output"""
        parsed = {
            "credentials_found": [],
            "attempts": 0,
            "success": False
        }
        
        lines = output.split('\n')
        for line in lines:
            if "login:" in line and "password:" in line:
                parsed["credentials_found"].append(line.strip())
                parsed["success"] = True
        
        return parsed
    
    def _parse_prowler_output(self, output: str) -> Dict[str, Any]:
        """Parse prowler output"""
        parsed = {
            "findings": [],
            "passed": 0,
            "failed": 0,
            "total_checks": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            if "PASS" in line:
                parsed["passed"] += 1
            elif "FAIL" in line:
                parsed["failed"] += 1
                parsed["findings"].append(line.strip())
        
        parsed["total_checks"] = parsed["passed"] + parsed["failed"]
        return parsed
