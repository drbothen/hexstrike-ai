"""
Tool output parsing service.

This module changes when tool output formats change.
"""

from typing import Dict, Any
import json
import re
import logging

logger = logging.getLogger(__name__)

class ResultParser:
    """Parse tool outputs into structured data"""
    
    def parse_tool_output(self, tool: str, output: str) -> Dict[str, Any]:
        """Parse output based on tool type"""
        if tool == "nmap":
            return self._parse_nmap_output(output)
        elif tool == "gobuster":
            return self._parse_gobuster_output(output)
        elif tool == "nuclei":
            return self._parse_nuclei_output(output)
        elif tool == "sqlmap":
            return self._parse_sqlmap_output(output)
        elif tool == "hydra":
            return self._parse_hydra_output(output)
        elif tool == "rustscan":
            return self._parse_rustscan_output(output)
        elif tool == "amass":
            return self._parse_amass_output(output)
        elif tool == "prowler":
            return self._parse_prowler_output(output)
        elif tool == "ghidra":
            return self._parse_ghidra_output(output)
        else:
            return {"raw_output": output}
    
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
            line = line.strip()
            
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    
                    if '/' in port_info:
                        port = int(port_info.split('/')[0])
                        parsed["open_ports"].append(port)
                        parsed["services"][port] = service
            
            elif "OS details:" in line:
                parsed["os_detection"] = line.replace("OS details:", "").strip()
            
            elif line.startswith("|"):
                parsed["script_results"].append(line)
        
        return parsed
    
    def _parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        parsed = {
            "found_paths": [],
            "status_codes": {}
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
        
        return parsed
    
    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei output"""
        parsed = {
            "vulnerabilities": [],
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
                            "raw_line": line
                        }
                        
                        parsed["vulnerabilities"].append(vulnerability)
        
        return parsed
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output"""
        parsed = {
            "injectable_parameters": [],
            "databases": [],
            "is_vulnerable": False
        }
        
        if "is vulnerable" in output:
            parsed["is_vulnerable"] = True
        
        return parsed
    
    def _parse_hydra_output(self, output: str) -> Dict[str, Any]:
        """Parse hydra output"""
        parsed = {
            "credentials": [],
            "successful_logins": 0
        }
        
        lines = output.split('\n')
        
        for line in lines:
            if "login:" in line and "password:" in line:
                parsed["credentials"].append(line.strip())
                parsed["successful_logins"] += 1
        
        return parsed
    
    def _parse_rustscan_output(self, output: str) -> Dict[str, Any]:
        """Parse rustscan output"""
        parsed = {
            "open_ports": [],
            "scan_time": 0.0
        }
        
        lines = output.split('\n')
        
        for line in lines:
            if "Open" in line:
                port_match = re.search(r'(\d+)', line)
                if port_match:
                    parsed["open_ports"].append(int(port_match.group(1)))
        
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
    
    def _parse_prowler_output(self, output: str) -> Dict[str, Any]:
        """Parse prowler output"""
        parsed = {
            "findings": [],
            "passed_checks": 0,
            "failed_checks": 0
        }
        
        lines = output.split('\n')
        
        for line in lines:
            if "PASS" in line:
                parsed["passed_checks"] += 1
            elif "FAIL" in line:
                parsed["failed_checks"] += 1
                parsed["findings"].append(line.strip())
        
        return parsed
    
    def _parse_ghidra_output(self, output: str) -> Dict[str, Any]:
        """Parse ghidra output"""
        parsed = {
            "analysis_complete": False,
            "functions_found": 0,
            "strings_found": 0
        }
        
        if "Analysis complete" in output:
            parsed["analysis_complete"] = True
        
        return parsed
