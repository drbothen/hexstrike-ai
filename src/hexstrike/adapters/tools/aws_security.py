"""
AWS cloud security tool adapters.

This module changes when AWS security tool integrations change.
"""

from typing import Dict, Any, List
import json
import re
import logging
from .nmap_adapter import ToolAdapter
from ...services.tool_execution_service import ExecutionResult

logger = logging.getLogger(__name__)

class ProwlerAdapter(ToolAdapter):
    """Prowler cloud security assessment adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute prowler scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="prowler"
            )
        
        return self.execution_service.execute_tool("prowler", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse prowler output"""
        parsed = {
            "findings": [],
            "passed_checks": 0,
            "failed_checks": 0,
            "total_checks": 0,
            "compliance_score": 0.0,
            "services_scanned": []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if "PASS" in line:
                parsed["passed_checks"] += 1
            elif "FAIL" in line:
                parsed["failed_checks"] += 1
                
                finding = {
                    "status": "FAIL",
                    "check_id": "",
                    "description": line,
                    "severity": "medium"
                }
                
                check_match = re.search(r'([A-Z0-9_]+)', line)
                if check_match:
                    finding["check_id"] = check_match.group(1)
                
                parsed["findings"].append(finding)
            
            elif "Scanning" in line and "service" in line.lower():
                service_match = re.search(r'Scanning\s+([^\s]+)', line)
                if service_match:
                    service = service_match.group(1)
                    if service not in parsed["services_scanned"]:
                        parsed["services_scanned"].append(service)
        
        parsed["total_checks"] = parsed["passed_checks"] + parsed["failed_checks"]
        
        if parsed["total_checks"] > 0:
            parsed["compliance_score"] = (parsed["passed_checks"] / parsed["total_checks"]) * 100
        
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate prowler parameters"""
        return True
    
    def configure_aws_profile(self, profile: str, region: str) -> None:
        """Configure AWS profile for prowler"""
        logger.info(f"Configuring AWS profile: {profile} in region: {region}")

class TrivyAdapter(ToolAdapter):
    """Trivy vulnerability scanner adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute trivy scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="trivy"
            )
        
        return self.execution_service.execute_tool("trivy", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse trivy output"""
        parsed = {
            "vulnerabilities": [],
            "total_vulnerabilities": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0
            },
            "target": "",
            "scan_type": ""
        }
        
        try:
            if output.strip().startswith('{'):
                json_data = json.loads(output)
                
                if "Results" in json_data:
                    for result in json_data["Results"]:
                        if "Vulnerabilities" in result:
                            for vuln in result["Vulnerabilities"]:
                                severity = vuln.get("Severity", "UNKNOWN")
                                parsed["severity_counts"][severity] += 1
                                
                                vulnerability = {
                                    "vulnerability_id": vuln.get("VulnerabilityID", ""),
                                    "package_name": vuln.get("PkgName", ""),
                                    "installed_version": vuln.get("InstalledVersion", ""),
                                    "fixed_version": vuln.get("FixedVersion", ""),
                                    "severity": severity,
                                    "title": vuln.get("Title", ""),
                                    "description": vuln.get("Description", "")
                                }
                                
                                parsed["vulnerabilities"].append(vulnerability)
                
                parsed["total_vulnerabilities"] = len(parsed["vulnerabilities"])
                
        except json.JSONDecodeError:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if any(severity in line for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
                    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                        if severity in line:
                            parsed["severity_counts"][severity] += 1
                            
                            vulnerability = {
                                "vulnerability_id": "",
                                "severity": severity,
                                "description": line
                            }
                            
                            cve_match = re.search(r'(CVE-\d{4}-\d+)', line)
                            if cve_match:
                                vulnerability["vulnerability_id"] = cve_match.group(1)
                            
                            parsed["vulnerabilities"].append(vulnerability)
                            break
            
            parsed["total_vulnerabilities"] = len(parsed["vulnerabilities"])
        
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate trivy parameters"""
        required_params = ["target"]
        
        for param in required_params:
            if param not in params:
                logger.error(f"Missing required parameter: {param}")
                return False
        
        return True
    
    def scan_container(self, image: str) -> Dict[str, Any]:
        """Scan container image for vulnerabilities"""
        params = {
            "target": image,
            "scan_type": "image",
            "format": "json"
        }
        
        result = self.execute(params)
        return result.parsed_output
