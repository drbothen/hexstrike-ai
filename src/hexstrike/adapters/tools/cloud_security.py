"""
Cloud security tool adapters and integrations.

This module changes when cloud security tool integrations or cloud provider APIs change.
"""

from typing import Dict, Any, List
import json
import re
import logging
from .web_security import ToolAdapter
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

class KubeHunterAdapter(ToolAdapter):
    """Kube-hunter Kubernetes security scanner adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute kube-hunter scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="kube-hunter"
            )
        
        return self.execution_service.execute_tool("kube-hunter", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse kube-hunter output"""
        parsed = {
            "vulnerabilities": [],
            "services": [],
            "nodes": [],
            "total_vulnerabilities": 0,
            "severity_counts": {
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        try:
            if output.strip().startswith('{'):
                json_data = json.loads(output)
                
                if "vulnerabilities" in json_data:
                    for vuln in json_data["vulnerabilities"]:
                        severity = vuln.get("severity", "low").lower()
                        if severity in parsed["severity_counts"]:
                            parsed["severity_counts"][severity] += 1
                        
                        vulnerability = {
                            "vulnerability": vuln.get("vulnerability", ""),
                            "description": vuln.get("description", ""),
                            "severity": severity,
                            "category": vuln.get("category", ""),
                            "hunter": vuln.get("hunter", "")
                        }
                        
                        parsed["vulnerabilities"].append(vulnerability)
                
                if "services" in json_data:
                    parsed["services"] = json_data["services"]
                
                if "nodes" in json_data:
                    parsed["nodes"] = json_data["nodes"]
                
        except json.JSONDecodeError:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if "vulnerability" in line.lower() or "exposed" in line.lower():
                    vulnerability = {
                        "description": line,
                        "severity": "medium"
                    }
                    
                    if any(keyword in line.lower() for keyword in ["critical", "high", "dangerous"]):
                        vulnerability["severity"] = "high"
                        parsed["severity_counts"]["high"] += 1
                    elif any(keyword in line.lower() for keyword in ["low", "info"]):
                        vulnerability["severity"] = "low"
                        parsed["severity_counts"]["low"] += 1
                    else:
                        parsed["severity_counts"]["medium"] += 1
                    
                    parsed["vulnerabilities"].append(vulnerability)
        
        parsed["total_vulnerabilities"] = len(parsed["vulnerabilities"])
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate kube-hunter parameters"""
        return True
    
    def scan_kubernetes(self, target: str) -> Dict[str, Any]:
        """Scan Kubernetes cluster"""
        params = {
            "target": target,
            "remote": True
        }
        
        result = self.execute(params)
        return result.parsed_output

class CheckovAdapter(ToolAdapter):
    """Checkov infrastructure as code scanner adapter"""
    
    def execute(self, params: Dict[str, Any]) -> ExecutionResult:
        """Execute checkov scan"""
        if not self.validate_parameters(params):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Parameter validation failed",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name="checkov"
            )
        
        return self.execution_service.execute_tool("checkov", params)
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse checkov output"""
        parsed = {
            "passed_checks": 0,
            "failed_checks": 0,
            "skipped_checks": 0,
            "total_checks": 0,
            "compliance_score": 0.0,
            "failed_checks_details": [],
            "frameworks": []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            if "passed checks:" in line.lower():
                match = re.search(r'(\d+)', line)
                if match:
                    parsed["passed_checks"] = int(match.group(1))
            
            elif "failed checks:" in line.lower():
                match = re.search(r'(\d+)', line)
                if match:
                    parsed["failed_checks"] = int(match.group(1))
            
            elif "skipped checks:" in line.lower():
                match = re.search(r'(\d+)', line)
                if match:
                    parsed["skipped_checks"] = int(match.group(1))
            
            elif "FAILED" in line:
                failed_check = {
                    "check_id": "",
                    "description": line,
                    "file": "",
                    "severity": "medium"
                }
                
                check_match = re.search(r'CKV[_\w]+', line)
                if check_match:
                    failed_check["check_id"] = check_match.group(0)
                
                parsed["failed_checks_details"].append(failed_check)
        
        parsed["total_checks"] = parsed["passed_checks"] + parsed["failed_checks"] + parsed["skipped_checks"]
        
        if parsed["total_checks"] > 0:
            parsed["compliance_score"] = (parsed["passed_checks"] / parsed["total_checks"]) * 100
        
        return parsed
    
    def validate_parameters(self, params: Dict[str, Any]) -> bool:
        """Validate checkov parameters"""
        if "directory" not in params and "file" not in params:
            logger.error("Either 'directory' or 'file' parameter is required")
            return False
        
        return True
