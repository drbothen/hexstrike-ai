"""
Attack chain templates for different target types.

This module changes when new attack chain templates are added.
"""

from typing import Dict, List
from dataclasses import dataclass
from ..domain.target_analysis import TargetType

@dataclass
class ChainTemplate:
    """Template for attack chain construction"""
    name: str
    target_types: List[TargetType]
    phases: List[Dict[str, any]]
    estimated_time: int
    success_probability: float
    risk_level: str

class AttackChainTemplates:
    """Manages attack chain templates for different scenarios"""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, ChainTemplate]:
        """Initialize attack chain templates"""
        templates = {}
        
        templates["web_comprehensive"] = ChainTemplate(
            name="Comprehensive Web Application Assessment",
            target_types=[TargetType.WEB_APPLICATION],
            phases=[
                {
                    "name": "reconnaissance",
                    "description": "Initial target reconnaissance",
                    "tools": ["nmap", "httpx", "katana"],
                    "parallel": True,
                    "estimated_time": 300,
                    "success_probability": 0.9
                },
                {
                    "name": "content_discovery",
                    "description": "Discover hidden content and endpoints",
                    "tools": ["gobuster", "dirsearch", "feroxbuster"],
                    "parallel": True,
                    "estimated_time": 600,
                    "success_probability": 0.8
                },
                {
                    "name": "vulnerability_scanning",
                    "description": "Automated vulnerability detection",
                    "tools": ["nuclei", "nikto"],
                    "parallel": True,
                    "estimated_time": 900,
                    "success_probability": 0.85
                },
                {
                    "name": "parameter_discovery",
                    "description": "Discover hidden parameters",
                    "tools": ["arjun", "paramspider"],
                    "parallel": False,
                    "estimated_time": 400,
                    "success_probability": 0.75
                },
                {
                    "name": "exploitation",
                    "description": "Exploit discovered vulnerabilities",
                    "tools": ["sqlmap", "dalfox"],
                    "parallel": False,
                    "estimated_time": 1200,
                    "success_probability": 0.6
                }
            ],
            estimated_time=3400,
            success_probability=0.7,
            risk_level="medium"
        )
        
        templates["network_comprehensive"] = ChainTemplate(
            name="Comprehensive Network Host Assessment",
            target_types=[TargetType.NETWORK_HOST],
            phases=[
                {
                    "name": "port_scanning",
                    "description": "Comprehensive port scanning",
                    "tools": ["nmap", "rustscan"],
                    "parallel": False,
                    "estimated_time": 600,
                    "success_probability": 0.95
                },
                {
                    "name": "service_enumeration",
                    "description": "Enumerate discovered services",
                    "tools": ["enum4linux-ng", "smbmap", "rpcclient"],
                    "parallel": True,
                    "estimated_time": 800,
                    "success_probability": 0.8
                },
                {
                    "name": "vulnerability_assessment",
                    "description": "Assess service vulnerabilities",
                    "tools": ["nuclei", "nmap-advanced"],
                    "parallel": True,
                    "estimated_time": 1000,
                    "success_probability": 0.75
                },
                {
                    "name": "credential_attacks",
                    "description": "Attempt credential-based attacks",
                    "tools": ["hydra", "responder"],
                    "parallel": False,
                    "estimated_time": 1800,
                    "success_probability": 0.5
                }
            ],
            estimated_time=4200,
            success_probability=0.65,
            risk_level="high"
        )
        
        templates["api_comprehensive"] = ChainTemplate(
            name="Comprehensive API Assessment",
            target_types=[TargetType.API_ENDPOINT],
            phases=[
                {
                    "name": "endpoint_discovery",
                    "description": "Discover API endpoints",
                    "tools": ["katana", "gau", "waybackurls"],
                    "parallel": True,
                    "estimated_time": 400,
                    "success_probability": 0.85
                },
                {
                    "name": "parameter_discovery",
                    "description": "Discover API parameters",
                    "tools": ["arjun", "x8", "paramspider"],
                    "parallel": True,
                    "estimated_time": 500,
                    "success_probability": 0.8
                },
                {
                    "name": "vulnerability_testing",
                    "description": "Test for API vulnerabilities",
                    "tools": ["nuclei", "jaeles"],
                    "parallel": True,
                    "estimated_time": 700,
                    "success_probability": 0.7
                }
            ],
            estimated_time=1600,
            success_probability=0.75,
            risk_level="medium"
        )
        
        templates["cloud_comprehensive"] = ChainTemplate(
            name="Comprehensive Cloud Security Assessment",
            target_types=[TargetType.CLOUD_SERVICE],
            phases=[
                {
                    "name": "configuration_assessment",
                    "description": "Assess cloud configuration",
                    "tools": ["prowler", "scout-suite"],
                    "parallel": True,
                    "estimated_time": 1200,
                    "success_probability": 0.9
                },
                {
                    "name": "container_scanning",
                    "description": "Scan containers and images",
                    "tools": ["trivy", "clair"],
                    "parallel": True,
                    "estimated_time": 800,
                    "success_probability": 0.85
                },
                {
                    "name": "kubernetes_assessment",
                    "description": "Assess Kubernetes security",
                    "tools": ["kube-hunter", "kube-bench"],
                    "parallel": True,
                    "estimated_time": 600,
                    "success_probability": 0.8
                },
                {
                    "name": "iac_scanning",
                    "description": "Scan Infrastructure as Code",
                    "tools": ["checkov", "terrascan"],
                    "parallel": True,
                    "estimated_time": 400,
                    "success_probability": 0.9
                }
            ],
            estimated_time=3000,
            success_probability=0.8,
            risk_level="high"
        )
        
        return templates
    
    def get_template(self, name: str) -> ChainTemplate:
        """Get template by name"""
        return self.templates.get(name)
    
    def get_templates_for_target_type(self, target_type: TargetType) -> List[ChainTemplate]:
        """Get all templates for target type"""
        return [template for template in self.templates.values() 
                if target_type in template.target_types]
    
    def list_template_names(self) -> List[str]:
        """List all template names"""
        return list(self.templates.keys())
