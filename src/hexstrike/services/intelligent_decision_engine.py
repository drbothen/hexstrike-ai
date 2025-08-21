"""
Core intelligent decision engine for AI-powered tool selection and optimization.

This module changes when decision algorithms or tool effectiveness models change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging
from ..domain.target_analysis import TargetType, TargetProfile

logger = logging.getLogger(__name__)

@dataclass
class AttackStep:
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int
    dependencies: List[str] = field(default_factory=list)

class AttackChain:
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability = 0.0
        self.estimated_time = 0
        self.required_tools = set()
        self.risk_level = "unknown"
    
    def add_step(self, step: AttackStep):
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.calculate_success_probability()
    
    def calculate_success_probability(self):
        if not self.steps:
            self.success_probability = 0.0
            return
        
        total_probability = 1.0
        for step in self.steps:
            total_probability *= step.success_probability
        
        self.success_probability = total_probability
        self.estimated_time = sum(step.execution_time_estimate for step in self.steps)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }

class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine"""
    
    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
        self._use_advanced_optimizer = True
        
    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness ratings for different target types"""
        return {
            TargetType.WEB_APPLICATION.value: {
                "nmap": 0.8, "gobuster": 0.9, "nuclei": 0.95, "nikto": 0.85,
                "sqlmap": 0.9, "ffuf": 0.9, "feroxbuster": 0.85, "katana": 0.88,
                "httpx": 0.85, "wpscan": 0.95, "burpsuite": 0.9, "dirsearch": 0.87,
                "gau": 0.82, "waybackurls": 0.8, "arjun": 0.9, "paramspider": 0.85,
                "x8": 0.88, "jaeles": 0.92, "dalfox": 0.93, "anew": 0.7,
                "qsreplace": 0.75, "uro": 0.7
            },
            TargetType.NETWORK_HOST.value: {
                "nmap": 0.95, "nmap-advanced": 0.97, "masscan": 0.92, "rustscan": 0.9,
                "autorecon": 0.95, "enum4linux": 0.8, "enum4linux-ng": 0.88,
                "smbmap": 0.85, "rpcclient": 0.82, "nbtscan": 0.75, "arp-scan": 0.85,
                "responder": 0.88, "hydra": 0.8, "netexec": 0.85, "amass": 0.7
            },
            TargetType.API_ENDPOINT.value: {
                "nuclei": 0.9, "ffuf": 0.85, "arjun": 0.95, "paramspider": 0.88,
                "httpx": 0.9, "x8": 0.92, "katana": 0.85, "jaeles": 0.88, "postman": 0.8
            },
            TargetType.CLOUD_SERVICE.value: {
                "prowler": 0.95, "scout-suite": 0.92, "cloudmapper": 0.88, "pacu": 0.85,
                "trivy": 0.9, "clair": 0.85, "kube-hunter": 0.9, "kube-bench": 0.88,
                "docker-bench-security": 0.85, "falco": 0.87, "checkov": 0.9, "terrascan": 0.88
            }
        }
    
    def _initialize_technology_signatures(self) -> Dict[str, List[str]]:
        """Initialize technology detection signatures"""
        return {
            "wordpress": ["wp-content", "wp-admin", "wp-includes", "xmlrpc.php"],
            "drupal": ["sites/default", "misc/drupal.js", "modules/", "themes/"],
            "joomla": ["administrator/", "components/", "modules/", "templates/"],
            "apache": ["Server: Apache", "apache", "httpd"],
            "nginx": ["Server: nginx", "nginx"],
            "iis": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"],
            "php": ["X-Powered-By: PHP", ".php", "PHPSESSID"],
            "asp": ["X-Powered-By: ASP.NET", ".aspx", "ASP.NET_SessionId"],
            "nodejs": ["X-Powered-By: Express", "node.js", "express"],
            "python": ["Server: gunicorn", "django", "flask"],
            "java": ["jsessionid", "X-Powered-By: Servlet", "tomcat"]
        }
    
    def _initialize_attack_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize attack patterns for different scenarios"""
        return {
            "web_application": [
                {"phase": "reconnaissance", "tools": ["nmap", "httpx", "katana"], "parallel": True},
                {"phase": "content_discovery", "tools": ["gobuster", "dirsearch", "feroxbuster"], "parallel": True},
                {"phase": "vulnerability_scanning", "tools": ["nuclei", "nikto"], "parallel": True},
                {"phase": "parameter_discovery", "tools": ["arjun", "paramspider"], "parallel": False},
                {"phase": "exploitation", "tools": ["sqlmap", "dalfox"], "parallel": False}
            ],
            "network_host": [
                {"phase": "port_scanning", "tools": ["nmap", "rustscan"], "parallel": False},
                {"phase": "service_enumeration", "tools": ["enum4linux-ng", "smbmap"], "parallel": True},
                {"phase": "vulnerability_assessment", "tools": ["nuclei", "nmap-advanced"], "parallel": True},
                {"phase": "credential_attacks", "tools": ["hydra", "responder"], "parallel": False}
            ],
            "api_endpoint": [
                {"phase": "endpoint_discovery", "tools": ["katana", "gau"], "parallel": True},
                {"phase": "parameter_discovery", "tools": ["arjun", "x8"], "parallel": True},
                {"phase": "vulnerability_testing", "tools": ["nuclei", "jaeles"], "parallel": True}
            ]
        }
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        from .target_analyzer import TargetAnalyzer
        
        analyzer = TargetAnalyzer()
        return analyzer.analyze_target(target)
    
    def select_optimal_tools(self, target_profile: TargetProfile, objective: str = "comprehensive") -> List[str]:
        """Select optimal tools based on target profile and objective"""
        target_type = target_profile.target_type.value
        effectiveness_scores = self.tool_effectiveness.get(target_type, {})
        
        if objective == "fast":
            threshold = 0.8
        elif objective == "comprehensive":
            threshold = 0.6
        else:
            threshold = 0.7
        
        selected_tools = [
            tool for tool, score in effectiveness_scores.items()
            if score >= threshold
        ]
        
        selected_tools.sort(key=lambda t: effectiveness_scores.get(t, 0), reverse=True)
        
        return selected_tools[:10]
    
    def optimize_parameters(self, tool_name: str, target_profile: TargetProfile) -> Dict[str, Any]:
        """Optimize tool parameters based on target profile and context"""
        from .tool_effectiveness_manager import ToolEffectivenessManager
        
        if not self._use_advanced_optimizer:
            return {"target": target_profile.target}
        
        tool_manager = ToolEffectivenessManager()
        return tool_manager.optimize_parameters(tool_name, target_profile)
    
    def enable_advanced_optimization(self):
        self._use_advanced_optimizer = True
    
    def disable_advanced_optimization(self):
        self._use_advanced_optimizer = False
    
    def create_attack_chain(self, target_profile: TargetProfile, objective: str = "comprehensive") -> AttackChain:
        """Create an intelligent attack chain based on target profile"""
        chain = AttackChain(target_profile)
        
        target_type_key = target_profile.target_type.value.replace("_", "_").lower()
        if target_type_key == "web_application":
            pattern_key = "web_application"
        elif target_type_key == "network_host":
            pattern_key = "network_host"
        elif target_type_key == "api_endpoint":
            pattern_key = "api_endpoint"
        else:
            pattern_key = "web_application"
        
        attack_pattern = self.attack_patterns.get(pattern_key, [])
        
        for phase in attack_pattern:
            tools = phase["tools"]
            primary_tool = tools[0] if tools else "nmap"
            
            optimized_params = self.optimize_parameters(primary_tool, target_profile)
            
            step = AttackStep(
                tool=primary_tool,
                parameters=optimized_params,
                expected_outcome=f"Complete {phase['phase']} phase",
                success_probability=0.8,
                execution_time_estimate=300,
                dependencies=[]
            )
            
            chain.add_step(step)
        
        chain.risk_level = target_profile.risk_level
        return chain
