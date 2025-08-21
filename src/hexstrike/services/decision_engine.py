"""
Core decision engine for tool selection and target analysis.

This module changes when decision algorithms or target analysis logic changes.
"""

from typing import Dict, Any, List, Optional, Set
import logging
from ..domain.target_analysis import TargetProfile, TargetType, TechnologyStack

logger = logging.getLogger(__name__)

class DecisionEngine:
    """Core decision engine for tool selection"""
    
    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
    
    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness scores for different target types"""
        return {
            "nmap": {
                "network_host": 0.95,
                "web_application": 0.85,
                "api_endpoint": 0.80,
                "cloud_service": 0.75,
                "mobile_app": 0.30,
                "binary_file": 0.10
            },
            "gobuster": {
                "web_application": 0.90,
                "api_endpoint": 0.85,
                "network_host": 0.20,
                "cloud_service": 0.70,
                "mobile_app": 0.15,
                "binary_file": 0.05
            },
            "nuclei": {
                "web_application": 0.95,
                "api_endpoint": 0.90,
                "network_host": 0.60,
                "cloud_service": 0.85,
                "mobile_app": 0.25,
                "binary_file": 0.10
            },
            "sqlmap": {
                "web_application": 0.85,
                "api_endpoint": 0.80,
                "network_host": 0.10,
                "cloud_service": 0.60,
                "mobile_app": 0.20,
                "binary_file": 0.05
            },
            "hydra": {
                "network_host": 0.80,
                "web_application": 0.70,
                "api_endpoint": 0.60,
                "cloud_service": 0.75,
                "mobile_app": 0.30,
                "binary_file": 0.05
            },
            "rustscan": {
                "network_host": 0.90,
                "web_application": 0.75,
                "api_endpoint": 0.70,
                "cloud_service": 0.80,
                "mobile_app": 0.25,
                "binary_file": 0.10
            },
            "amass": {
                "web_application": 0.85,
                "api_endpoint": 0.80,
                "network_host": 0.40,
                "cloud_service": 0.75,
                "mobile_app": 0.20,
                "binary_file": 0.05
            },
            "prowler": {
                "cloud_service": 0.95,
                "web_application": 0.30,
                "api_endpoint": 0.40,
                "network_host": 0.20,
                "mobile_app": 0.10,
                "binary_file": 0.05
            },
            "ghidra": {
                "binary_file": 0.95,
                "mobile_app": 0.80,
                "network_host": 0.10,
                "web_application": 0.15,
                "api_endpoint": 0.10,
                "cloud_service": 0.05
            }
        }
    
    def _initialize_technology_signatures(self) -> Dict[str, List[str]]:
        """Initialize technology detection signatures"""
        return {
            "wordpress": ["wp-content", "wp-admin", "wp-includes"],
            "drupal": ["sites/default", "modules", "themes"],
            "joomla": ["administrator", "components", "modules"],
            "apache": ["Server: Apache", "apache"],
            "nginx": ["Server: nginx", "nginx"],
            "iis": ["Server: Microsoft-IIS", "X-Powered-By: ASP.NET"]
        }
    
    def _initialize_attack_patterns(self) -> Dict[str, List[str]]:
        """Initialize attack pattern mappings"""
        return {
            "web_application": ["directory_traversal", "xss", "sql_injection", "csrf"],
            "api_endpoint": ["injection", "broken_auth", "data_exposure"],
            "network_host": ["port_scan", "service_enum", "brute_force"],
            "cloud_service": ["misconfig", "iam_issues", "storage_exposure"],
            "mobile_app": ["reverse_engineering", "crypto_issues", "data_leakage"],
            "binary_file": ["buffer_overflow", "format_string", "rop_chain"]
        }
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create profile"""
        target_type = self._determine_target_type(target)
        technologies = self._detect_technologies(target)
        
        return TargetProfile(
            target=target,
            target_type=target_type,
            technologies=technologies,
            attack_surface=self._calculate_attack_surface(target_type, technologies),
            risk_level=self._determine_risk_level(target_type),
            confidence=self._calculate_confidence(target, target_type)
        )
    
    def select_optimal_tools(self, target_profile: TargetProfile, max_tools: int = 5) -> List[str]:
        """Select optimal tools for target"""
        target_type_str = target_profile.target_type.value
        
        tool_scores = []
        for tool, effectiveness in self.tool_effectiveness.items():
            score = effectiveness.get(target_type_str, 0.0)
            
            if target_profile.technologies:
                for tech in target_profile.technologies:
                    if tech.name.lower() in ["wordpress", "drupal", "joomla"] and tool in ["nuclei", "gobuster"]:
                        score += 0.1
                    elif tech.name.lower() in ["apache", "nginx"] and tool == "nmap":
                        score += 0.05
            
            tool_scores.append((tool, score))
        
        tool_scores.sort(key=lambda x: x[1], reverse=True)
        return [tool for tool, score in tool_scores[:max_tools] if score > 0.3]
    
    def _determine_target_type(self, target: str) -> TargetType:
        """Determine target type from target string"""
        if target.startswith(("http://", "https://")):
            if "/api/" in target or target.endswith("/api"):
                return TargetType.API_ENDPOINT
            return TargetType.WEB_APPLICATION
        elif target.endswith((".exe", ".bin", ".elf", ".apk")):
            if target.endswith(".apk"):
                return TargetType.MOBILE_APP
            return TargetType.BINARY_FILE
        elif "amazonaws.com" in target or "azure.com" in target or "googleapis.com" in target:
            return TargetType.CLOUD_SERVICE
        else:
            return TargetType.NETWORK_HOST
    
    def _detect_technologies(self, target: str) -> List[TechnologyStack]:
        """Detect technologies from target"""
        technologies = []
        
        for tech, signatures in self.technology_signatures.items():
            for signature in signatures:
                if signature.lower() in target.lower():
                    technologies.append(TechnologyStack(
                        name=tech,
                        version="unknown",
                        confidence=0.7
                    ))
                    break
        
        return technologies
    
    def _calculate_attack_surface(self, target_type: TargetType, technologies: List[TechnologyStack]) -> float:
        """Calculate attack surface score"""
        base_score = {
            TargetType.WEB_APPLICATION: 0.8,
            TargetType.API_ENDPOINT: 0.7,
            TargetType.NETWORK_HOST: 0.6,
            TargetType.CLOUD_SERVICE: 0.9,
            TargetType.MOBILE_APP: 0.5,
            TargetType.BINARY_FILE: 0.4
        }.get(target_type, 0.5)
        
        tech_modifier = len(technologies) * 0.1
        return min(base_score + tech_modifier, 1.0)
    
    def _determine_risk_level(self, target_type: TargetType) -> str:
        """Determine risk level based on target type"""
        risk_mapping = {
            TargetType.WEB_APPLICATION: "medium",
            TargetType.API_ENDPOINT: "high",
            TargetType.NETWORK_HOST: "medium",
            TargetType.CLOUD_SERVICE: "high",
            TargetType.MOBILE_APP: "low",
            TargetType.BINARY_FILE: "low"
        }
        return risk_mapping.get(target_type, "medium")
    
    def _calculate_confidence(self, target: str, target_type: TargetType) -> float:
        """Calculate confidence in target analysis"""
        confidence = 0.5
        
        if target.startswith(("http://", "https://")) and target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            confidence += 0.3
        
        if any(domain in target for domain in ["amazonaws.com", "azure.com", "googleapis.com"]) and target_type == TargetType.CLOUD_SERVICE:
            confidence += 0.4
        
        return min(confidence, 1.0)
    
    def calculate_tool_effectiveness(self, tool: str, target_type: str) -> float:
        """Calculate effectiveness score for tool and target type"""
        return self.tool_effectiveness.get(tool, {}).get(target_type, 0.0)
    
    def update_tool_effectiveness(self, tool: str, target_type: str, new_score: float) -> None:
        """Update tool effectiveness score"""
        if tool not in self.tool_effectiveness:
            self.tool_effectiveness[tool] = {}
        self.tool_effectiveness[tool][target_type] = new_score
        logger.info(f"Updated {tool} effectiveness for {target_type}: {new_score}")
