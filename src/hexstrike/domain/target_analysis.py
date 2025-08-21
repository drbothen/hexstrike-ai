"""
Target classification and analysis domain logic.

This module changes when target classification rules change.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert TargetProfile to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }
    
    def calculate_attack_surface(self) -> float:
        """Calculate attack surface score based on exposed services and technologies"""
        score = 0.0
        
        type_scores = {
            TargetType.WEB_APPLICATION: 3.0,
            TargetType.API_ENDPOINT: 2.5,
            TargetType.NETWORK_HOST: 2.0,
            TargetType.CLOUD_SERVICE: 3.5,
            TargetType.MOBILE_APP: 1.5,
            TargetType.BINARY_FILE: 1.0,
            TargetType.UNKNOWN: 1.0
        }
        score += type_scores.get(self.target_type, 1.0)
        
        score += len(self.open_ports) * 0.1
        
        high_risk_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 6379]
        for port in self.open_ports:
            if port in high_risk_ports:
                score += 0.5
        
        web_ports = [80, 443, 8080, 8443, 8000, 8888, 9000]
        if any(port in web_ports for port in self.open_ports):
            score += 1.0
        
        risky_technologies = [
            TechnologyStack.PHP,
            TechnologyStack.WORDPRESS,
            TechnologyStack.DRUPAL,
            TechnologyStack.JOOMLA
        ]
        for tech in self.technologies:
            if tech in risky_technologies:
                score += 0.5
            else:
                score += 0.2
        
        security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options', 'strict-transport-security']
        present_headers = sum(1 for header in security_headers if header.lower() in [h.lower() for h in self.security_headers.keys()])
        score -= present_headers * 0.2
        
        if self.ssl_info.get('valid', False):
            score -= 0.5
        
        self.attack_surface_score = max(0.0, score)
        return self.attack_surface_score
    
    def assess_risk_level(self) -> str:
        """Assess risk level based on attack surface and other factors"""
        if self.attack_surface_score == 0:
            self.calculate_attack_surface()
        
        if self.attack_surface_score >= 5.0:
            risk = "critical"
        elif self.attack_surface_score >= 3.5:
            risk = "high"
        elif self.attack_surface_score >= 2.0:
            risk = "medium"
        elif self.attack_surface_score >= 1.0:
            risk = "low"
        else:
            risk = "minimal"
        
        self.risk_level = risk
        return risk
