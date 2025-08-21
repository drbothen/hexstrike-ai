"""
Target classification and analysis domain logic.

This module changes when target classification rules or analysis algorithms change.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import ipaddress
import urllib.parse
import logging

logger = logging.getLogger(__name__)

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

class TargetAnalyzer:
    """Target analysis orchestration logic"""
    
    def __init__(self):
        self.technology_signatures = self._initialize_technology_signatures()
        self.cloud_providers = self._initialize_cloud_providers()
    
    def _initialize_technology_signatures(self) -> Dict[str, TechnologyStack]:
        """Initialize technology detection signatures"""
        return {
            "apache": TechnologyStack.APACHE,
            "nginx": TechnologyStack.NGINX,
            "iis": TechnologyStack.IIS,
            "node.js": TechnologyStack.NODEJS,
            "nodejs": TechnologyStack.NODEJS,
            "php": TechnologyStack.PHP,
            "python": TechnologyStack.PYTHON,
            "java": TechnologyStack.JAVA,
            "asp.net": TechnologyStack.DOTNET,
            "wordpress": TechnologyStack.WORDPRESS,
            "drupal": TechnologyStack.DRUPAL,
            "joomla": TechnologyStack.JOOMLA,
            "react": TechnologyStack.REACT,
            "angular": TechnologyStack.ANGULAR,
            "vue": TechnologyStack.VUE
        }
    
    def _initialize_cloud_providers(self) -> Dict[str, str]:
        """Initialize cloud provider detection patterns"""
        return {
            "amazonaws.com": "AWS",
            "cloudfront.net": "AWS",
            "s3.amazonaws.com": "AWS",
            "azure.com": "Microsoft Azure",
            "azurewebsites.net": "Microsoft Azure",
            "googleapis.com": "Google Cloud",
            "googleusercontent.com": "Google Cloud",
            "appspot.com": "Google Cloud",
            "digitalocean.com": "DigitalOcean",
            "heroku.com": "Heroku",
            "cloudflare.com": "Cloudflare"
        }
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        profile = TargetProfile(target=target)
        
        # Determine target type
        profile.target_type = self.classify_target_type(target)
        
        if profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            profile.ip_addresses = self._resolve_domain(target)
        elif self._is_ip_address(target):
            profile.ip_addresses = [target]
        
        profile.cloud_provider = self._detect_cloud_provider(target)
        
        profile.confidence_score = self._calculate_confidence_score(profile)
        
        return profile
    
    def classify_target_type(self, target: str) -> TargetType:
        """Classify target type based on format and characteristics"""
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            if '/api/' in parsed.path or parsed.path.endswith('.json'):
                return TargetType.API_ENDPOINT
            else:
                return TargetType.WEB_APPLICATION
        
        if self._is_ip_address(target):
            return TargetType.NETWORK_HOST
        
        if self._is_domain(target):
            return TargetType.WEB_APPLICATION
        
        if target.startswith('/') or '\\' in target or target.endswith(('.exe', '.bin', '.elf')):
            return TargetType.BINARY_FILE
        
        return TargetType.UNKNOWN
    
    def detect_technologies(self, target: str, headers: Dict[str, str], content: str) -> List[TechnologyStack]:
        """Detect technologies based on headers and content"""
        technologies = []
        
        server_header = headers.get('server', '').lower()
        for signature, tech in self.technology_signatures.items():
            if signature in server_header:
                technologies.append(tech)
        
        powered_by = headers.get('x-powered-by', '').lower()
        for signature, tech in self.technology_signatures.items():
            if signature in powered_by:
                technologies.append(tech)
        
        content_lower = content.lower()
        
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.append(TechnologyStack.WORDPRESS)
        
        if 'drupal' in content_lower or 'sites/default/files' in content_lower:
            technologies.append(TechnologyStack.DRUPAL)
        
        if 'joomla' in content_lower or '/components/com_' in content_lower:
            technologies.append(TechnologyStack.JOOMLA)
        
        if 'react' in content_lower or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in content:
            technologies.append(TechnologyStack.REACT)
        
        if 'angular' in content_lower or 'ng-version' in content:
            technologies.append(TechnologyStack.ANGULAR)
        
        if 'vue' in content_lower or '__VUE__' in content:
            technologies.append(TechnologyStack.VUE)
        
        return list(set(technologies))  # Remove duplicates
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain name"""
        if '.' not in target:
            return False
        
        parts = target.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or not part.replace('-', '').isalnum():
                return False
        
        return True
    
    def _resolve_domain(self, target: str) -> List[str]:
        """Resolve domain to IP addresses"""
        import socket
        
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            hostname = parsed.hostname
        else:
            hostname = target
        
        if not hostname:
            return []
        
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ip_addresses = list(set(info[4][0] for info in addr_info))
            return ip_addresses
        except socket.gaierror:
            logger.warning(f"Could not resolve domain: {hostname}")
            return []
    
    def _detect_cloud_provider(self, target: str) -> Optional[str]:
        """Detect cloud provider based on target characteristics"""
        target_lower = target.lower()
        
        for pattern, provider in self.cloud_providers.items():
            if pattern in target_lower:
                return provider
        
        return None
    
    def _calculate_confidence_score(self, profile: TargetProfile) -> float:
        """Calculate confidence score for the analysis"""
        score = 0.0
        
        if profile.target_type != TargetType.UNKNOWN:
            score += 0.3
        
        if profile.ip_addresses:
            score += 0.2
        
        if profile.technologies:
            score += 0.2
        
        if profile.cloud_provider:
            score += 0.1
        
        if profile.open_ports:
            score += 0.1
        
        if profile.services:
            score += 0.1
        
        return min(1.0, score)
