"""
Target analysis orchestration logic.

This module changes when target analysis algorithms change.
"""

from typing import List, Dict, Any, Optional
import ipaddress
import urllib.parse
import logging
from .target_analysis import TargetType, TechnologyStack, TargetProfile

logger = logging.getLogger(__name__)

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
