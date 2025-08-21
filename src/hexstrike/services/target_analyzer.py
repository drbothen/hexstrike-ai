"""
Target analysis service for HexStrike AI.

This module provides target analysis functionality for the intelligent decision engine.
"""

from typing import Dict, Any, List, Optional
import logging
from ..domain.target_analysis import TargetType, TargetProfile

logger = logging.getLogger(__name__)

class TargetAnalyzer:
    """Analyzes targets and creates comprehensive profiles"""
    
    def __init__(self):
        self.technology_signatures = self._initialize_technology_signatures()
    
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
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create comprehensive profile"""
        target_type = self._determine_target_type(target)
        technologies = self._detect_technologies(target)
        attack_surface = self._calculate_attack_surface(target, target_type)
        risk_level = self._determine_risk_level(attack_surface)
        confidence = self._calculate_confidence(target, target_type, technologies)
        
        return TargetProfile(
            target=target,
            target_type=target_type,
            technologies=technologies,
            attack_surface=attack_surface,
            risk_level=risk_level,
            confidence=confidence
        )
    
    def _determine_target_type(self, target: str) -> TargetType:
        """Determine the type of target"""
        if target.startswith(('http://', 'https://')):
            return TargetType.WEB_APPLICATION
        elif '/' in target and not target.startswith(('http://', 'https://')):
            return TargetType.API_ENDPOINT
        elif any(cloud in target.lower() for cloud in ['aws', 'azure', 'gcp', 'cloud']):
            return TargetType.CLOUD_SERVICE
        else:
            return TargetType.NETWORK_HOST
    
    def _resolve_domain(self, target: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            import socket
            return socket.gethostbyname(target)
        except:
            return None
    
    def _detect_technologies(self, target: str) -> List[str]:
        """Detect technologies used by target"""
        detected = []
        
        for tech, signatures in self.technology_signatures.items():
            if any(sig.lower() in target.lower() for sig in signatures):
                detected.append(tech)
        
        return detected
    
    def _detect_cms(self, target: str) -> Optional[str]:
        """Detect CMS type"""
        cms_indicators = {
            'wordpress': ['wp-content', 'wp-admin'],
            'drupal': ['sites/default', 'misc/drupal.js'],
            'joomla': ['administrator/', 'components/']
        }
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in target.lower() for indicator in indicators):
                return cms
        
        return None
    
    def _calculate_attack_surface(self, target: str, target_type: TargetType) -> Dict[str, Any]:
        """Calculate attack surface metrics"""
        return {
            "complexity": "medium",
            "exposure": "high" if target_type == TargetType.WEB_APPLICATION else "medium",
            "potential_vectors": self._get_potential_vectors(target_type),
            "estimated_endpoints": 10 if target_type == TargetType.WEB_APPLICATION else 5
        }
    
    def _get_potential_vectors(self, target_type: TargetType) -> List[str]:
        """Get potential attack vectors for target type"""
        vectors = {
            TargetType.WEB_APPLICATION: ["sqli", "xss", "csrf", "lfi", "rfi", "ssrf"],
            TargetType.NETWORK_HOST: ["service_exploit", "credential_attack", "privilege_escalation"],
            TargetType.API_ENDPOINT: ["parameter_pollution", "injection", "broken_auth"],
            TargetType.CLOUD_SERVICE: ["misconfiguration", "privilege_escalation", "data_exposure"]
        }
        return vectors.get(target_type, [])
    
    def _determine_risk_level(self, attack_surface: Dict[str, Any]) -> str:
        """Determine risk level based on attack surface"""
        complexity = attack_surface.get("complexity", "medium")
        exposure = attack_surface.get("exposure", "medium")
        
        if exposure == "high" and complexity == "low":
            return "high"
        elif exposure == "high" or complexity == "high":
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(self, target: str, target_type: TargetType, technologies: List[str]) -> float:
        """Calculate confidence in analysis"""
        base_confidence = 0.7
        
        if technologies:
            base_confidence += 0.2
        
        if target_type != TargetType.NETWORK_HOST:
            base_confidence += 0.1
        
        return min(1.0, base_confidence)
