"""
Target and attack modeling data structures.

This module changes when target profiling or attack modeling strategies change.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

class TargetType(Enum):
    """Types of penetration testing targets"""
    WEB_APPLICATION = "web_application"
    NETWORK = "network"
    MOBILE_APP = "mobile_app"
    API = "api"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    IOT_DEVICE = "iot_device"
    WIRELESS = "wireless"
    SOCIAL_ENGINEERING = "social_engineering"

class TechnologyStack(Enum):
    """Common technology stacks for target profiling"""
    LAMP = "lamp"  # Linux, Apache, MySQL, PHP
    MEAN = "mean"  # MongoDB, Express, Angular, Node.js
    MERN = "mern"  # MongoDB, Express, React, Node.js
    DJANGO = "django"  # Python Django
    RAILS = "rails"  # Ruby on Rails
    DOTNET = "dotnet"  # .NET Framework
    SPRING = "spring"  # Spring Framework
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target profile for intelligent testing"""
    url: str
    target_type: TargetType
    technology_stack: TechnologyStack
    open_ports: List[int]
    discovered_services: Dict[str, Any]
    security_headers: Dict[str, str]
    cms_detection: Optional[str]
    framework_detection: Optional[str]
    server_info: Dict[str, str]
    ssl_info: Dict[str, Any]
    subdomain_count: int
    directory_structure: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary for API responses"""
        return {
            "url": self.url,
            "target_type": self.target_type.value,
            "technology_stack": self.technology_stack.value,
            "open_ports": self.open_ports,
            "discovered_services": self.discovered_services,
            "security_headers": self.security_headers,
            "cms_detection": self.cms_detection,
            "framework_detection": self.framework_detection,
            "server_info": self.server_info,
            "ssl_info": self.ssl_info,
            "subdomain_count": self.subdomain_count,
            "directory_structure": self.directory_structure
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    command: str
    expected_outcome: str
    success_indicators: List[str]

class AttackChain:
    """Represents a sequence of attack steps for a specific vulnerability"""
    
    def __init__(self, vulnerability_type: str, target_profile: TargetProfile):
        self.vulnerability_type = vulnerability_type
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability = 0.0
    
    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self._recalculate_probability()
    
    def calculate_success_probability(self) -> float:
        """Calculate overall success probability based on target profile and steps"""
        base_probability = 0.7
        
        if self.target_profile.target_type == TargetType.WEB_APPLICATION:
            base_probability += 0.1
        elif self.target_profile.target_type == TargetType.NETWORK:
            base_probability -= 0.1
        
        security_score = len(self.target_profile.security_headers) * 0.05
        base_probability -= security_score
        
        step_penalty = len(self.steps) * 0.02
        base_probability -= step_penalty
        
        return max(0.1, min(0.95, base_probability))
    
    def _recalculate_probability(self):
        """Recalculate success probability when steps change"""
        self.success_probability = self.calculate_success_probability()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert attack chain to dictionary"""
        return {
            "vulnerability_type": self.vulnerability_type,
            "target_profile": self.target_profile.to_dict(),
            "steps": [
                {
                    "tool": step.tool,
                    "command": step.command,
                    "expected_outcome": step.expected_outcome,
                    "success_indicators": step.success_indicators
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "total_steps": len(self.steps)
        }
