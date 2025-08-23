---
title: dataclass.TargetProfile
kind: dataclass
module: __main__
line_range: [473, 510]
discovered_in_chunk: 1
---

# TargetProfile Dataclass

## Entity Classification & Context
- **Kind:** Dataclass
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Decorators:** @dataclass

## Complete Signature & Definition
```python
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
```

## Purpose & Behavior
Comprehensive data structure for storing target analysis results:
- **Target Information:** URL/IP, type classification, IP addresses
- **Network Data:** Open ports, running services, subdomains
- **Technology Stack:** Detected technologies, CMS type, cloud provider
- **Security Posture:** Security headers, SSL configuration
- **Risk Assessment:** Attack surface score, risk level, confidence metrics
- **Discovery Results:** Endpoints, subdomains from reconnaissance

## Dependencies & Usage
- **Depends on:** 
  - dataclasses.dataclass, field
  - typing.List, Dict, Optional, Any
  - TargetType, TechnologyStack enums
- **Used by:**
  - IntelligentDecisionEngine for analysis and tool selection
  - AttackChain for attack planning
  - Parameter optimization methods

## Implementation Details

### Key Fields
- **target:** Primary target identifier (URL, IP, domain)
- **target_type:** Classification from TargetType enum
- **ip_addresses:** Resolved IP addresses for the target
- **open_ports:** Discovered open ports from scanning
- **services:** Port-to-service mapping
- **technologies:** Detected technology stack components
- **cms_type:** Content management system if detected
- **cloud_provider:** Cloud service provider if applicable
- **security_headers:** HTTP security headers analysis
- **ssl_info:** SSL/TLS configuration details
- **subdomains:** Discovered subdomains
- **endpoints:** Discovered API endpoints or paths
- **attack_surface_score:** Calculated attack surface metric (0.0-10.0)
- **risk_level:** Risk classification (minimal, low, medium, high, critical)
- **confidence_score:** Analysis confidence level (0.0-1.0)

### Methods
- **to_dict():** Converts profile to dictionary for JSON serialization

## Testing & Validation
- Field validation and type checking
- JSON serialization/deserialization
- Integration with analysis workflows

## Code Reproduction
```python
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
```
