"""
Attack chain building and optimization service.

This module changes when attack chain strategies or optimization algorithms change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging
from ..domain.target_analysis import TargetType, TargetProfile
from .intelligent_decision_engine import AttackStep, AttackChain

logger = logging.getLogger(__name__)

@dataclass
class ChainTemplate:
    """Template for attack chain construction"""
    name: str
    target_types: List[TargetType]
    phases: List[Dict[str, Any]]
    estimated_time: int
    success_probability: float
    risk_level: str

class AttackChainBuilder:
    """Builds and optimizes attack chains for different scenarios"""
    
    def __init__(self):
        self.chain_templates = self._initialize_chain_templates()
        self.optimization_strategies = self._initialize_optimization_strategies()
    
    def _initialize_chain_templates(self) -> Dict[str, ChainTemplate]:
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
    
    def _initialize_optimization_strategies(self) -> Dict[str, Any]:
        """Initialize optimization strategies"""
        return {
            "time_optimized": {
                "description": "Minimize execution time",
                "parallel_preference": True,
                "tool_limit": 3,
                "phase_limit": 3
            },
            "comprehensive": {
                "description": "Maximum coverage",
                "parallel_preference": False,
                "tool_limit": 5,
                "phase_limit": 6
            },
            "stealth": {
                "description": "Minimize detection risk",
                "parallel_preference": False,
                "tool_limit": 2,
                "phase_limit": 4,
                "excluded_tools": ["masscan", "rustscan"]
            }
        }
    
    def build_chain(self, target_profile: TargetProfile, strategy: str = "comprehensive") -> AttackChain:
        """Build optimized attack chain for target"""
        template = self._select_template(target_profile)
        if not template:
            return self._build_default_chain(target_profile)
        
        chain = AttackChain(target_profile)
        optimization = self.optimization_strategies.get(strategy, self.optimization_strategies["comprehensive"])
        
        phases_to_include = template.phases[:optimization.get("phase_limit", len(template.phases))]
        
        for phase in phases_to_include:
            tools = phase["tools"]
            
            if "excluded_tools" in optimization:
                tools = [t for t in tools if t not in optimization["excluded_tools"]]
            
            tools = tools[:optimization.get("tool_limit", len(tools))]
            
            if not tools:
                continue
            
            primary_tool = tools[0]
            
            step = AttackStep(
                tool=primary_tool,
                parameters={"target": target_profile.target},
                expected_outcome=phase["description"],
                success_probability=phase["success_probability"],
                execution_time_estimate=phase["estimated_time"],
                dependencies=[]
            )
            
            chain.add_step(step)
        
        chain.risk_level = template.risk_level
        return chain
    
    def _select_template(self, target_profile: TargetProfile) -> Optional[ChainTemplate]:
        """Select appropriate template for target"""
        target_type = target_profile.target_type
        
        for template in self.chain_templates.values():
            if target_type in template.target_types:
                return template
        
        return None
    
    def _build_default_chain(self, target_profile: TargetProfile) -> AttackChain:
        """Build default chain when no template matches"""
        chain = AttackChain(target_profile)
        
        default_step = AttackStep(
            tool="nmap",
            parameters={"target": target_profile.target, "scan_type": "-sS"},
            expected_outcome="Basic reconnaissance",
            success_probability=0.8,
            execution_time_estimate=300,
            dependencies=[]
        )
        
        chain.add_step(default_step)
        chain.risk_level = "low"
        return chain
    
    def optimize_chain(self, chain: AttackChain, constraints: Dict[str, Any]) -> AttackChain:
        """Optimize existing attack chain based on constraints"""
        max_time = constraints.get("max_time")
        max_risk = constraints.get("max_risk", "high")
        required_tools = constraints.get("required_tools", [])
        
        optimized_chain = AttackChain(chain.target_profile)
        
        for step in chain.steps:
            if max_time and optimized_chain.estimated_time + step.execution_time_estimate > max_time:
                continue
            
            if max_risk == "low" and step.success_probability < 0.8:
                continue
            elif max_risk == "medium" and step.success_probability < 0.6:
                continue
            
            if required_tools and step.tool not in required_tools:
                continue
            
            optimized_chain.add_step(step)
        
        return optimized_chain
    
    def get_chain_statistics(self, chain: AttackChain) -> Dict[str, Any]:
        """Get comprehensive statistics for attack chain"""
        if not chain.steps:
            return {"error": "Empty chain"}
        
        tool_distribution = {}
        for step in chain.steps:
            tool_distribution[step.tool] = tool_distribution.get(step.tool, 0) + 1
        
        avg_success_prob = sum(step.success_probability for step in chain.steps) / len(chain.steps)
        
        return {
            "total_steps": len(chain.steps),
            "estimated_time_minutes": chain.estimated_time // 60,
            "overall_success_probability": chain.success_probability,
            "average_step_success": avg_success_prob,
            "tool_distribution": tool_distribution,
            "risk_level": chain.risk_level,
            "required_tools": list(chain.required_tools)
        }
    
    def suggest_improvements(self, chain: AttackChain) -> List[str]:
        """Suggest improvements for attack chain"""
        suggestions = []
        
        if chain.success_probability < 0.5:
            suggestions.append("Consider adding more reliable tools to improve success probability")
        
        if chain.estimated_time > 7200:  # 2 hours
            suggestions.append("Chain execution time is high, consider parallel execution or tool optimization")
        
        if len(chain.steps) < 3:
            suggestions.append("Chain has few steps, consider adding more comprehensive phases")
        
        tool_counts = {}
        for step in chain.steps:
            tool_counts[step.tool] = tool_counts.get(step.tool, 0) + 1
        
        if max(tool_counts.values()) > 3:
            suggestions.append("Some tools are used repeatedly, consider diversifying tool selection")
        
        return suggestions
</new_str>
