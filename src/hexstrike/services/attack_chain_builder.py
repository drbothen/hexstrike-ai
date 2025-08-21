"""
Attack chain building and optimization service.

This module changes when attack chain strategies or optimization algorithms change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging
from ..domain.target_analysis import TargetType, TargetProfile
from .intelligent_decision_engine import AttackStep, AttackChain
from .attack_chain_templates import AttackChainTemplates, ChainTemplate

logger = logging.getLogger(__name__)

class AttackChainBuilder:
    """Builds and optimizes attack chains for different scenarios"""
    
    def __init__(self):
        self.template_manager = AttackChainTemplates()
        self.chain_templates = self.template_manager.templates
        self.optimization_strategies = self._initialize_optimization_strategies()
    
    
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
