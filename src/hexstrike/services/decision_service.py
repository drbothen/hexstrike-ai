"""
AI-powered tool selection and optimization service.

This module changes when tool selection algorithms or optimization strategies change.
"""

from typing import Dict, Any, List, Optional, Set
import logging
from ..domain.target_analysis import TargetProfile, TargetType, TechnologyStack
from .decision_engine import DecisionEngine
from .parameter_optimizer import ParameterOptimizer

logger = logging.getLogger(__name__)

class DecisionService:
    """Main decision orchestrator for tool selection and optimization"""
    
    def __init__(self):
        self.decision_engine = DecisionEngine()
        self.parameter_optimizer = ParameterOptimizer()
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create profile"""
        return self.decision_engine.analyze_target(target)
    
    def select_optimal_tools(self, target_profile: TargetProfile, max_tools: int = 5) -> List[str]:
        """Select optimal tools for target"""
        return self.decision_engine.select_optimal_tools(target_profile, max_tools)
    
    def optimize_parameters(self, tool: str, target_profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize parameters for specific tool and target"""
        return self.parameter_optimizer.optimize_parameters(tool, target_profile, base_params)
    
    def get_essential_tools(self, target_type: TargetType) -> List[str]:
        """Get essential tools for target type"""
        essential_mapping = {
            TargetType.WEB_APPLICATION: ["nmap", "gobuster", "nuclei"],
            TargetType.API_ENDPOINT: ["nmap", "nuclei", "sqlmap"],
            TargetType.NETWORK_HOST: ["nmap", "rustscan", "hydra"],
            TargetType.CLOUD_SERVICE: ["prowler", "nuclei"],
            TargetType.BINARY_FILE: ["ghidra"],
            TargetType.MOBILE_APP: ["ghidra"]
        }
        return essential_mapping.get(target_type, ["nmap"])
    
    def enable_advanced_optimization(self) -> None:
        """Enable advanced parameter optimization"""
        self.parameter_optimizer.enable_advanced_optimization()
    
    def disable_advanced_optimization(self) -> None:
        """Disable advanced parameter optimization"""
        self.parameter_optimizer.disable_advanced_optimization()
    
    def calculate_tool_effectiveness(self, tool: str, target_type: str) -> float:
        """Calculate effectiveness score for tool and target type"""
        return self.decision_engine.calculate_tool_effectiveness(tool, target_type)
    
    def update_tool_effectiveness(self, tool: str, target_type: str, new_score: float) -> None:
        """Update tool effectiveness score"""
        self.decision_engine.update_tool_effectiveness(tool, target_type, new_score)
