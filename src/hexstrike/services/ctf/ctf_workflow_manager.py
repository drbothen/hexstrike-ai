"""
CTF workflow management and challenge solving automation.

This module changes when CTF strategies or challenge types change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class CTFCategory(Enum):
    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    FORENSICS = "forensics"
    REVERSE = "rev"
    MISC = "misc"
    OSINT = "osint"

@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str
    description: str
    points: int = 0
    difficulty: str = "unknown"
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)

class CTFWorkflowManager:
    """Specialized workflow manager for CTF competitions"""
    
    def __init__(self):
        from .ctf_patterns import CTFPatterns
        
        self.category_tools = CTFPatterns.get_category_tools()
        self.solving_strategies = CTFPatterns.get_solving_strategies()
        self.challenge_patterns = CTFPatterns.get_challenge_patterns()
        self.success_indicators = CTFPatterns.get_success_indicators()
    
    def create_ctf_challenge_workflow(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Create specialized workflow for CTF challenge"""
        workflow = {
            "challenge": challenge.name,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "points": challenge.points,
            "phases": [],
            "estimated_time": 0,
            "tools_required": set(),
            "strategies": []
        }
        
        pattern = self.challenge_patterns.get(challenge.category, [])
        if not pattern:
            return self._create_generic_workflow(challenge)
        
        for step in pattern:
            phase = {
                "step": step["step"],
                "name": step["action"],
                "description": step["description"],
                "tools": step["tools"],
                "parallel": step["parallel"],
                "estimated_time": step["estimated_time"],
                "success_indicators": self._get_success_indicators(challenge.category, step["action"])
            }
            
            workflow["phases"].append(phase)
            workflow["estimated_time"] += step["estimated_time"]
            workflow["tools_required"].update(step["tools"])
        
        workflow["strategies"] = self.solving_strategies.get(challenge.category, [])
        workflow["tools_required"] = list(workflow["tools_required"])
        
        return workflow
    
    def _create_generic_workflow(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Create generic workflow for unknown categories"""
        return {
            "challenge": challenge.name,
            "category": challenge.category,
            "phases": [
                {
                    "step": 1,
                    "name": "analysis",
                    "description": "Initial challenge analysis",
                    "tools": ["manual"],
                    "estimated_time": 1800
                }
            ],
            "estimated_time": 1800,
            "tools_required": ["manual"],
            "strategies": [{"strategy": "manual_analysis", "description": "Manual analysis and problem solving"}]
        }
    
    def _get_success_indicators(self, category: str, action: str) -> List[str]:
        """Get success indicators for specific actions"""
        return self.success_indicators.get(action, ["Progress made", "Information gathered"])
    
    def suggest_tools_for_challenge(self, challenge: CTFChallenge) -> List[str]:
        """Suggest optimal tools for specific challenge"""
        category_tools = self.category_tools.get(challenge.category, {})
        suggested = []
        
        for tool_group in category_tools.values():
            suggested.extend(tool_group[:2])  # Take top 2 from each group
        
        description_lower = challenge.description.lower()
        
        if "sql" in description_lower:
            suggested.extend(["sqlmap", "nuclei"])
        if "xss" in description_lower:
            suggested.extend(["dalfox", "nuclei"])
        if "binary" in description_lower:
            suggested.extend(["ghidra", "gdb-peda"])
        if "image" in description_lower:
            suggested.extend(["exiftool", "steghide"])
        if "hash" in description_lower:
            suggested.extend(["hashcat", "john"])
        
        return list(set(suggested))  # Remove duplicates
    
    def get_category_statistics(self) -> Dict[str, Any]:
        """Get statistics about CTF categories and tools"""
        stats = {}
        
        for category, tools in self.category_tools.items():
            total_tools = sum(len(tool_list) for tool_list in tools.values())
            stats[category] = {
                "tool_groups": len(tools),
                "total_tools": total_tools,
                "strategies": len(self.solving_strategies.get(category, [])),
                "workflow_steps": len(self.challenge_patterns.get(category, []))
            }
        
        return stats
    
    def optimize_workflow_for_time(self, workflow: Dict[str, Any], max_time: int) -> Dict[str, Any]:
        """Optimize workflow to fit within time constraint"""
        if workflow["estimated_time"] <= max_time:
            return workflow
        
        optimized = workflow.copy()
        optimized["phases"] = []
        current_time = 0
        
        sorted_phases = sorted(workflow["phases"], key=lambda x: x["step"])
        
        for phase in sorted_phases:
            if current_time + phase["estimated_time"] <= max_time:
                optimized["phases"].append(phase)
                current_time += phase["estimated_time"]
            else:
                remaining_time = max_time - current_time
                if remaining_time >= 300:  # Minimum 5 minutes
                    shortened_phase = phase.copy()
                    shortened_phase["estimated_time"] = remaining_time
                    shortened_phase["description"] += " (time-limited)"
                    optimized["phases"].append(shortened_phase)
                break
        
        optimized["estimated_time"] = current_time
        return optimized
