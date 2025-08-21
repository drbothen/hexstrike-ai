"""
Tool effectiveness management and scoring system.

This module changes when tool effectiveness ratings or scoring algorithms change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import logging
from ..domain.target_analysis import TargetType

logger = logging.getLogger(__name__)

@dataclass
class EffectivenessScore:
    """Tool effectiveness score with metadata"""
    score: float
    confidence: float
    last_updated: str
    sample_size: int = 0
    success_rate: float = 0.0

class ToolEffectivenessManager:
    """Manages tool effectiveness ratings and learning"""
    
    def __init__(self):
        self.effectiveness_matrix = self._initialize_effectiveness_matrix()
        self.learning_enabled = True
        self.update_history = []
    
    def _initialize_effectiveness_matrix(self) -> Dict[str, Dict[str, EffectivenessScore]]:
        """Initialize comprehensive tool effectiveness matrix"""
        matrix = {}
        
        matrix[TargetType.WEB_APPLICATION.value] = {
            "nmap": EffectivenessScore(0.8, 0.9, "2024-01-01"),
            "gobuster": EffectivenessScore(0.9, 0.95, "2024-01-01"),
            "nuclei": EffectivenessScore(0.95, 0.98, "2024-01-01"),
            "nikto": EffectivenessScore(0.85, 0.9, "2024-01-01"),
            "sqlmap": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "ffuf": EffectivenessScore(0.9, 0.93, "2024-01-01"),
            "feroxbuster": EffectivenessScore(0.85, 0.88, "2024-01-01"),
            "katana": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "httpx": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "wpscan": EffectivenessScore(0.95, 0.97, "2024-01-01"),
            "dirsearch": EffectivenessScore(0.87, 0.89, "2024-01-01"),
            "gau": EffectivenessScore(0.82, 0.85, "2024-01-01"),
            "waybackurls": EffectivenessScore(0.8, 0.83, "2024-01-01"),
            "arjun": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "paramspider": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "x8": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "jaeles": EffectivenessScore(0.92, 0.94, "2024-01-01"),
            "dalfox": EffectivenessScore(0.93, 0.95, "2024-01-01")
        }
        
        matrix[TargetType.NETWORK_HOST.value] = {
            "nmap": EffectivenessScore(0.95, 0.98, "2024-01-01"),
            "nmap-advanced": EffectivenessScore(0.97, 0.99, "2024-01-01"),
            "masscan": EffectivenessScore(0.92, 0.94, "2024-01-01"),
            "rustscan": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "autorecon": EffectivenessScore(0.95, 0.96, "2024-01-01"),
            "enum4linux": EffectivenessScore(0.8, 0.85, "2024-01-01"),
            "enum4linux-ng": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "smbmap": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "rpcclient": EffectivenessScore(0.82, 0.84, "2024-01-01"),
            "nbtscan": EffectivenessScore(0.75, 0.8, "2024-01-01"),
            "arp-scan": EffectivenessScore(0.85, 0.88, "2024-01-01"),
            "responder": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "hydra": EffectivenessScore(0.8, 0.85, "2024-01-01"),
            "netexec": EffectivenessScore(0.85, 0.87, "2024-01-01")
        }
        
        matrix[TargetType.API_ENDPOINT.value] = {
            "nuclei": EffectivenessScore(0.9, 0.93, "2024-01-01"),
            "ffuf": EffectivenessScore(0.85, 0.88, "2024-01-01"),
            "arjun": EffectivenessScore(0.95, 0.97, "2024-01-01"),
            "paramspider": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "httpx": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "x8": EffectivenessScore(0.92, 0.94, "2024-01-01"),
            "katana": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "jaeles": EffectivenessScore(0.88, 0.9, "2024-01-01")
        }
        
        matrix[TargetType.CLOUD_SERVICE.value] = {
            "prowler": EffectivenessScore(0.95, 0.97, "2024-01-01"),
            "scout-suite": EffectivenessScore(0.92, 0.94, "2024-01-01"),
            "cloudmapper": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "pacu": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "trivy": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "clair": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "kube-hunter": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "kube-bench": EffectivenessScore(0.88, 0.9, "2024-01-01"),
            "docker-bench-security": EffectivenessScore(0.85, 0.87, "2024-01-01"),
            "falco": EffectivenessScore(0.87, 0.89, "2024-01-01"),
            "checkov": EffectivenessScore(0.9, 0.92, "2024-01-01"),
            "terrascan": EffectivenessScore(0.88, 0.9, "2024-01-01")
        }
        
        return matrix
    
    def get_effectiveness_score(self, tool_name: str, target_type: TargetType) -> Optional[EffectivenessScore]:
        """Get effectiveness score for tool and target type"""
        target_matrix = self.effectiveness_matrix.get(target_type.value, {})
        return target_matrix.get(tool_name)
    
    def update_effectiveness(self, tool_name: str, target_type: TargetType, 
                           success: bool, execution_time: float = 0.0) -> None:
        """Update tool effectiveness based on execution results"""
        if not self.learning_enabled:
            return
        
        target_key = target_type.value
        if target_key not in self.effectiveness_matrix:
            self.effectiveness_matrix[target_key] = {}
        
        current_score = self.effectiveness_matrix[target_key].get(tool_name)
        if not current_score:
            current_score = EffectivenessScore(0.5, 0.5, "2024-01-01")
        
        total_runs = current_score.sample_size + 1
        new_success_rate = ((current_score.success_rate * current_score.sample_size) + (1.0 if success else 0.0)) / total_runs
        
        adjustment = 0.05 if success else -0.03
        new_score = max(0.0, min(1.0, current_score.score + adjustment))
        
        new_confidence = min(0.99, current_score.confidence + (0.01 if total_runs < 100 else 0.001))
        
        updated_score = EffectivenessScore(
            score=new_score,
            confidence=new_confidence,
            last_updated="2024-01-01",
            sample_size=total_runs,
            success_rate=new_success_rate
        )
        
        self.effectiveness_matrix[target_key][tool_name] = updated_score
        
        self.update_history.append({
            "tool": tool_name,
            "target_type": target_type.value,
            "success": success,
            "new_score": new_score,
            "timestamp": "2024-01-01"
        })
        
        logger.info(f"Updated effectiveness for {tool_name} on {target_type.value}: {new_score:.3f}")
    
    def get_top_tools(self, target_type: TargetType, limit: int = 10) -> List[tuple]:
        """Get top tools for target type sorted by effectiveness"""
        target_matrix = self.effectiveness_matrix.get(target_type.value, {})
        
        tools_with_scores = [
            (tool, score.score, score.confidence)
            for tool, score in target_matrix.items()
        ]
        
        tools_with_scores.sort(key=lambda x: x[1] * x[2], reverse=True)
        return tools_with_scores[:limit]
    
    def get_tool_alternatives(self, tool_name: str, target_type: TargetType, 
                            min_effectiveness: float = 0.7) -> List[str]:
        """Get alternative tools with similar effectiveness"""
        target_matrix = self.effectiveness_matrix.get(target_type.value, {})
        current_score = target_matrix.get(tool_name)
        
        if not current_score:
            return []
        
        alternatives = []
        for tool, score in target_matrix.items():
            if (tool != tool_name and 
                score.score >= min_effectiveness and
                abs(score.score - current_score.score) <= 0.2):
                alternatives.append(tool)
        
        return alternatives
    
    def enable_learning(self):
        """Enable effectiveness learning from execution results"""
        self.learning_enabled = True
        logger.info("Tool effectiveness learning enabled")
    
    def disable_learning(self):
        """Disable effectiveness learning"""
        self.learning_enabled = False
        logger.info("Tool effectiveness learning disabled")
    
    def export_matrix(self) -> Dict[str, Any]:
        """Export effectiveness matrix for analysis"""
        export_data = {}
        
        for target_type, tools in self.effectiveness_matrix.items():
            export_data[target_type] = {}
            for tool, score in tools.items():
                export_data[target_type][tool] = {
                    "score": score.score,
                    "confidence": score.confidence,
                    "sample_size": score.sample_size,
                    "success_rate": score.success_rate,
                    "last_updated": score.last_updated
                }
        
        return export_data
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get learning statistics and insights"""
        total_updates = len(self.update_history)
        successful_updates = sum(1 for update in self.update_history if update["success"])
        
        tool_update_counts = {}
        for update in self.update_history:
            tool = update["tool"]
            tool_update_counts[tool] = tool_update_counts.get(tool, 0) + 1
        
        return {
            "total_updates": total_updates,
            "success_rate": successful_updates / total_updates if total_updates > 0 else 0,
            "most_updated_tools": sorted(tool_update_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            "learning_enabled": self.learning_enabled
        }
