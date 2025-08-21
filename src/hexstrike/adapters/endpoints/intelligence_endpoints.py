"""
Intelligence engine endpoint handlers.

This module changes when intelligence API endpoints or analysis capabilities change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.intelligent_decision_engine import IntelligentDecisionEngine
from ...services.tool_effectiveness_manager import ToolEffectivenessManager
from ...services.attack_chain_builder import AttackChainBuilder
from ...domain.target_analysis import TargetType
from ...interfaces.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

class IntelligenceEndpoints:
    """Intelligence engine endpoint handlers"""
    
    def __init__(self):
        self.decision_engine = IntelligentDecisionEngine()
        self.effectiveness_manager = ToolEffectivenessManager()
        self.chain_builder = AttackChainBuilder()
    
    def analyze_target(self) -> Dict[str, Any]:
        """Analyze target and create comprehensive profile"""
        try:
            data = request.get_json()
            target = data.get('target', '')
            
            if not target:
                return jsonify({"error": "Target parameter is required"}), 400
            
            target_profile = self.decision_engine.analyze_target(target)
            
            logger.info(f"🎯 Analyzed target: {target}")
            
            return jsonify({
                "success": True,
                "target": target,
                "profile": target_profile.to_dict(),
                "message": "Target analysis completed"
            })
            
        except Exception as e:
            logger.error(f"💥 Error analyzing target: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def select_tools(self) -> Dict[str, Any]:
        """Select optimal tools for target"""
        try:
            data = request.get_json()
            target = data.get('target', '')
            objective = data.get('objective', 'comprehensive')
            
            target_profile = self.decision_engine.analyze_target(target)
            optimal_tools = self.decision_engine.select_optimal_tools(target_profile, objective)
            
            logger.info(f"🔧 Selected {len(optimal_tools)} tools for {target}")
            
            return jsonify({
                "success": True,
                "target": target,
                "objective": objective,
                "selected_tools": optimal_tools,
                "target_type": target_profile.target_type.value,
                "message": f"Selected {len(optimal_tools)} optimal tools"
            })
            
        except Exception as e:
            logger.error(f"💥 Error selecting tools: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def optimize_parameters(self) -> Dict[str, Any]:
        """Optimize tool parameters for target"""
        try:
            data = request.get_json()
            target = data.get('target', '')
            tool_name = data.get('tool', '')
            
            if not target or not tool_name:
                return jsonify({"error": "Target and tool parameters are required"}), 400
            
            target_profile = self.decision_engine.analyze_target(target)
            optimized_params = self.decision_engine.optimize_parameters(tool_name, target_profile)
            
            logger.info(f"⚙️ Optimized parameters for {tool_name} on {target}")
            
            return jsonify({
                "success": True,
                "target": target,
                "tool": tool_name,
                "optimized_parameters": optimized_params,
                "target_type": target_profile.target_type.value,
                "message": f"Parameters optimized for {tool_name}"
            })
            
        except Exception as e:
            logger.error(f"💥 Error optimizing parameters: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def create_attack_chain(self) -> Dict[str, Any]:
        """Create intelligent attack chain"""
        try:
            data = request.get_json()
            target = data.get('target', '')
            strategy = data.get('strategy', 'comprehensive')
            
            target_profile = self.decision_engine.analyze_target(target)
            attack_chain = self.chain_builder.build_chain(target_profile, strategy)
            
            chain_stats = self.chain_builder.get_chain_statistics(attack_chain)
            suggestions = self.chain_builder.suggest_improvements(attack_chain)
            
            logger.info(f"⛓️ Created attack chain for {target} with {len(attack_chain.steps)} steps")
            
            return jsonify({
                "success": True,
                "target": target,
                "strategy": strategy,
                "attack_chain": attack_chain.to_dict(),
                "statistics": chain_stats,
                "suggestions": suggestions,
                "message": f"Attack chain created with {len(attack_chain.steps)} steps"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating attack chain: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def smart_scan(self) -> Dict[str, Any]:
        """Execute smart scan with AI optimization"""
        try:
            data = request.get_json()
            target = data.get('target', '')
            scan_type = data.get('scan_type', 'comprehensive')
            
            target_profile = self.decision_engine.analyze_target(target)
            optimal_tools = self.decision_engine.select_optimal_tools(target_profile, scan_type)
            
            scan_plan = {
                "target": target,
                "target_profile": target_profile.to_dict(),
                "selected_tools": optimal_tools,
                "optimized_parameters": {},
                "execution_order": []
            }
            
            for tool in optimal_tools[:5]:
                optimized_params = self.decision_engine.optimize_parameters(tool, target_profile)
                scan_plan["optimized_parameters"][tool] = optimized_params
                scan_plan["execution_order"].append({
                    "tool": tool,
                    "parameters": optimized_params,
                    "priority": optimal_tools.index(tool) + 1
                })
            
            logger.info(f"🧠 Created smart scan plan for {target}")
            
            return jsonify({
                "success": True,
                "scan_plan": scan_plan,
                "message": "Smart scan plan created with AI optimization"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating smart scan: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def technology_detection(self) -> Dict[str, Any]:
        """Detect technologies used by target"""
        try:
            data = request.get_json()
            target = data.get('target', '')
            
            target_profile = self.decision_engine.analyze_target(target)
            
            technology_analysis = {
                "target": target,
                "detected_technologies": target_profile.technologies,
                "target_type": target_profile.target_type.value,
                "confidence": target_profile.confidence,
                "attack_surface": target_profile.attack_surface,
                "risk_level": target_profile.risk_level
            }
            
            recommended_tools = []
            for tech in target_profile.technologies:
                if tech in ['wordpress', 'drupal', 'joomla']:
                    recommended_tools.extend(['wpscan', 'nuclei'])
                elif tech in ['php', 'asp']:
                    recommended_tools.extend(['sqlmap', 'nuclei'])
                elif tech in ['nodejs', 'python']:
                    recommended_tools.extend(['nuclei', 'ffuf'])
            
            technology_analysis["recommended_tools"] = list(set(recommended_tools))
            
            logger.info(f"🔍 Detected {len(target_profile.technologies)} technologies for {target}")
            
            return jsonify({
                "success": True,
                "analysis": technology_analysis,
                "message": f"Detected {len(target_profile.technologies)} technologies"
            })
            
        except Exception as e:
            logger.error(f"💥 Error in technology detection: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def tool_effectiveness_stats(self) -> Dict[str, Any]:
        """Get tool effectiveness statistics"""
        try:
            data = request.get_json()
            target_type_str = data.get('target_type', 'web_application')
            
            try:
                target_type = TargetType(target_type_str)
            except ValueError:
                target_type = TargetType.WEB_APPLICATION
            
            top_tools = self.effectiveness_manager.get_top_tools(target_type, limit=10)
            learning_stats = self.effectiveness_manager.get_learning_statistics()
            
            logger.info(f"📊 Retrieved effectiveness stats for {target_type.value}")
            
            return jsonify({
                "success": True,
                "target_type": target_type.value,
                "top_tools": [{"tool": tool, "score": score, "confidence": conf} 
                             for tool, score, conf in top_tools],
                "learning_statistics": learning_stats,
                "message": f"Tool effectiveness statistics for {target_type.value}"
            })
            
        except Exception as e:
            logger.error(f"💥 Error getting effectiveness stats: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
</new_str>
