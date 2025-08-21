"""
CTF competition endpoint handlers.

This module changes when CTF API endpoints or challenge types change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.ctf.ctf_workflow_manager import CTFWorkflowManager, CTFChallenge
from ...interfaces.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

class CTFEndpoints:
    """CTF competition endpoint handlers"""
    
    def __init__(self):
        self.ctf_manager = CTFWorkflowManager()
    
    def create_challenge_workflow(self) -> Dict[str, Any]:
        """Create specialized workflow for CTF challenge"""
        try:
            data = request.get_json()
            
            challenge = CTFChallenge(
                name=data.get('name', ''),
                category=data.get('category', ''),
                description=data.get('description', ''),
                points=data.get('points', 0),
                difficulty=data.get('difficulty', 'unknown'),
                files=data.get('files', []),
                url=data.get('url', ''),
                hints=data.get('hints', [])
            )
            
            workflow = self.ctf_manager.create_ctf_challenge_workflow(challenge)
            
            logger.info(f"🏆 Created CTF workflow for {challenge.name} ({challenge.category})")
            
            return jsonify({
                "success": True,
                "workflow": workflow,
                "message": f"CTF workflow created for {challenge.category} challenge"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating CTF workflow: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def auto_solve_challenge(self) -> Dict[str, Any]:
        """Attempt to automatically solve a CTF challenge"""
        try:
            data = request.get_json()
            
            challenge = CTFChallenge(
                name=data.get('name', ''),
                category=data.get('category', ''),
                description=data.get('description', ''),
                files=data.get('files', []),
                url=data.get('url', '')
            )
            
            suggested_tools = self.ctf_manager.suggest_tools_for_challenge(challenge)
            workflow = self.ctf_manager.create_ctf_challenge_workflow(challenge)
            
            logger.info(f"🤖 Auto-solving CTF challenge: {challenge.name}")
            
            return jsonify({
                "success": True,
                "challenge": challenge.name,
                "category": challenge.category,
                "suggested_tools": suggested_tools,
                "workflow": workflow,
                "message": "Auto-solve workflow initiated"
            })
            
        except Exception as e:
            logger.error(f"💥 Error in CTF auto-solve: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def create_team_strategy(self) -> Dict[str, Any]:
        """Create optimal team strategy for CTF competition"""
        try:
            data = request.get_json()
            
            team_size = data.get('team_size', 4)
            competition_duration = data.get('duration_hours', 24)
            categories = data.get('categories', ['web', 'crypto', 'pwn', 'forensics'])
            
            strategy = {
                "team_size": team_size,
                "duration": competition_duration,
                "category_assignments": {},
                "time_allocation": {},
                "coordination_plan": []
            }
            
            for i, category in enumerate(categories):
                member_id = i % team_size + 1
                strategy["category_assignments"][category] = f"Member_{member_id}"
                strategy["time_allocation"][category] = competition_duration // len(categories)
            
            strategy["coordination_plan"] = [
                "Initial 30min: Team briefing and challenge triage",
                "First 2 hours: Individual category focus",
                "Mid-competition: Progress sync and resource reallocation",
                "Final 2 hours: Flag submission and verification"
            ]
            
            logger.info(f"👥 Created CTF team strategy for {team_size} members")
            
            return jsonify({
                "success": True,
                "strategy": strategy,
                "message": "CTF team strategy created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating CTF team strategy: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def suggest_tools(self) -> Dict[str, Any]:
        """Suggest optimal tools for CTF challenge"""
        try:
            data = request.get_json()
            
            challenge = CTFChallenge(
                name=data.get('name', ''),
                category=data.get('category', ''),
                description=data.get('description', '')
            )
            
            suggested_tools = self.ctf_manager.suggest_tools_for_challenge(challenge)
            category_stats = self.ctf_manager.get_category_statistics()
            
            logger.info(f"🔧 Suggested tools for {challenge.category} challenge")
            
            return jsonify({
                "success": True,
                "challenge": challenge.name,
                "category": challenge.category,
                "suggested_tools": suggested_tools,
                "category_stats": category_stats.get(challenge.category, {}),
                "message": f"Tool suggestions for {challenge.category} challenge"
            })
            
        except Exception as e:
            logger.error(f"💥 Error suggesting CTF tools: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def cryptography_solver(self) -> Dict[str, Any]:
        """Advanced cryptography challenge solver"""
        try:
            data = request.get_json()
            
            cipher_text = data.get('cipher_text', '')
            cipher_type = data.get('cipher_type', 'unknown')
            hints = data.get('hints', [])
            
            analysis_results = {
                "cipher_text": cipher_text,
                "detected_type": cipher_type,
                "analysis": [],
                "suggested_attacks": [],
                "tools_to_use": []
            }
            
            if cipher_type.lower() in ['caesar', 'substitution']:
                analysis_results["suggested_attacks"] = ["frequency_analysis", "brute_force"]
                analysis_results["tools_to_use"] = ["cyberchef", "frequency-analyzer"]
            elif cipher_type.lower() in ['rsa', 'public_key']:
                analysis_results["suggested_attacks"] = ["factorization", "weak_key_check"]
                analysis_results["tools_to_use"] = ["rsatool", "factordb", "sage"]
            elif cipher_type.lower() == 'hash':
                analysis_results["suggested_attacks"] = ["dictionary_attack", "rainbow_tables"]
                analysis_results["tools_to_use"] = ["hashcat", "john"]
            
            logger.info(f"🔐 Analyzing cryptography challenge: {cipher_type}")
            
            return jsonify({
                "success": True,
                "analysis": analysis_results,
                "message": "Cryptography analysis completed"
            })
            
        except Exception as e:
            logger.error(f"💥 Error in CTF crypto solver: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def forensics_analyzer(self) -> Dict[str, Any]:
        """Advanced forensics challenge analyzer"""
        try:
            data = request.get_json()
            
            file_path = data.get('file_path', '')
            file_type = data.get('file_type', 'unknown')
            analysis_depth = data.get('depth', 'standard')
            
            analysis_plan = {
                "file_path": file_path,
                "file_type": file_type,
                "analysis_phases": [],
                "tools_required": [],
                "estimated_time": 0
            }
            
            if file_type.lower() in ['image', 'jpg', 'png']:
                analysis_plan["analysis_phases"] = [
                    "metadata_extraction",
                    "steganography_check",
                    "visual_analysis"
                ]
                analysis_plan["tools_required"] = ["exiftool", "steghide", "stegsolve"]
                analysis_plan["estimated_time"] = 1800
            elif file_type.lower() in ['memory', 'dump']:
                analysis_plan["analysis_phases"] = [
                    "memory_analysis",
                    "process_extraction",
                    "artifact_recovery"
                ]
                analysis_plan["tools_required"] = ["volatility", "rekall"]
                analysis_plan["estimated_time"] = 3600
            elif file_type.lower() in ['pcap', 'network']:
                analysis_plan["analysis_phases"] = [
                    "protocol_analysis",
                    "stream_extraction",
                    "anomaly_detection"
                ]
                analysis_plan["tools_required"] = ["wireshark", "tcpdump"]
                analysis_plan["estimated_time"] = 2400
            
            logger.info(f"🔍 Forensics analysis plan for {file_type}")
            
            return jsonify({
                "success": True,
                "analysis_plan": analysis_plan,
                "message": "Forensics analysis plan created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error in CTF forensics analyzer: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def binary_analyzer(self) -> Dict[str, Any]:
        """Advanced binary analysis for reverse engineering"""
        try:
            data = request.get_json()
            
            binary_path = data.get('binary_path', '')
            analysis_type = data.get('analysis_type', 'comprehensive')
            target_arch = data.get('architecture', 'x64')
            
            analysis_workflow = {
                "binary_path": binary_path,
                "architecture": target_arch,
                "analysis_phases": [
                    {
                        "phase": "static_analysis",
                        "tools": ["file", "strings", "checksec"],
                        "estimated_time": 600
                    },
                    {
                        "phase": "disassembly",
                        "tools": ["ghidra", "radare2"],
                        "estimated_time": 1800
                    },
                    {
                        "phase": "dynamic_analysis",
                        "tools": ["gdb-peda", "ltrace", "strace"],
                        "estimated_time": 2400
                    }
                ],
                "security_features": [],
                "potential_vulns": []
            }
            
            if analysis_type == "quick":
                analysis_workflow["analysis_phases"] = analysis_workflow["analysis_phases"][:2]
            
            logger.info(f"⚙️ Binary analysis workflow for {target_arch}")
            
            return jsonify({
                "success": True,
                "workflow": analysis_workflow,
                "message": "Binary analysis workflow created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error in CTF binary analyzer: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
