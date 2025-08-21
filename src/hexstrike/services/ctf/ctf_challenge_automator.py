"""
CTF challenge automation and solving service.

This module changes when automation strategies or solving patterns change.
"""

from typing import Dict, Any, List
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str
    description: str
    points: int = 0
    difficulty: str = "unknown"
    files: List[str] = None
    url: str = ""
    hints: List[str] = None
    
    def __post_init__(self):
        if self.files is None:
            self.files = []
        if self.hints is None:
            self.hints = []

class CTFChallengeAutomator:
    """Advanced automation system for CTF challenge solving"""
    
    def __init__(self):
        self.active_challenges = {}
        self.solution_cache = {}
        self.learning_database = {}
        self.success_patterns = {}
        
    def auto_solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Attempt to automatically solve a CTF challenge"""
        result = {
            "challenge_id": challenge.name,
            "status": "in_progress",
            "automated_steps": [],
            "manual_steps": [],
            "confidence": 0.0,
            "estimated_completion": 0,
            "artifacts": [],
            "flag_candidates": [],
            "next_actions": []
        }
        
        try:
            from .ctf_workflow_manager import CTFWorkflowManager
            ctf_manager = CTFWorkflowManager()
            
            workflow = ctf_manager.create_ctf_challenge_workflow(challenge)
            
            for phase in workflow.get("phases", []):
                if phase.get("parallel", False):
                    step_result = self._execute_parallel_step(phase, challenge)
                else:
                    step_result = self._execute_sequential_step(phase, challenge)
                
                result["automated_steps"].append(step_result)
                
                flag_candidates = self._extract_flag_candidates(step_result.get("output", ""))
                result["flag_candidates"].extend(flag_candidates)
                
                if step_result.get("success", False):
                    result["confidence"] += 0.1
                
                if flag_candidates and self._validate_flag_format(flag_candidates[0]):
                    result["status"] = "solved"
                    result["flag"] = flag_candidates[0]
                    break
            
            if result["status"] != "solved":
                result["manual_steps"] = self._generate_manual_guidance(challenge, result)
                result["status"] = "needs_manual_intervention"
            
            result["confidence"] = min(1.0, result["confidence"])
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Error in auto-solve for {challenge.name}: {str(e)}")
        
        return result
    
    def _execute_parallel_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step with parallel tool execution"""
        step_result = {
            "step": step["step"],
            "action": step["name"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }
        
        start_time = time.time()
        tools = step.get("tools", [])
        
        for tool in tools:
            try:
                if tool != "manual":
                    from ..tool_execution_service import ToolExecutionService
                    execution_service = ToolExecutionService()
                    
                    tool_result = execution_service.execute_tool(tool, {
                        "target": challenge.url or challenge.name,
                        "challenge_files": challenge.files
                    })
                    
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"\n--- {tool} output ---\n{tool_result.stdout}\n"
                    
                    if tool_result.success:
                        step_result["success"] = True
                        
            except Exception as e:
                logger.error(f"Error executing tool {tool}: {str(e)}")
                step_result["output"] += f"\n--- {tool} error ---\n{str(e)}\n"
        
        step_result["execution_time"] = time.time() - start_time
        return step_result
    
    def _execute_sequential_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step with sequential tool execution"""
        step_result = {
            "step": step["step"],
            "action": step["name"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }
        
        start_time = time.time()
        tools = step.get("tools", [])
        
        for tool in tools:
            try:
                if tool == "manual":
                    step_result["output"] += f"\n--- Manual step required ---\n{step['description']}\n"
                    step_result["tools_used"].append("manual")
                    continue
                
                from ..tool_execution_service import ToolExecutionService
                execution_service = ToolExecutionService()
                
                tool_result = execution_service.execute_tool(tool, {
                    "target": challenge.url or challenge.name,
                    "challenge_files": challenge.files
                })
                
                step_result["tools_used"].append(tool)
                step_result["output"] += f"\n--- {tool} output ---\n{tool_result.stdout}\n"
                
                if tool_result.success:
                    step_result["success"] = True
                    break
                    
            except Exception as e:
                logger.error(f"Error executing tool {tool}: {str(e)}")
                step_result["output"] += f"\n--- {tool} error ---\n{str(e)}\n"
        
        step_result["execution_time"] = time.time() - start_time
        return step_result
    
    def _extract_flag_candidates(self, output: str) -> List[str]:
        """Extract potential flags from tool output"""
        import re
        
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}',
            r'[0-9a-f]{32}',
            r'[0-9a-f]{40}',
            r'[0-9a-f]{64}'
        ]
        
        candidates = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            candidates.extend(matches)
        
        return list(set(candidates))
    
    def _validate_flag_format(self, flag: str) -> bool:
        """Validate if string matches common flag formats"""
        import re
        
        common_formats = [
            r'^flag\{.+\}$',
            r'^FLAG\{.+\}$',
            r'^ctf\{.+\}$',
            r'^CTF\{.+\}$',
            r'^[a-zA-Z0-9_]+\{.+\}$',
            r'^[0-9a-f]{32}$',
            r'^[0-9a-f]{40}$',
            r'^[0-9a-f]{64}$'
        ]
        
        for pattern in common_formats:
            if re.match(pattern, flag, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_manual_guidance(self, challenge: CTFChallenge, 
                                 automation_result: Dict[str, Any]) -> List[str]:
        """Generate manual guidance based on automation results"""
        guidance = []
        
        category = challenge.category.lower()
        
        if category == "web":
            guidance.extend([
                "Manually inspect the web application using browser developer tools",
                "Check for hidden form fields, comments in source code",
                "Test for common web vulnerabilities (SQL injection, XSS, etc.)",
                "Analyze JavaScript code for client-side logic flaws",
                "Check robots.txt, sitemap.xml, and other common files"
            ])
        
        elif category == "crypto":
            guidance.extend([
                "Analyze the encryption algorithm and key generation",
                "Look for weak keys, poor randomness, or implementation flaws",
                "Try frequency analysis for substitution ciphers",
                "Check for known plaintext attacks",
                "Consider mathematical attacks on the cryptographic scheme"
            ])
        
        elif category == "pwn":
            guidance.extend([
                "Analyze the binary for buffer overflows and format string bugs",
                "Check for stack canaries, ASLR, and other protections",
                "Build ROP chains or use return-to-libc attacks",
                "Look for heap exploitation opportunities",
                "Use debugging tools to understand program flow"
            ])
        
        elif category == "forensics":
            guidance.extend([
                "Examine file headers and metadata for hidden information",
                "Use steganography tools to extract hidden data from images",
                "Analyze memory dumps for process information and artifacts",
                "Check network captures for suspicious traffic patterns",
                "Look for deleted files and file system artifacts"
            ])
        
        elif category == "rev":
            guidance.extend([
                "Disassemble and analyze the binary's control flow",
                "Look for anti-debugging and obfuscation techniques",
                "Identify key algorithms and data structures",
                "Use dynamic analysis to understand runtime behavior",
                "Patch or modify the binary to bypass protections"
            ])
        
        elif category == "misc":
            guidance.extend([
                "Try different encoding/decoding schemes",
                "Look for patterns in the data or challenge description",
                "Consider esoteric programming languages",
                "Check for hidden data in unusual file formats",
                "Think outside the box for unconventional solutions"
            ])
        
        elif category == "osint":
            guidance.extend([
                "Search for information using various search engines and databases",
                "Analyze social media profiles and public records",
                "Use reverse image search and metadata analysis",
                "Check domain registration and certificate information",
                "Look for leaked credentials or sensitive information"
            ])
        
        else:
            guidance.extend([
                "Carefully read the challenge description for clues",
                "Analyze any provided files or URLs",
                "Research the challenge topic and related techniques",
                "Try different approaches and tools",
                "Collaborate with team members for different perspectives"
            ])
        
        if automation_result.get("flag_candidates"):
            guidance.append("Review the flag candidates found by automation tools")
        
        if automation_result.get("artifacts"):
            guidance.append("Examine the artifacts generated during automated analysis")
        
        return guidance
