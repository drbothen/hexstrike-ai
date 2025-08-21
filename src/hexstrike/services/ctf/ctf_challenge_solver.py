"""
CTF challenge solving strategies and automation.

This module changes when CTF solving strategies or challenge types change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str
    points: int
    description: str = ""
    files: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    url: str = ""

class CTFChallengeSolver:
    """Automated CTF challenge solving strategies"""
    
    def __init__(self):
        self.solving_strategies = self._initialize_solving_strategies()
        self.category_tools = self._initialize_category_tools()
    
    def _initialize_solving_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Initialize solving strategies by category"""
        return {
            "web": {
                "description": "Web application security challenges",
                "common_techniques": ["sql_injection", "xss", "directory_traversal", "command_injection"],
                "tools": ["burpsuite", "sqlmap", "gobuster", "nikto", "ffuf"],
                "automated_steps": [
                    {"step": "reconnaissance", "tools": ["nmap", "gobuster"]},
                    {"step": "vulnerability_scanning", "tools": ["nikto", "nuclei"]},
                    {"step": "exploitation", "tools": ["sqlmap", "burpsuite"]}
                ]
            },
            "crypto": {
                "description": "Cryptography challenges",
                "common_techniques": ["frequency_analysis", "cipher_identification", "key_recovery"],
                "tools": ["john", "hashcat", "cyberchef", "sage", "python"],
                "automated_steps": [
                    {"step": "cipher_identification", "tools": ["cyberchef", "python"]},
                    {"step": "cryptanalysis", "tools": ["sage", "python"]},
                    {"step": "brute_force", "tools": ["john", "hashcat"]}
                ]
            },
            "forensics": {
                "description": "Digital forensics challenges",
                "common_techniques": ["file_analysis", "metadata_extraction", "steganography"],
                "tools": ["binwalk", "strings", "exiftool", "volatility", "autopsy"],
                "automated_steps": [
                    {"step": "file_identification", "tools": ["file", "binwalk"]},
                    {"step": "metadata_analysis", "tools": ["exiftool", "strings"]},
                    {"step": "data_recovery", "tools": ["volatility", "autopsy"]}
                ]
            },
            "reverse": {
                "description": "Reverse engineering challenges",
                "common_techniques": ["static_analysis", "dynamic_analysis", "decompilation"],
                "tools": ["ghidra", "ida", "gdb", "radare2", "objdump"],
                "automated_steps": [
                    {"step": "static_analysis", "tools": ["ghidra", "strings", "objdump"]},
                    {"step": "dynamic_analysis", "tools": ["gdb", "strace"]},
                    {"step": "exploitation", "tools": ["pwntools", "ropper"]}
                ]
            },
            "pwn": {
                "description": "Binary exploitation challenges",
                "common_techniques": ["buffer_overflow", "rop_chains", "format_strings"],
                "tools": ["gdb", "pwntools", "ropper", "checksec", "one_gadget"],
                "automated_steps": [
                    {"step": "binary_analysis", "tools": ["checksec", "ghidra"]},
                    {"step": "vulnerability_discovery", "tools": ["gdb", "fuzzing"]},
                    {"step": "exploit_development", "tools": ["pwntools", "ropper"]}
                ]
            },
            "misc": {
                "description": "Miscellaneous challenges",
                "common_techniques": ["scripting", "automation", "custom_tools"],
                "tools": ["python", "bash", "netcat", "socat"],
                "automated_steps": [
                    {"step": "problem_analysis", "tools": ["python", "bash"]},
                    {"step": "solution_development", "tools": ["python", "custom"]},
                    {"step": "automation", "tools": ["bash", "python"]}
                ]
            }
        }
    
    def _initialize_category_tools(self) -> Dict[str, List[str]]:
        """Initialize tools by category"""
        return {
            "web": ["burpsuite", "sqlmap", "gobuster", "nikto", "ffuf", "nuclei", "katana"],
            "crypto": ["john", "hashcat", "cyberchef", "sage", "python", "openssl"],
            "forensics": ["binwalk", "strings", "exiftool", "volatility", "autopsy", "sleuthkit"],
            "reverse": ["ghidra", "ida", "gdb", "radare2", "objdump", "ltrace", "strace"],
            "pwn": ["gdb", "pwntools", "ropper", "checksec", "one_gadget", "angr"],
            "misc": ["python", "bash", "netcat", "socat", "curl", "wget"]
        }
    
    def auto_solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Attempt to automatically solve a CTF challenge"""
        category = challenge.category.lower()
        strategy = self.solving_strategies.get(category, {})
        
        if not strategy:
            return {
                "success": False,
                "error": f"No solving strategy for category: {category}",
                "suggested_tools": ["manual_analysis"]
            }
        
        workflow = {
            "challenge": challenge.name,
            "category": category,
            "strategy": strategy["description"],
            "steps": [],
            "estimated_time": 0
        }
        
        for step_info in strategy.get("automated_steps", []):
            step = {
                "name": step_info["step"],
                "tools": step_info["tools"],
                "estimated_time": self._estimate_step_time(step_info["step"], category),
                "success_probability": self._estimate_success_probability(step_info["step"], category)
            }
            workflow["steps"].append(step)
            workflow["estimated_time"] += step["estimated_time"]
        
        return {
            "success": True,
            "workflow": workflow,
            "recommended_tools": strategy.get("tools", []),
            "techniques": strategy.get("common_techniques", [])
        }
    
    def _estimate_step_time(self, step: str, category: str) -> int:
        """Estimate time for a solving step"""
        time_estimates = {
            "reconnaissance": 300,
            "vulnerability_scanning": 600,
            "exploitation": 1200,
            "cipher_identification": 180,
            "cryptanalysis": 900,
            "brute_force": 1800,
            "file_identification": 120,
            "metadata_analysis": 300,
            "data_recovery": 600,
            "static_analysis": 900,
            "dynamic_analysis": 1200,
            "binary_analysis": 600,
            "vulnerability_discovery": 1800,
            "exploit_development": 2400,
            "problem_analysis": 300,
            "solution_development": 1200,
            "automation": 600
        }
        
        base_time = time_estimates.get(step, 600)
        
        category_multipliers = {
            "crypto": 1.5,
            "reverse": 1.8,
            "pwn": 2.0,
            "forensics": 1.3,
            "web": 1.0,
            "misc": 1.2
        }
        
        multiplier = category_multipliers.get(category, 1.0)
        return int(base_time * multiplier)
    
    def _estimate_success_probability(self, step: str, category: str) -> float:
        """Estimate success probability for a solving step"""
        base_probabilities = {
            "reconnaissance": 0.9,
            "vulnerability_scanning": 0.8,
            "exploitation": 0.6,
            "cipher_identification": 0.7,
            "cryptanalysis": 0.5,
            "brute_force": 0.4,
            "file_identification": 0.95,
            "metadata_analysis": 0.8,
            "data_recovery": 0.6,
            "static_analysis": 0.8,
            "dynamic_analysis": 0.7,
            "binary_analysis": 0.85,
            "vulnerability_discovery": 0.6,
            "exploit_development": 0.4,
            "problem_analysis": 0.8,
            "solution_development": 0.5,
            "automation": 0.7
        }
        
        return base_probabilities.get(step, 0.5)
    
    def suggest_tools_for_challenge(self, challenge: CTFChallenge) -> List[str]:
        """Suggest tools for a specific challenge"""
        category = challenge.category.lower()
        tools = self.category_tools.get(category, [])
        
        if challenge.files:
            if any(f.endswith(('.exe', '.bin', '.elf')) for f in challenge.files):
                tools.extend(["ghidra", "gdb", "radare2"])
            if any(f.endswith(('.pcap', '.pcapng')) for f in challenge.files):
                tools.extend(["wireshark", "tcpdump"])
            if any(f.endswith(('.zip', '.tar', '.gz')) for f in challenge.files):
                tools.extend(["binwalk", "7zip"])
        
        if challenge.url:
            tools.extend(["burpsuite", "gobuster", "nikto"])
        
        return list(set(tools))
