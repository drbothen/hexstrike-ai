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
        self.category_tools = {
            "web": {
                "reconnaissance": ["httpx", "katana", "gau", "waybackurls"],
                "vulnerability_scanning": ["nuclei", "dalfox", "sqlmap", "nikto"],
                "content_discovery": ["gobuster", "dirsearch", "feroxbuster"],
                "parameter_testing": ["arjun", "paramspider", "x8"],
                "specialized": ["wpscan", "joomscan", "droopescan"]
            },
            "crypto": {
                "hash_analysis": ["hashcat", "john", "hash-identifier"],
                "cipher_analysis": ["cipher-identifier", "cryptool", "cyberchef"],
                "rsa_attacks": ["rsatool", "factordb", "yafu"],
                "frequency_analysis": ["frequency-analysis", "substitution-solver"],
                "modern_crypto": ["sage", "pycrypto", "cryptography"]
            },
            "pwn": {
                "binary_analysis": ["checksec", "ghidra", "radare2", "gdb-peda"],
                "exploit_development": ["pwntools", "ropper", "one-gadget"],
                "heap_exploitation": ["glibc-heap-analysis", "heap-viewer"],
                "format_string": ["format-string-exploiter"],
                "rop_chains": ["ropgadget", "ropper", "angr"]
            },
            "forensics": {
                "file_analysis": ["file", "binwalk", "foremost", "photorec"],
                "image_forensics": ["exiftool", "steghide", "stegsolve", "zsteg"],
                "memory_forensics": ["volatility", "rekall"],
                "network_forensics": ["wireshark", "tcpdump", "networkminer"],
                "disk_forensics": ["autopsy", "sleuthkit", "testdisk"]
            },
            "rev": {
                "disassemblers": ["ghidra", "ida", "radare2", "binary-ninja"],
                "debuggers": ["gdb", "x64dbg", "ollydbg"],
                "decompilers": ["ghidra", "hex-rays", "retdec"],
                "packers": ["upx", "peid", "detect-it-easy"],
                "analysis": ["strings", "ltrace", "strace", "objdump"]
            },
            "misc": {
                "encoding": ["base64", "hex", "url-decode", "rot13"],
                "compression": ["zip", "tar", "gzip", "7zip"],
                "qr_codes": ["qr-decoder", "zbar"],
                "audio_analysis": ["audacity", "sonic-visualizer"],
                "esoteric": ["brainfuck", "whitespace", "piet"]
            },
            "osint": {
                "search_engines": ["google-dorking", "shodan", "censys"],
                "social_media": ["sherlock", "social-analyzer"],
                "image_analysis": ["reverse-image-search", "exif-analysis"],
                "domain_analysis": ["whois", "dns-analysis", "certificate-transparency"],
                "geolocation": ["geoint", "osm-analysis", "satellite-imagery"]
            }
        }
        
        self.solving_strategies = {
            "web": [
                {"strategy": "source_code_analysis", "description": "Analyze HTML/JS source for hidden information"},
                {"strategy": "directory_traversal", "description": "Test for path traversal vulnerabilities"},
                {"strategy": "sql_injection", "description": "Test for SQL injection in all parameters"},
                {"strategy": "xss_exploitation", "description": "Test for XSS and exploit for admin access"},
                {"strategy": "authentication_bypass", "description": "Test for auth bypass techniques"},
                {"strategy": "session_manipulation", "description": "Analyze and manipulate session tokens"},
                {"strategy": "file_upload_bypass", "description": "Test file upload restrictions and bypasses"}
            ],
            "crypto": [
                {"strategy": "frequency_analysis", "description": "Perform frequency analysis for substitution ciphers"},
                {"strategy": "known_plaintext", "description": "Use known plaintext attacks"},
                {"strategy": "weak_keys", "description": "Test for weak cryptographic keys"},
                {"strategy": "implementation_flaws", "description": "Look for implementation vulnerabilities"},
                {"strategy": "side_channel", "description": "Exploit timing or other side channels"},
                {"strategy": "mathematical_attacks", "description": "Use mathematical properties to break crypto"}
            ],
            "pwn": [
                {"strategy": "buffer_overflow", "description": "Exploit buffer overflow vulnerabilities"},
                {"strategy": "format_string", "description": "Exploit format string vulnerabilities"},
                {"strategy": "rop_chains", "description": "Build ROP chains for exploitation"},
                {"strategy": "heap_exploitation", "description": "Exploit heap-based vulnerabilities"},
                {"strategy": "return_to_libc", "description": "Use return-to-libc attacks"},
                {"strategy": "shellcode_injection", "description": "Inject and execute shellcode"}
            ],
            "forensics": [
                {"strategy": "file_carving", "description": "Extract files from disk images or memory dumps"},
                {"strategy": "metadata_analysis", "description": "Analyze file metadata for hidden information"},
                {"strategy": "steganography", "description": "Look for hidden data in images or audio"},
                {"strategy": "timeline_analysis", "description": "Reconstruct timeline of events"},
                {"strategy": "network_analysis", "description": "Analyze network traffic for suspicious activity"},
                {"strategy": "memory_analysis", "description": "Analyze memory dumps for artifacts"}
            ],
            "rev": [
                {"strategy": "static_analysis", "description": "Analyze binary without execution"},
                {"strategy": "dynamic_analysis", "description": "Analyze binary during execution"},
                {"strategy": "anti_debugging", "description": "Bypass anti-debugging techniques"},
                {"strategy": "unpacking", "description": "Unpack packed or obfuscated binaries"},
                {"strategy": "algorithm_identification", "description": "Identify key algorithms and logic"},
                {"strategy": "patch_analysis", "description": "Modify binary to bypass protections"}
            ],
            "misc": [
                {"strategy": "pattern_recognition", "description": "Look for patterns in data or challenge"},
                {"strategy": "encoding_analysis", "description": "Try various encoding/decoding schemes"},
                {"strategy": "esoteric_languages", "description": "Consider esoteric programming languages"},
                {"strategy": "creative_thinking", "description": "Think outside the box for unique solutions"},
                {"strategy": "research_based", "description": "Research specific topics mentioned in challenge"}
            ],
            "osint": [
                {"strategy": "search_engine_dorking", "description": "Use advanced search techniques"},
                {"strategy": "social_media_analysis", "description": "Analyze social media profiles and posts"},
                {"strategy": "domain_investigation", "description": "Investigate domain registration and history"},
                {"strategy": "image_analysis", "description": "Reverse image search and metadata analysis"},
                {"strategy": "credential_hunting", "description": "Search for exposed credentials"},
                {"strategy": "geolocation", "description": "Determine location from various clues"}
            ]
        }
        
        try:
            from .ctf_patterns import CTFPatterns
            self.challenge_patterns = CTFPatterns.get_challenge_patterns()
            self.success_indicators = CTFPatterns.get_success_indicators()
        except ImportError:
            self.challenge_patterns = {}
            self.success_indicators = {}
    
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
            pattern = self._create_category_workflow(challenge.category)
        
        for step in pattern:
            phase = {
                "step": step.get("step", len(workflow["phases"]) + 1),
                "name": step.get("action", step.get("name", "unknown")),
                "description": step.get("description", ""),
                "tools": step.get("tools", []),
                "parallel": step.get("parallel", False),
                "estimated_time": step.get("estimated_time", 300),
                "success_indicators": self._get_success_indicators(challenge.category, step.get("action", step.get("name", "")))
            }
            
            workflow["phases"].append(phase)
            workflow["estimated_time"] += phase["estimated_time"]
            workflow["tools_required"].update(phase["tools"])
        
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
    
    def _create_category_workflow(self, category: str) -> List[Dict[str, Any]]:
        """Create workflow steps for specific category"""
        category_workflows = {
            "web": [
                {
                    "step": 1,
                    "action": "reconnaissance",
                    "description": "Web application reconnaissance",
                    "tools": ["httpx", "katana", "whatweb"],
                    "parallel": True,
                    "estimated_time": 300
                },
                {
                    "step": 2,
                    "action": "content_discovery",
                    "description": "Discover hidden content and directories",
                    "tools": ["gobuster", "feroxbuster", "dirsearch"],
                    "parallel": True,
                    "estimated_time": 600
                },
                {
                    "step": 3,
                    "action": "vulnerability_scanning",
                    "description": "Scan for web vulnerabilities",
                    "tools": ["nuclei", "dalfox", "sqlmap"],
                    "parallel": False,
                    "estimated_time": 900
                }
            ],
            "crypto": [
                {
                    "step": 1,
                    "action": "cipher_identification",
                    "description": "Identify cipher type and characteristics",
                    "tools": ["cipher-identifier", "hash-identifier"],
                    "parallel": True,
                    "estimated_time": 180
                },
                {
                    "step": 2,
                    "action": "cryptanalysis",
                    "description": "Perform cryptanalysis based on cipher type",
                    "tools": ["frequency-analysis", "substitution-solver"],
                    "parallel": False,
                    "estimated_time": 1200
                }
            ],
            "pwn": [
                {
                    "step": 1,
                    "action": "binary_analysis",
                    "description": "Analyze binary for vulnerabilities",
                    "tools": ["checksec", "ghidra", "strings"],
                    "parallel": True,
                    "estimated_time": 600
                },
                {
                    "step": 2,
                    "action": "exploit_development",
                    "description": "Develop exploit for identified vulnerabilities",
                    "tools": ["pwntools", "gdb-peda", "ropper"],
                    "parallel": False,
                    "estimated_time": 1800
                }
            ],
            "forensics": [
                {
                    "step": 1,
                    "action": "file_analysis",
                    "description": "Analyze provided files for hidden data",
                    "tools": ["file", "binwalk", "exiftool"],
                    "parallel": True,
                    "estimated_time": 300
                },
                {
                    "step": 2,
                    "action": "data_extraction",
                    "description": "Extract hidden or deleted data",
                    "tools": ["foremost", "steghide", "volatility"],
                    "parallel": False,
                    "estimated_time": 900
                }
            ],
            "rev": [
                {
                    "step": 1,
                    "action": "disassembly",
                    "description": "Disassemble and analyze binary",
                    "tools": ["ghidra", "radare2", "ida"],
                    "parallel": True,
                    "estimated_time": 900
                },
                {
                    "step": 2,
                    "action": "dynamic_analysis",
                    "description": "Analyze binary during execution",
                    "tools": ["gdb", "ltrace", "strace"],
                    "parallel": False,
                    "estimated_time": 600
                }
            ],
            "misc": [
                {
                    "step": 1,
                    "action": "pattern_analysis",
                    "description": "Analyze challenge for patterns and clues",
                    "tools": ["manual"],
                    "parallel": False,
                    "estimated_time": 600
                },
                {
                    "step": 2,
                    "action": "encoding_analysis",
                    "description": "Try various encoding schemes",
                    "tools": ["base64", "hex", "rot13"],
                    "parallel": True,
                    "estimated_time": 300
                }
            ],
            "osint": [
                {
                    "step": 1,
                    "action": "information_gathering",
                    "description": "Gather information from various sources",
                    "tools": ["google-dorking", "sherlock", "whois"],
                    "parallel": True,
                    "estimated_time": 900
                },
                {
                    "step": 2,
                    "action": "analysis_correlation",
                    "description": "Analyze and correlate gathered information",
                    "tools": ["manual"],
                    "parallel": False,
                    "estimated_time": 600
                }
            ]
        }
        
        return category_workflows.get(category, [
            {
                "step": 1,
                "action": "manual_analysis",
                "description": "Manual analysis and problem solving",
                "tools": ["manual"],
                "parallel": False,
                "estimated_time": 1800
            }
        ])
    
    def create_ctf_team_strategy(self, team_size: int, time_limit: int, 
                               challenges: List[CTFChallenge]) -> Dict[str, Any]:
        """Create team strategy for CTF competition"""
        strategy = {
            "team_size": team_size,
            "time_limit_minutes": time_limit,
            "total_challenges": len(challenges),
            "challenge_allocation": {},
            "priority_order": [],
            "estimated_completion": 0
        }
        
        challenges_by_category = {}
        for challenge in challenges:
            if challenge.category not in challenges_by_category:
                challenges_by_category[challenge.category] = []
            challenges_by_category[challenge.category].append(challenge)
        
        sorted_challenges = sorted(challenges, key=lambda x: (x.difficulty, -x.points))
        
        for i, challenge in enumerate(sorted_challenges):
            team_member = i % team_size
            if team_member not in strategy["challenge_allocation"]:
                strategy["challenge_allocation"][team_member] = []
            strategy["challenge_allocation"][team_member].append(challenge.name)
        
        strategy["priority_order"] = [c.name for c in sorted_challenges]
        
        return strategy
