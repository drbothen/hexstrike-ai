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
        self.category_tools = self._initialize_category_tools()
        self.solving_strategies = self._initialize_solving_strategies()
        self.challenge_patterns = self._initialize_challenge_patterns()
    
    def _initialize_category_tools(self) -> Dict[str, Dict[str, List[str]]]:
        """Initialize tools for each CTF category"""
        return {
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
    
    def _initialize_solving_strategies(self) -> Dict[str, List[Dict[str, str]]]:
        """Initialize solving strategies for each category"""
        return {
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
                {"strategy": "race_conditions", "description": "Exploit race condition vulnerabilities"},
                {"strategy": "integer_overflow", "description": "Exploit integer overflow conditions"}
            ],
            "forensics": [
                {"strategy": "file_carving", "description": "Recover deleted or hidden files"},
                {"strategy": "metadata_analysis", "description": "Analyze file metadata for hidden information"},
                {"strategy": "steganography", "description": "Extract hidden data from images/audio"},
                {"strategy": "memory_analysis", "description": "Analyze memory dumps for artifacts"},
                {"strategy": "network_analysis", "description": "Analyze network traffic for suspicious activity"},
                {"strategy": "timeline_analysis", "description": "Reconstruct timeline of events"}
            ],
            "rev": [
                {"strategy": "static_analysis", "description": "Analyze binary without execution"},
                {"strategy": "dynamic_analysis", "description": "Analyze binary during execution"},
                {"strategy": "anti_debugging", "description": "Bypass anti-debugging techniques"},
                {"strategy": "unpacking", "description": "Unpack packed/obfuscated binaries"},
                {"strategy": "algorithm_recovery", "description": "Reverse engineer algorithms"},
                {"strategy": "key_recovery", "description": "Extract encryption keys from binaries"}
            ]
        }
    
    def _initialize_challenge_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Initialize common challenge patterns and workflows"""
        return {
            "web": [
                {"step": 1, "action": "reconnaissance", "description": "Initial web reconnaissance", "parallel": True, "tools": ["httpx", "katana"], "estimated_time": 300},
                {"step": 2, "action": "source_analysis", "description": "Analyze source code and comments", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "directory_discovery", "description": "Discover hidden directories and files", "parallel": True, "tools": ["gobuster", "dirsearch"], "estimated_time": 900},
                {"step": 4, "action": "vulnerability_testing", "description": "Test for common web vulnerabilities", "parallel": True, "tools": ["sqlmap", "dalfox", "nuclei"], "estimated_time": 1200},
                {"step": 5, "action": "parameter_fuzzing", "description": "Fuzz parameters for hidden functionality", "parallel": False, "tools": ["arjun", "ffuf"], "estimated_time": 800},
                {"step": 6, "action": "exploitation", "description": "Exploit discovered vulnerabilities", "parallel": False, "tools": ["manual"], "estimated_time": 1800}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify cipher type and characteristics", "parallel": False, "tools": ["cipher-identifier"], "estimated_time": 300},
                {"step": 2, "action": "frequency_analysis", "description": "Perform frequency analysis", "parallel": False, "tools": ["frequency-analyzer"], "estimated_time": 600},
                {"step": 3, "action": "pattern_analysis", "description": "Look for patterns and repetitions", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 4, "action": "known_attacks", "description": "Try known cryptographic attacks", "parallel": True, "tools": ["hashcat", "john"], "estimated_time": 1800},
                {"step": 5, "action": "mathematical_analysis", "description": "Apply mathematical cryptanalysis", "parallel": False, "tools": ["sage", "python"], "estimated_time": 2400}
            ],
            "pwn": [
                {"step": 1, "action": "binary_analysis", "description": "Analyze binary characteristics", "parallel": True, "tools": ["checksec", "file", "strings"], "estimated_time": 300},
                {"step": 2, "action": "disassembly", "description": "Disassemble and analyze code", "parallel": False, "tools": ["ghidra", "radare2"], "estimated_time": 1800},
                {"step": 3, "action": "vulnerability_identification", "description": "Identify potential vulnerabilities", "parallel": False, "tools": ["manual"], "estimated_time": 1200},
                {"step": 4, "action": "exploit_development", "description": "Develop exploit payload", "parallel": False, "tools": ["pwntools", "ropper"], "estimated_time": 2400},
                {"step": 5, "action": "exploitation", "description": "Execute exploit and capture flag", "parallel": False, "tools": ["manual"], "estimated_time": 600}
            ],
            "forensics": [
                {"step": 1, "action": "file_identification", "description": "Identify file types and structure", "parallel": True, "tools": ["file", "binwalk"], "estimated_time": 300},
                {"step": 2, "action": "metadata_extraction", "description": "Extract metadata and hidden information", "parallel": True, "tools": ["exiftool", "strings"], "estimated_time": 600},
                {"step": 3, "action": "file_carving", "description": "Recover hidden or deleted files", "parallel": True, "tools": ["foremost", "photorec"], "estimated_time": 1200},
                {"step": 4, "action": "steganography_analysis", "description": "Check for steganographic content", "parallel": True, "tools": ["steghide", "stegsolve"], "estimated_time": 900},
                {"step": 5, "action": "memory_analysis", "description": "Analyze memory dumps if present", "parallel": False, "tools": ["volatility"], "estimated_time": 1800},
                {"step": 6, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events", "parallel": False, "tools": ["manual"], "estimated_time": 1200}
            ],
            "rev": [
                {"step": 1, "action": "binary_triage", "description": "Initial binary triage and classification", "parallel": True, "tools": ["file", "strings", "checksec"], "estimated_time": 300},
                {"step": 2, "action": "packer_detection", "description": "Detect and unpack if necessary", "parallel": False, "tools": ["upx", "peid"], "estimated_time": 600},
                {"step": 3, "action": "static_disassembly", "description": "Static disassembly and analysis", "parallel": True, "tools": ["ghidra", "radare2"], "estimated_time": 2400},
                {"step": 4, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": False, "tools": ["gdb-peda", "ltrace"], "estimated_time": 1800},
                {"step": 5, "action": "algorithm_recovery", "description": "Reverse engineer key algorithms", "parallel": False, "tools": ["manual"], "estimated_time": 3600}
            ]
        }
    
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
        indicators = {
            "reconnaissance": ["Live endpoints discovered", "Technology stack identified"],
            "source_analysis": ["Hidden comments found", "JavaScript secrets discovered"],
            "directory_discovery": ["Hidden directories found", "Sensitive files discovered"],
            "vulnerability_testing": ["Vulnerabilities identified", "Injection points found"],
            "cipher_identification": ["Cipher type identified", "Key characteristics determined"],
            "binary_analysis": ["Binary type identified", "Security features analyzed"],
            "file_identification": ["File types identified", "Hidden files discovered"],
            "disassembly": ["Code structure understood", "Key functions identified"]
        }
        
        return indicators.get(action, ["Progress made", "Information gathered"])
    
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
