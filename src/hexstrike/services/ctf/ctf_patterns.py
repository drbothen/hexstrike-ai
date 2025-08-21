"""
CTF patterns and strategies for HexStrike AI.

This module provides patterns, strategies, and tool mappings for CTF challenges.
"""

from typing import Dict, Any, List

class CTFPatterns:
    """Provides patterns and strategies for CTF challenges"""
    
    @staticmethod
    def get_category_tools() -> Dict[str, Dict[str, List[str]]]:
        """Get tools for each CTF category"""
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
    
    @staticmethod
    def get_solving_strategies() -> Dict[str, List[Dict[str, str]]]:
        """Get solving strategies for each category"""
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
    
    @staticmethod
    def get_challenge_patterns() -> Dict[str, List[Dict[str, Any]]]:
        """Get common challenge patterns and workflows"""
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
    
    @staticmethod
    def get_success_indicators() -> Dict[str, List[str]]:
        """Get success indicators for specific actions"""
        return {
            "reconnaissance": ["Live endpoints discovered", "Technology stack identified"],
            "source_analysis": ["Hidden comments found", "JavaScript secrets discovered"],
            "directory_discovery": ["Hidden directories found", "Sensitive files discovered"],
            "vulnerability_testing": ["Vulnerabilities identified", "Injection points found"],
            "cipher_identification": ["Cipher type identified", "Key characteristics determined"],
            "binary_analysis": ["Binary type identified", "Security features analyzed"],
            "file_identification": ["File types identified", "Hidden files discovered"],
            "disassembly": ["Code structure understood", "Key functions identified"]
        }
