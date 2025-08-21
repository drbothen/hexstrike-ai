"""
Failure recovery system with intelligent alternative tool selection.

This module changes when failure recovery or tool selection strategies change.
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class FailureRecoverySystem:
    """Intelligent failure recovery with alternative tool selection"""
    
    def __init__(self):
        self.tool_alternatives = {
            "nmap": ["rustscan", "masscan", "zmap"],
            "gobuster": ["dirsearch", "feroxbuster", "dirb"],
            "sqlmap": ["sqlninja", "bbqsql", "jsql-injection"],
            "nuclei": ["nikto", "w3af", "skipfish"],
            "hydra": ["medusa", "ncrack", "patator"],
            "hashcat": ["john", "ophcrack", "rainbowcrack"],
            "amass": ["subfinder", "sublist3r", "assetfinder"],
            "ffuf": ["wfuzz", "gobuster", "dirb"]
        }
        
        self.failure_patterns = {
            "timeout": ["timeout", "timed out", "connection timeout"],
            "permission_denied": ["permission denied", "access denied", "forbidden"],
            "not_found": ["not found", "command not found", "no such file"],
            "network_error": ["network unreachable", "connection refused", "host unreachable"],
            "rate_limited": ["rate limit", "too many requests", "throttled"],
            "authentication_required": ["authentication required", "unauthorized", "login required"]
        }
    
    def analyze_failure(self, error_output: str, exit_code: int) -> Dict[str, Any]:
        """Analyze failure and suggest recovery strategies"""
        failure_type = "unknown"
        confidence = 0.0
        recovery_strategies = []
        
        error_lower = error_output.lower()
        
        # Identify failure type
        for failure, patterns in self.failure_patterns.items():
            for pattern in patterns:
                if pattern in error_lower:
                    failure_type = failure
                    confidence += 0.3
                    break
        
        # Exit code analysis
        if exit_code == 1:
            confidence += 0.1
        elif exit_code == 124:  # timeout
            failure_type = "timeout"
            confidence += 0.5
        elif exit_code == 126:  # permission denied
            failure_type = "permission_denied"
            confidence += 0.5
        
        confidence = min(1.0, confidence)
        
        # Generate recovery strategies
        if failure_type == "timeout":
            recovery_strategies = [
                "Increase timeout values",
                "Reduce thread count",
                "Use alternative faster tool",
                "Split target into smaller chunks"
            ]
        elif failure_type == "permission_denied":
            recovery_strategies = [
                "Run with elevated privileges",
                "Check file permissions",
                "Use alternative tool with different approach"
            ]
        elif failure_type == "rate_limited":
            recovery_strategies = [
                "Implement delays between requests",
                "Reduce thread count",
                "Use stealth timing profile",
                "Rotate IP addresses if possible"
            ]
        elif failure_type == "network_error":
            recovery_strategies = [
                "Check network connectivity",
                "Try alternative network routes",
                "Use proxy or VPN",
                "Verify target is accessible"
            ]
        
        return {
            "failure_type": failure_type,
            "confidence": confidence,
            "recovery_strategies": recovery_strategies,
            "alternative_tools": self.tool_alternatives.get(self._extract_tool_name(error_output), [])
        }
    
    def _classify_failure(self, error_output: str, exit_code: int) -> str:
        """Classify the type of failure based on error output"""
        error_lower = error_output.lower()
        
        for failure_type, patterns in self.failure_patterns.items():
            for pattern in patterns:
                if pattern in error_lower:
                    return failure_type
        
        if exit_code == 124:  # timeout exit code
            return "timeout"
        elif exit_code == 126 or exit_code == 127:  # permission or not found
            return "permission" if "permission" in error_lower else "not_found"
        elif exit_code == 1:
            return "general_error"
        
        return "unknown"
    
    def _calculate_confidence(self, failure_type: str, error_output: str) -> float:
        """Calculate confidence in failure classification"""
        if failure_type == "unknown":
            return 0.3
        
        patterns = self.failure_patterns.get(failure_type, [])
        matches = sum(1 for pattern in patterns if pattern in error_output.lower())
        
        base_confidence = 0.6
        pattern_boost = min(0.4, matches * 0.1)
        
        return min(1.0, base_confidence + pattern_boost)
    
    def _summarize_error(self, error_output: str) -> str:
        """Create a concise error summary"""
        lines = error_output.strip().split('\n')
        
        relevant_lines = []
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['error', 'failed', 'exception', 'denied']):
                relevant_lines.append(line)
        
        if relevant_lines:
            return relevant_lines[0][:200]  # First relevant line, truncated
        elif lines:
            return lines[-1][:200]  # Last line if no specific error found
        else:
            return "No error details available"
    
    def _extract_tool_name(self, command: str) -> str:
        """Extract tool name from command"""
        return command.split()[0] if command else "unknown"
