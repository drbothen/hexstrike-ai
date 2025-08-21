"""
Recovery strategy service for error handling and recovery.

This module changes when error recovery or escalation strategies change.
"""

import os
import json
import logging
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"

@dataclass
class ErrorContext:
    """Context information for error handling decisions"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: Dict[str, Any]
    previous_errors: List['ErrorContext'] = field(default_factory=list)

@dataclass
class RecoveryStrategy:
    """Recovery strategy with configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds

    def __init__(self):
        self.tool_alternatives = {
            'nmap': ['masscan', 'zmap', 'rustscan'],
            'gobuster': ['dirb', 'dirbuster', 'ffuf'],
            'sqlmap': ['sqlninja', 'havij'],
            'nikto': ['w3af', 'skipfish'],
            'hydra': ['medusa', 'ncrack'],
            'john': ['hashcat', 'ophcrack'],
            'metasploit': ['armitage', 'cobalt_strike'],
            'burpsuite': ['owasp_zap', 'w3af'],
            'wireshark': ['tcpdump', 'tshark'],
            'aircrack': ['reaver', 'wifite']
        }
        self.error_history = []
        self.max_history_size = 1000

    def get_alternative_tool(self, failed_tool: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool for failed tool"""
        alternatives = self.tool_alternatives.get(failed_tool, [])
        
        if not alternatives:
            return None
        
        # Filter alternatives based on context requirements
        filtered_alternatives = []
        for alt in alternatives:
            if context.get('require_no_privileges') and alt in ['nmap', 'masscan']:
                continue  # Skip tools that typically require privileges
            if context.get('prefer_faster_tools') and alt in ['amass', 'w3af']:
                continue  # Skip slower tools
            filtered_alternatives.append(alt)
        
        if not filtered_alternatives:
            filtered_alternatives = alternatives
        
        # Return first available alternative
        return filtered_alternatives[0] if filtered_alternatives else None
    
    def escalate_to_human(self, context: ErrorContext, urgency: str = "medium") -> Dict[str, Any]:
        """Escalate complex errors to human operator with full context"""
        escalation_data = {
            "timestamp": context.timestamp.isoformat(),
            "tool": context.tool_name,
            "target": context.target,
            "error_type": context.error_type.value,
            "error_message": context.error_message,
            "attempt_count": context.attempt_count,
            "urgency": urgency,
            "suggested_actions": self._get_human_suggestions(context),
            "context": {
                "parameters": context.parameters,
                "system_resources": context.system_resources,
                "recent_errors": [e.error_message for e in context.previous_errors[-5:]]
            }
        }
        
        # Log escalation with enhanced formatting
        logger.error(f"CRITICAL ERROR - HUMAN ESCALATION REQUIRED")
        logger.error(f"Tool: {context.tool_name} | Error: {context.error_message}")
        logger.error(f"ESCALATION DETAILS:")
        logger.error(f"{json.dumps(escalation_data, indent=2)}")
        
        return escalation_data
    
    def _get_human_suggestions(self, context: ErrorContext) -> List[str]:
        """Get human-readable suggestions for error resolution"""
        suggestions = []
        
        if context.error_type == ErrorType.PERMISSION_DENIED:
            suggestions.extend([
                "Run the command with sudo privileges",
                "Check file/directory permissions",
                "Verify user is in required groups"
            ])
        elif context.error_type == ErrorType.TOOL_NOT_FOUND:
            suggestions.extend([
                f"Install {context.tool_name} using package manager",
                "Check if tool is in PATH",
                "Verify tool installation"
            ])
        elif context.error_type == ErrorType.NETWORK_UNREACHABLE:
            suggestions.extend([
                "Check network connectivity",
                "Verify target is accessible",
                "Check firewall rules"
            ])
        elif context.error_type == ErrorType.RATE_LIMITED:
            suggestions.extend([
                "Wait before retrying",
                "Use slower scan rates",
                "Check API rate limits"
            ])
        else:
            suggestions.append("Review error details and logs")
        
        return suggestions
    
    def _get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource information"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None,
                "active_processes": len(psutil.pids())
            }
        except Exception:
            return {"error": "Unable to get system resources"}
    
    def _add_to_history(self, error_context: ErrorContext):
        """Add error context to history"""
        self.error_history.append(error_context)
        
        # Maintain history size limit
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        if not self.error_history:
            return {"total_errors": 0}
        
        error_counts = {}
        tool_errors = {}
        recent_errors = []
        
        # Count errors by type and tool
        for error in self.error_history:
            error_type = error.error_type.value
            tool = error.tool_name
            
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            tool_errors[tool] = tool_errors.get(tool, 0) + 1
            
            # Recent errors (last hour)
            if (datetime.now() - error.timestamp).total_seconds() < 3600:
                recent_errors.append({
                    "tool": tool,
                    "error_type": error_type,
                    "timestamp": error.timestamp.isoformat()
                })
        
        return {
            "total_errors": len(self.error_history),
            "error_counts_by_type": error_counts,
            "error_counts_by_tool": tool_errors,
            "recent_errors_count": len(recent_errors),
            "recent_errors": recent_errors[-10:]  # Last 10 recent errors
        }
