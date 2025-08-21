"""
Error handling service with intelligent recovery strategies.

This module changes when error patterns or recovery strategies change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import logging
import re

logger = logging.getLogger(__name__)

class ErrorType(Enum):
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
    estimated_time: int

class IntelligentErrorHandler:
    """Advanced error handling with automatic recovery strategies"""
    
    def __init__(self):
        self.error_patterns = self._initialize_error_patterns()
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.tool_alternatives = self._initialize_tool_alternatives()
        self.parameter_adjustments = self._initialize_parameter_adjustments()
        self.error_history = []
        self.max_history_size = 1000
        
    def _initialize_error_patterns(self) -> Dict[str, ErrorType]:
        """Initialize error pattern recognition"""
        return {
            r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
            r"operation timed out|command timeout": ErrorType.TIMEOUT,
            
            r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
            r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,
            
            r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
            r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,
            
            r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
            r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,
            
            r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
            r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,
            
            r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
            r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,
            
            r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
            r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,
            
            r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
            r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,
            
            r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
            r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,
            
            r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
            r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR
        }
    
    def _initialize_recovery_strategies(self) -> Dict[ErrorType, List[RecoveryStrategy]]:
        """Initialize recovery strategies for different error types"""
        return {
            ErrorType.TIMEOUT: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 5, "max_delay": 60},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.7,
                    estimated_time=30
                ),
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                    parameters={"reduce_threads": True, "reduce_timeout": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=45
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_faster_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=60
                )
            ],
            ErrorType.PERMISSION_DENIED: [
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"remove_privileged_options": True, "use_user_mode": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=15
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_unprivileged_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=30
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"reason": "elevated_privileges_required"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                )
            ],
            ErrorType.NETWORK_UNREACHABLE: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 10, "max_delay": 120},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.5,
                    estimated_time=60
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"use_different_ports": True, "try_alternative_protocols": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=45
                ),
                RecoveryStrategy(
                    action=RecoveryAction.GRACEFUL_DEGRADATION,
                    parameters={"skip_network_dependent_operations": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=20
                )
            ],
            ErrorType.RATE_LIMITED: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 60, "max_delay": 600, "exponential": True},
                    max_attempts=5,
                    backoff_multiplier=2.0,
                    success_probability=0.9,
                    estimated_time=300
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"reduce_request_rate": True, "increase_delays": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=180
                )
            ],
            ErrorType.TOOL_NOT_FOUND: [
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"find_equivalent_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=30
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"reason": "tool_installation_required"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=600
                )
            ],
            ErrorType.INVALID_PARAMETERS: [
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"use_default_parameters": True, "remove_invalid_options": True},
                    max_attempts=3,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=20
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_simpler_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=45
                )
            ],
            ErrorType.RESOURCE_EXHAUSTED: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                    parameters={"reduce_memory_usage": True, "reduce_parallelism": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=60
                ),
                RecoveryStrategy(
                    action=RecoveryAction.GRACEFUL_DEGRADATION,
                    parameters={"skip_resource_intensive_operations": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=30
                )
            ]
        }
    
    def _initialize_tool_alternatives(self) -> Dict[str, List[str]]:
        """Initialize tool alternatives for common tools"""
        return {
            "nmap": ["rustscan", "masscan", "zmap"],
            "gobuster": ["feroxbuster", "dirsearch", "ffuf"],
            "sqlmap": ["nuclei", "w3af", "manual_testing"],
            "nikto": ["nuclei", "w3af", "whatweb"],
            "amass": ["subfinder", "assetfinder", "findomain"],
            "subfinder": ["amass", "assetfinder", "findomain"],
            "httpx": ["curl", "wget", "requests"],
            "nuclei": ["jaeles", "nikto", "w3af"],
            "ffuf": ["gobuster", "wfuzz", "feroxbuster"],
            "wfuzz": ["ffuf", "gobuster", "feroxbuster"],
            "burpsuite": ["zap", "w3af", "manual_testing"],
            "metasploit": ["manual_exploitation", "custom_scripts"],
            "john": ["hashcat", "hydra", "medusa"],
            "hashcat": ["john", "hydra", "medusa"],
            "hydra": ["medusa", "ncrack", "patator"],
            "wireshark": ["tcpdump", "tshark", "networkminer"],
            "volatility": ["rekall", "manual_analysis"],
            "binwalk": ["foremost", "photorec", "scalpel"],
            "ghidra": ["ida", "radare2", "binary-ninja"],
            "radare2": ["ghidra", "ida", "objdump"],
            "gdb": ["lldb", "windbg", "x64dbg"]
        }
    
    def _initialize_parameter_adjustments(self) -> Dict[str, Dict[str, Any]]:
        """Initialize parameter adjustments for error recovery"""
        return {
            "timeout_reduction": {
                "nmap": {"timing": "T3", "host_timeout": "30s"},
                "gobuster": {"timeout": "10s", "threads": "10"},
                "sqlmap": {"timeout": "30", "threads": "1"},
                "nuclei": {"timeout": "10", "rate_limit": "100"}
            },
            "scope_reduction": {
                "nmap": {"top_ports": "1000", "skip_host_discovery": True},
                "gobuster": {"wordlist": "common.txt", "extensions": "php,html"},
                "amass": {"passive": True, "timeout": "10m"},
                "nuclei": {"severity": "high,critical", "tags": "cve"}
            },
            "privilege_reduction": {
                "nmap": {"unprivileged": True, "no_ping": True},
                "masscan": {"rate": "1000", "wait": "3"},
                "tcpdump": {"interface": "any", "count": "100"}
            }
        }
    
    def classify_error(self, error_message: str, exception: Exception) -> ErrorType:
        """Classify error based on message and exception type"""
        error_text = f"{error_message} {str(exception)}".lower()
        
        for pattern, error_type in self.error_patterns.items():
            if re.search(pattern, error_text, re.IGNORECASE):
                return error_type
        
        return ErrorType.UNKNOWN
    
    def handle_tool_failure(self, tool_name: str, exception: Exception, context: Dict[str, Any]):
        """Handle tool failure with intelligent recovery"""
        error_type = self.classify_error(str(exception), exception)
        
        error_context = ErrorContext(
            tool_name=tool_name,
            target=context.get("target", "unknown"),
            parameters=context.get("parameters", {}),
            error_type=error_type,
            error_message=str(exception),
            attempt_count=context.get("attempt_count", 1),
            timestamp=datetime.now(),
            stack_trace=str(exception.__traceback__) if hasattr(exception, '__traceback__') else "",
            system_resources=self._get_system_resources(),
            previous_errors=context.get("previous_errors", [])
        )
        
        self._add_to_history(error_context)
        
        strategies = self.recovery_strategies.get(error_type, [])
        if not strategies:
            return self.escalate_to_human(error_context)
        
        best_strategy = self._select_best_strategy(strategies, error_context)
        
        if best_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
            return self.get_alternative_tool(tool_name, context)
        elif best_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
            return self.auto_adjust_parameters(tool_name, context)
        elif best_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
            return self.escalate_to_human(error_context)
        else:
            return {
                "action": best_strategy.action.value,
                "parameters": best_strategy.parameters,
                "estimated_time": best_strategy.estimated_time,
                "success_probability": best_strategy.success_probability
            }
    
    def _select_best_strategy(self, strategies: List[RecoveryStrategy], context: ErrorContext) -> RecoveryStrategy:
        """Select the best recovery strategy based on context"""
        if context.attempt_count <= 1:
            return strategies[0]
        elif context.attempt_count <= 3:
            return strategies[min(1, len(strategies) - 1)]
        else:
            return strategies[-1]
    
    def auto_adjust_parameters(self, tool_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically adjust tool parameters for recovery"""
        adjustments = {}
        
        if "timeout" in str(context.get("error_message", "")).lower():
            timeout_adj = self.parameter_adjustments.get("timeout_reduction", {}).get(tool_name, {})
            adjustments.update(timeout_adj)
        
        if "permission" in str(context.get("error_message", "")).lower():
            privilege_adj = self.parameter_adjustments.get("privilege_reduction", {}).get(tool_name, {})
            adjustments.update(privilege_adj)
        
        if "memory" in str(context.get("error_message", "")).lower():
            scope_adj = self.parameter_adjustments.get("scope_reduction", {}).get(tool_name, {})
            adjustments.update(scope_adj)
        
        return {
            "adjusted_parameters": adjustments,
            "original_parameters": context.get("parameters", {}),
            "adjustment_reason": "automatic_error_recovery"
        }
    
    def get_alternative_tool(self, tool_name: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool for failed tool"""
        alternatives = self.tool_alternatives.get(tool_name, [])
        
        if not alternatives:
            return None
        
        failed_tools = context.get("failed_tools", [])
        for alt_tool in alternatives:
            if alt_tool not in failed_tools:
                return alt_tool
        
        return alternatives[0] if alternatives else None
    
    def escalate_to_human(self, error_context: ErrorContext) -> Dict[str, Any]:
        """Escalate error to human operator"""
        return {
            "action": "escalate_to_human",
            "error_context": {
                "tool": error_context.tool_name,
                "error_type": error_context.error_type.value,
                "error_message": error_context.error_message,
                "target": error_context.target,
                "attempt_count": error_context.attempt_count,
                "timestamp": error_context.timestamp.isoformat()
            },
            "suggestions": self._get_human_suggestions(error_context),
            "system_status": self._get_system_resources()
        }
    
    def _get_human_suggestions(self, error_context: ErrorContext) -> List[str]:
        """Generate suggestions for human operator"""
        suggestions = []
        
        if error_context.error_type == ErrorType.TOOL_NOT_FOUND:
            suggestions.append(f"Install {error_context.tool_name} or use alternative tool")
            alternatives = self.tool_alternatives.get(error_context.tool_name, [])
            if alternatives:
                suggestions.append(f"Consider using alternatives: {', '.join(alternatives[:3])}")
        
        elif error_context.error_type == ErrorType.PERMISSION_DENIED:
            suggestions.append("Run with elevated privileges or adjust tool parameters")
            suggestions.append("Check file/directory permissions for target")
        
        elif error_context.error_type == ErrorType.NETWORK_UNREACHABLE:
            suggestions.append("Check network connectivity and firewall rules")
            suggestions.append("Verify target is accessible and responsive")
        
        elif error_context.error_type == ErrorType.RATE_LIMITED:
            suggestions.append("Reduce request rate or implement delays")
            suggestions.append("Consider using API keys or premium access")
        
        else:
            suggestions.append("Review error message and adjust tool configuration")
            suggestions.append("Check system resources and dependencies")
        
        return suggestions
    
    def _get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource information"""
        import psutil
        
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
        }
    
    def _add_to_history(self, error_context: ErrorContext) -> None:
        """Add error context to history"""
        self.error_history.append(error_context)
        
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics and trends"""
        if not self.error_history:
            return {"total_errors": 0, "error_counts_by_type": {}, "error_counts_by_tool": {}}
        
        error_counts = {}
        tool_errors = {}
        recent_errors = []
        
        for error in self.error_history:
            error_type = error.error_type.value
            tool = error.tool_name
            
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            tool_errors[tool] = tool_errors.get(tool, 0) + 1
            
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
            "recent_errors": recent_errors[-10:]
        }
