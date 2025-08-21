"""
Error handling and recovery strategies.

This module changes when error classification, recovery strategies, or error reporting changes.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ErrorType(Enum):
    """Error classification enumeration"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_TARGET = "invalid_target"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    CONNECTION_REFUSED = "connection_refused"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    SSL_ERROR = "ssl_error"
    PARSING_ERROR = "parsing_error"
    UNKNOWN_ERROR = "unknown_error"

class RecoveryAction(Enum):
    """Available recovery actions"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    SKIP_AND_CONTINUE = "skip_and_continue"
    ABORT_OPERATION = "abort_operation"

@dataclass
class ErrorContext:
    """Error context information"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: Optional[str] = None
    system_resources: Optional[Dict[str, Any]] = None

@dataclass
class RecoveryStrategy:
    """Recovery strategy configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    timeout_adjustment: float
    alternative_tools: List[str]
    success_probability: float

class ErrorHandler:
    """Main error handling orchestrator"""
    
    def __init__(self):
        self.error_patterns = self._initialize_error_patterns()
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.tool_alternatives = self._initialize_tool_alternatives()
        self.error_history: List[ErrorContext] = []
    
    def _initialize_error_patterns(self) -> Dict[str, ErrorType]:
        """Initialize error pattern matching"""
        return {
            "timeout": ErrorType.TIMEOUT,
            "timed out": ErrorType.TIMEOUT,
            "connection timeout": ErrorType.TIMEOUT,
            "permission denied": ErrorType.PERMISSION_DENIED,
            "access denied": ErrorType.PERMISSION_DENIED,
            "network unreachable": ErrorType.NETWORK_UNREACHABLE,
            "no route to host": ErrorType.NETWORK_UNREACHABLE,
            "rate limit": ErrorType.RATE_LIMITED,
            "too many requests": ErrorType.RATE_LIMITED,
            "command not found": ErrorType.TOOL_NOT_FOUND,
            "no such file": ErrorType.TOOL_NOT_FOUND,
            "invalid target": ErrorType.INVALID_TARGET,
            "invalid hostname": ErrorType.INVALID_TARGET,
            "connection refused": ErrorType.CONNECTION_REFUSED,
            "dns resolution failed": ErrorType.DNS_RESOLUTION_FAILED,
            "ssl error": ErrorType.SSL_ERROR,
            "certificate error": ErrorType.SSL_ERROR,
            "authentication failed": ErrorType.AUTHENTICATION_FAILED,
            "login failed": ErrorType.AUTHENTICATION_FAILED,
            "out of memory": ErrorType.RESOURCE_EXHAUSTED,
            "disk full": ErrorType.RESOURCE_EXHAUSTED
        }
    
    def _initialize_recovery_strategies(self) -> Dict[ErrorType, RecoveryStrategy]:
        """Initialize recovery strategies for each error type"""
        return {
            ErrorType.TIMEOUT: RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 5, "max_delay": 60},
                max_attempts=3,
                backoff_multiplier=2.0,
                timeout_adjustment=1.5,
                alternative_tools=[],
                success_probability=0.7
            ),
            ErrorType.PERMISSION_DENIED: RecoveryStrategy(
                action=RecoveryAction.ADJUST_PARAMETERS,
                parameters={"remove_privileged_options": True},
                max_attempts=2,
                backoff_multiplier=1.0,
                timeout_adjustment=1.0,
                alternative_tools=[],
                success_probability=0.5
            ),
            ErrorType.NETWORK_UNREACHABLE: RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"prefer_local_tools": True},
                max_attempts=1,
                backoff_multiplier=1.0,
                timeout_adjustment=1.0,
                alternative_tools=[],
                success_probability=0.6
            ),
            ErrorType.RATE_LIMITED: RecoveryStrategy(
                action=RecoveryAction.RETRY_WITH_BACKOFF,
                parameters={"initial_delay": 30, "max_delay": 300},
                max_attempts=3,
                backoff_multiplier=3.0,
                timeout_adjustment=1.0,
                alternative_tools=[],
                success_probability=0.8
            ),
            ErrorType.TOOL_NOT_FOUND: RecoveryStrategy(
                action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                parameters={"install_if_possible": False},
                max_attempts=1,
                backoff_multiplier=1.0,
                timeout_adjustment=1.0,
                alternative_tools=[],
                success_probability=0.9
            )
        }
    
    def _initialize_tool_alternatives(self) -> Dict[str, List[str]]:
        """Initialize tool alternatives mapping"""
        return {
            "nmap": ["rustscan", "masscan"],
            "gobuster": ["feroxbuster", "dirsearch", "ffuf"],
            "nuclei": ["nikto", "jaeles"],
            "hydra": ["medusa", "patator"],
            "john": ["hashcat"],
            "sqlmap": ["manual_sql_injection"],
            "amass": ["subfinder", "assetfinder"],
            "prowler": ["scout-suite"],
            "volatility": ["vol"],
            "ghidra": ["radare2", "ida"]
        }
    
    def classify_error(self, error_message: str, exception: Exception) -> ErrorType:
        """Classify error based on message and exception type"""
        error_lower = error_message.lower()
        
        for pattern, error_type in self.error_patterns.items():
            if pattern in error_lower:
                return error_type
        
        if isinstance(exception, TimeoutError):
            return ErrorType.TIMEOUT
        elif isinstance(exception, PermissionError):
            return ErrorType.PERMISSION_DENIED
        elif isinstance(exception, ConnectionError):
            return ErrorType.NETWORK_UNREACHABLE
        elif isinstance(exception, FileNotFoundError):
            return ErrorType.TOOL_NOT_FOUND
        
        return ErrorType.UNKNOWN_ERROR
    
    def get_recovery_strategy(self, error_type: ErrorType) -> RecoveryStrategy:
        """Get recovery strategy for error type"""
        return self.recovery_strategies.get(error_type, RecoveryStrategy(
            action=RecoveryAction.ESCALATE_TO_HUMAN,
            parameters={},
            max_attempts=1,
            backoff_multiplier=1.0,
            timeout_adjustment=1.0,
            alternative_tools=[],
            success_probability=0.1
        ))
    
    def handle_tool_failure(self, tool_name: str, exception: Exception, context: Dict[str, Any]) -> RecoveryStrategy:
        """Handle tool failure and return recovery strategy"""
        error_type = self.classify_error(str(exception), exception)
        strategy = self.get_recovery_strategy(error_type)
        
        error_context = ErrorContext(
            tool_name=tool_name,
            target=context.get("target", "unknown"),
            parameters=context.get("parameters", {}),
            error_type=error_type,
            error_message=str(exception),
            attempt_count=context.get("attempt_count", 1),
            timestamp=datetime.now(),
            stack_trace=context.get("stack_trace")
        )
        
        self.error_history.append(error_context)
        
        if tool_name in self.tool_alternatives:
            strategy.alternative_tools = self.tool_alternatives[tool_name]
        
        logger.warning(f"Tool failure handled: {tool_name} -> {error_type.value} -> {strategy.action.value}")
        
        return strategy
    
    def get_alternative_tool(self, tool_name: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool for failed tool"""
        alternatives = self.tool_alternatives.get(tool_name, [])
        
        if not alternatives:
            return None
        
        used_tools = context.get("used_tools", set())
        
        for alt_tool in alternatives:
            if alt_tool not in used_tools:
                return alt_tool
        
        return None
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        if not self.error_history:
            return {"total_errors": 0}
        
        error_counts = {}
        tool_errors = {}
        
        for error in self.error_history:
            error_type = error.error_type.value
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            
            tool_name = error.tool_name
            tool_errors[tool_name] = tool_errors.get(tool_name, 0) + 1
        
        return {
            "total_errors": len(self.error_history),
            "error_types": error_counts,
            "tool_errors": tool_errors,
            "most_common_error": max(error_counts.items(), key=lambda x: x[1])[0] if error_counts else None,
            "most_problematic_tool": max(tool_errors.items(), key=lambda x: x[1])[0] if tool_errors else None
        }
