"""
Compatibility shims for HexStrike AI modularization migration.

This module provides backward-compatible imports to ensure existing code
continues to work during the migration from hexstrike_server.py to the
modular architecture.
"""

import warnings
from typing import Any, Dict, List, Optional

from ..services.decision_service import DecisionService
from ..services.tool_execution_service import ToolExecutionService
from ..services.process_service import ProcessService
from ..interfaces.visual_engine import VisualEngine
from ..platform.errors import ErrorHandler, ErrorType, RecoveryAction
from ..domain.target_analysis import TargetProfile, TargetType, TechnologyStack

def _deprecation_warning(old_name: str, new_import: str) -> None:
    """Issue deprecation warning for old imports."""
    warnings.warn(
        f"{old_name} is deprecated. Use '{new_import}' instead.",
        DeprecationWarning,
        stacklevel=3
    )

class IntelligentDecisionEngine:
    """
    Compatibility wrapper for the original IntelligentDecisionEngine.
    
    DEPRECATED: Use hexstrike.services.decision_service.DecisionService instead.
    """
    
    def __init__(self):
        _deprecation_warning(
            "IntelligentDecisionEngine", 
            "hexstrike.services.decision_service.DecisionService"
        )
        self._service = DecisionService()
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create profile (compatibility method)."""
        return self._service.analyze_target(target)
    
    def select_optimal_tools(self, profile: TargetProfile, objective: str = "comprehensive") -> List[str]:
        """Select optimal tools for target (compatibility method)."""
        return self._service.select_optimal_tools(profile, objective)
    
    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Optimize tool parameters (compatibility method)."""
        return self._service.optimize_parameters(tool, profile, context or {})
    
    def create_attack_chain(self, profile: TargetProfile, objective: str = "comprehensive"):
        """Create attack chain (compatibility method)."""
        return {
            "target": profile.target,
            "tools": self.select_optimal_tools(profile, objective),
            "estimated_time": 1800,
            "success_probability": 0.7
        }
    
    def enable_advanced_optimization(self) -> None:
        """Enable advanced optimization (compatibility method)."""
        return self._service.enable_advanced_optimization()
    
    def disable_advanced_optimization(self) -> None:
        """Disable advanced optimization (compatibility method)."""
        return self._service.disable_advanced_optimization()

class ModernVisualEngine:
    """
    Compatibility wrapper for the original ModernVisualEngine.
    
    DEPRECATED: Use hexstrike.interfaces.visual_engine.VisualEngine instead.
    """
    
    def __init__(self):
        _deprecation_warning(
            "ModernVisualEngine",
            "hexstrike.interfaces.visual_engine.VisualEngine"
        )
    
    @staticmethod
    def create_banner() -> str:
        """Create banner (compatibility method)."""
        return VisualEngine.create_banner()
    
    @staticmethod
    def create_progress_bar(current: int, total: int, width: int = 50, tool: str = "") -> str:
        """Create progress bar (compatibility method)."""
        return VisualEngine.create_progress_bar(current, total, width, tool)
    
    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber', 
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render progress bar (compatibility method)."""
        return VisualEngine.render_progress_bar(progress, width, style, label, eta, speed)
    
    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create live dashboard (compatibility method)."""
        return VisualEngine.create_live_dashboard(processes)
    
    @staticmethod
    def format_vulnerability_card(vuln_data: Dict[str, Any]) -> str:
        """Format vulnerability card (compatibility method)."""
        return VisualEngine.format_vulnerability_card(vuln_data)
    
    @staticmethod
    def format_error_card(error_type: str, tool_name: str, error_message: str, recovery_action: str = "") -> str:
        """Format error card (compatibility method)."""
        return VisualEngine.format_error_card(error_type, tool_name, error_message, recovery_action)
    
    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "", progress: float = 0.0) -> str:
        """Format tool status (compatibility method)."""
        return VisualEngine.format_tool_status(tool_name, status, target, progress)

class IntelligentErrorHandler:
    """
    Compatibility wrapper for the original IntelligentErrorHandler.
    
    DEPRECATED: Use hexstrike.platform.errors.ErrorHandler instead.
    """
    
    def __init__(self):
        _deprecation_warning(
            "IntelligentErrorHandler",
            "hexstrike.platform.errors.ErrorHandler"
        )
        self._handler = ErrorHandler()
    
    def classify_error(self, error_message: str, exception: Exception) -> ErrorType:
        """Classify error (compatibility method)."""
        return self._handler.classify_error(error_message, exception)
    
    def handle_tool_failure(self, tool_name: str, exception: Exception, context: Dict[str, Any]):
        """Handle tool failure (compatibility method)."""
        return self._handler.handle_tool_failure(tool_name, exception, context)
    
    def get_alternative_tool(self, tool_name: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool (compatibility method)."""
        return self._handler.get_alternative_tool(tool_name, context)

class ProcessManager:
    """
    Compatibility wrapper for process management functions.
    
    DEPRECATED: Use hexstrike.services.process_service.ProcessService instead.
    """
    
    def __init__(self):
        _deprecation_warning(
            "ProcessManager",
            "hexstrike.services.process_service.ProcessService"
        )
        self._service = ProcessService()
    
    @staticmethod
    def register_process(pid: int, command: str, process_obj):
        """Register process (compatibility method)."""
        service = ProcessService()
        return service.register_process(pid, command, "unknown", "unknown")
    
    @staticmethod
    def terminate_process(pid: int) -> bool:
        """Terminate process (compatibility method)."""
        service = ProcessService()
        return service.terminate_process(pid)
    
    @staticmethod
    def pause_process(pid: int) -> bool:
        """Pause process (compatibility method)."""
        service = ProcessService()
        return service.pause_process(pid)
    
    @staticmethod
    def resume_process(pid: int) -> bool:
        """Resume process (compatibility method)."""
        service = ProcessService()
        return service.resume_process(pid)
    
    @staticmethod
    def list_active_processes() -> Dict[int, Dict[str, Any]]:
        """List active processes (compatibility method)."""
        service = ProcessService()
        return service.list_active_processes()

decision_engine = IntelligentDecisionEngine()
error_handler = IntelligentErrorHandler()
visual_engine = ModernVisualEngine()
process_manager = ProcessManager()

def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute command with caching (compatibility function).
    
    DEPRECATED: Use hexstrike.services.tool_execution_service.ToolExecutionService instead.
    """
    _deprecation_warning(
        "execute_command",
        "hexstrike.services.tool_execution_service.ToolExecutionService.execute_tool"
    )
    service = ToolExecutionService()
    result = service.execute_tool("generic", {"command": command})
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "return_code": result.return_code,
        "execution_time": result.execution_time
    }

def execute_command_with_recovery(tool_name: str, command: str, parameters: Dict[str, Any] = None, 
                                 use_cache: bool = True, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Execute command with recovery (compatibility function).
    
    DEPRECATED: Use hexstrike.services.tool_execution_service.ToolExecutionService instead.
    """
    _deprecation_warning(
        "execute_command_with_recovery",
        "hexstrike.services.tool_execution_service.ToolExecutionService.execute_with_recovery"
    )
    service = ToolExecutionService()
    params = parameters or {}
    params["command"] = command
    result = service.execute_with_recovery(tool_name, params, max_attempts)
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "return_code": result.return_code,
        "execution_time": result.execution_time,
        "recovery_info": result.recovery_info
    }

from ..platform.constants import (
    API_PORT,
    API_HOST,
    MAX_CONCURRENT_PROCESSES,
    DEFAULT_CACHE_TTL,
    COLORS
)

__all__ = [
    'IntelligentDecisionEngine',
    'ModernVisualEngine', 
    'IntelligentErrorHandler',
    
    'ProcessManager',
    
    # Global instances
    'decision_engine',
    'error_handler',
    'visual_engine',
    'process_manager',
    
    'execute_command',
    'execute_command_with_recovery',
    
    'API_PORT',
    'API_HOST',
    'COLORS',
    'MAX_CONCURRENT_PROCESSES',
    'DEFAULT_CACHE_TTL',
    
    'TargetProfile',
    'TargetType',
    'TechnologyStack',
    'ErrorType',
    'RecoveryAction',
]
