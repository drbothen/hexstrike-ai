"""
Command execution with intelligent error handling and recovery service.

This module changes when command recovery or error handling strategies change.
"""

import time
import logging
import traceback
from datetime import datetime
from typing import Dict, Any

from .recovery_strategy import ErrorType, RecoveryAction, ErrorContext
from .error_handler import IntelligentErrorHandler
from .graceful_degradation import GracefulDegradation

logger = logging.getLogger(__name__)

# Global instances
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()

def execute_command_with_recovery(tool_name: str, command: str, parameters: Dict[str, Any] = None, 
                                 use_cache: bool = True, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Execute a command with intelligent error handling and recovery
    
    Args:
        tool_name: Name of the tool being executed
        command: The command to execute
        parameters: Tool parameters for context
        use_cache: Whether to use caching
        max_attempts: Maximum number of recovery attempts
        
    Returns:
        A dictionary containing execution results with recovery information
    """
    if parameters is None:
        parameters = {}
    
    attempt_count = 0
    last_error = None
    recovery_history = []
    
    while attempt_count < max_attempts:
        attempt_count += 1
        
        try:
            from ..core.command_executor import execute_command
            
            # Execute the command
            result = execute_command(command, use_cache)
            
            # Check if execution was successful
            if result.get("success", False):
                # Add recovery information to successful result
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history
                }
                return result
            
            # Command failed, determine if we should attempt recovery
            error_message = result.get("stderr", "Unknown error")
            exception = Exception(error_message)
            
            # Create context for error handler
            context = {
                "target": parameters.get("target", "unknown"),
                "parameters": parameters,
                "attempt_count": attempt_count,
                "command": command
            }
            
            # Get recovery strategy from error handler
            recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)
            recovery_history.append({
                "attempt": attempt_count,
                "error": error_message,
                "recovery_action": recovery_strategy.action.value,
                "timestamp": datetime.now().isoformat()
            })
            
            # Apply recovery strategy
            if recovery_strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
                delay = recovery_strategy.parameters.get("initial_delay", 5)
                backoff = recovery_strategy.parameters.get("max_delay", 60)
                actual_delay = min(delay * (recovery_strategy.backoff_multiplier ** (attempt_count - 1)), backoff)
                
                retry_info = f'Retrying in {actual_delay}s (attempt {attempt_count}/{max_attempts})'
                logger.info(f"🔄 {tool_name} RECOVERY: {retry_info}")
                time.sleep(actual_delay)
                continue
                
            elif recovery_strategy.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
                # Adjust parameters to reduce scope
                adjusted_params = error_handler.auto_adjust_parameters(
                    tool_name, 
                    error_handler.classify_error(error_message, exception),
                    parameters
                )
                
                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with reduced scope")
                continue
                
            elif recovery_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                # Get alternative tool
                alternative_tool = error_handler.get_alternative_tool(tool_name, recovery_strategy.parameters)
                
                if alternative_tool:
                    switch_info = f'Switching to alternative: {alternative_tool}'
                    logger.info(f"🔄 {tool_name} RECOVERY: {switch_info}")
                    # This would require the calling function to handle tool switching
                    result["alternative_tool_suggested"] = alternative_tool
                    result["recovery_info"] = {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "tool_switch_suggested"
                    }
                    return result
                else:
                    logger.warning(f"⚠️  No alternative tool found for {tool_name}")
                    
            elif recovery_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
                # Adjust parameters based on error type
                error_type = error_handler.classify_error(error_message, exception)
                adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, parameters)
                
                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with adjusted parameters")
                continue
                
            elif recovery_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
                # Create error context for escalation
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=error_handler.classify_error(error_message, exception),
                    error_message=error_message,
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace="",
                    system_resources=error_handler._get_system_resources()
                )
                
                escalation_data = error_handler.escalate_to_human(
                    error_context, 
                    recovery_strategy.parameters.get("urgency", "medium")
                )
                
                result["human_escalation"] = escalation_data
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "human_escalation"
                }
                return result
                
            elif recovery_strategy.action == RecoveryAction.GRACEFUL_DEGRADATION:
                # Apply graceful degradation
                operation = _determine_operation_type(tool_name)
                degraded_result = degradation_manager.handle_partial_failure(
                    operation, 
                    result, 
                    [tool_name]
                )
                
                degraded_result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "graceful_degradation"
                }
                return degraded_result
                
            elif recovery_strategy.action == RecoveryAction.ABORT_OPERATION:
                logger.error(f"🛑 Aborting {tool_name} operation after {attempt_count} attempts")
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "operation_aborted"
                }
                return result
            
            last_error = exception
            
        except Exception as e:
            last_error = e
            logger.error(f"💥 Unexpected error in recovery attempt {attempt_count}: {str(e)}")
            
            # If this is the last attempt, escalate to human
            if attempt_count >= max_attempts:
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=ErrorType.UNKNOWN,
                    error_message=str(e),
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace=traceback.format_exc(),
                    system_resources=error_handler._get_system_resources()
                )
                
                escalation_data = error_handler.escalate_to_human(error_context, "high")
                
                return {
                    "success": False,
                    "error": str(e),
                    "human_escalation": escalation_data,
                    "recovery_info": {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "human_escalation_after_failure"
                    }
                }
    
    # All attempts exhausted
    logger.error(f"🚫 All recovery attempts exhausted for {tool_name}")
    return {
        "success": False,
        "error": f"All recovery attempts exhausted: {str(last_error)}",
        "recovery_info": {
            "attempts_made": attempt_count,
            "recovery_applied": True,
            "recovery_history": recovery_history,
            "final_action": "all_attempts_exhausted"
        }
    }

def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    from ..core.command_builder import rebuild_command_with_params
    return rebuild_command_with_params(tool_name, original_command, new_params)

def _determine_operation_type(tool_name: str) -> str:
    """Determine operation type from tool name"""
    from ..core.operation_classifier import determine_operation_type
    return determine_operation_type(tool_name)
