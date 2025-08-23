---
title: function.execute_command_with_recovery
kind: function
scope: module
module: __main__
line_range: [6796, 7009]
discovered_in_chunk: 6
---

# Function: execute_command_with_recovery

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute a command with intelligent error handling and recovery

## Complete Signature & Definition
```python
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
```

## Purpose & Behavior
Intelligent command execution with comprehensive error handling and recovery providing:
- **Automatic Recovery:** Intelligent error analysis and recovery strategy application
- **Multiple Attempts:** Configurable maximum attempts with different recovery strategies
- **Recovery History:** Complete tracking of recovery attempts and strategies
- **Tool-specific Recovery:** Context-aware recovery based on tool type and error patterns
- **Escalation Support:** Human escalation for unresolvable issues

## Dependencies & Usage
- **Depends on:**
  - execute_command function for basic execution
  - error_handler for intelligent error handling
  - degradation_manager for graceful degradation
  - ModernVisualEngine for visual formatting
  - datetime for timestamp tracking
  - time for backoff delays
  - logger for comprehensive logging
- **Used by:**
  - Security tool execution systems
  - Automated testing frameworks
  - Resilient command execution workflows

## Implementation Details

### Parameters
- **tool_name:** Name of the tool being executed (required)
- **command:** Command string to execute (required)
- **parameters:** Tool parameters for context (optional, default: None)
- **use_cache:** Enable/disable caching (optional, default: True)
- **max_attempts:** Maximum recovery attempts (optional, default: 3)

### Return Value
- **Type:** Dict[str, Any]
- **Content:** Execution results with comprehensive recovery information

### Recovery Loop Logic

#### Attempt Management
```python
attempt_count = 0
last_error = None
recovery_history = []

while attempt_count < max_attempts:
    attempt_count += 1
    # Recovery logic here
```

#### Recovery Strategy Application
1. **RETRY_WITH_BACKOFF:** Exponential backoff retry strategy
2. **RETRY_WITH_REDUCED_SCOPE:** Parameter adjustment for reduced scope
3. **SWITCH_TO_ALTERNATIVE_TOOL:** Alternative tool suggestion
4. **ADJUST_PARAMETERS:** Parameter optimization based on error type
5. **ESCALATE_TO_HUMAN:** Human escalation for complex issues
6. **GRACEFUL_DEGRADATION:** Fallback to degraded functionality
7. **ABORT_OPERATION:** Operation termination after exhaustion

### Recovery Strategies Implementation

#### Retry with Backoff
```python
if recovery_strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
    delay = recovery_strategy.parameters.get("initial_delay", 5)
    backoff = recovery_strategy.parameters.get("max_delay", 60)
    actual_delay = min(delay * (recovery_strategy.backoff_multiplier ** (attempt_count - 1)), backoff)
    time.sleep(actual_delay)
```

#### Retry with Reduced Scope
```python
elif recovery_strategy.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
    adjusted_params = error_handler.auto_adjust_parameters(
        tool_name, 
        error_handler.classify_error(error_message, exception),
        parameters
    )
    command = _rebuild_command_with_params(tool_name, command, adjusted_params)
```

#### Alternative Tool Switch
```python
elif recovery_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
    alternative_tool = error_handler.get_alternative_tool(tool_name, recovery_strategy.parameters)
    if alternative_tool:
        result["alternative_tool_suggested"] = alternative_tool
```

#### Parameter Adjustment
```python
elif recovery_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
    error_type = error_handler.classify_error(error_message, exception)
    adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, parameters)
    command = _rebuild_command_with_params(tool_name, command, adjusted_params)
```

#### Human Escalation
```python
elif recovery_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
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
    escalation_data = error_handler.escalate_to_human(error_context, "medium")
```

#### Graceful Degradation
```python
elif recovery_strategy.action == RecoveryAction.GRACEFUL_DEGRADATION:
    operation = _determine_operation_type(tool_name)
    degraded_result = degradation_manager.handle_partial_failure(
        operation, 
        result, 
        [tool_name]
    )
```

### Recovery History Tracking

#### History Entry Structure
```python
{
    "attempt": int,                     # Attempt number
    "error": str,                       # Error message
    "recovery_action": str,             # Recovery action taken
    "timestamp": str                    # ISO timestamp
}
```

#### Recovery Information Structure
```python
{
    "attempts_made": int,               # Total attempts made
    "recovery_applied": bool,           # Whether recovery was applied
    "recovery_history": List[Dict],     # Detailed recovery history
    "final_action": str                 # Final action taken
}
```

### Error Context Creation

#### Error Context for Escalation
```python
error_context = ErrorContext(
    tool_name=tool_name,
    target=parameters.get("target", "unknown"),
    parameters=parameters,
    error_type=error_handler.classify_error(error_message, exception),
    error_message=error_message,
    attempt_count=attempt_count,
    timestamp=datetime.now(),
    stack_trace=traceback.format_exc(),
    system_resources=error_handler._get_system_resources()
)
```

### Exception Handling

#### Unexpected Error Handling
```python
except Exception as e:
    last_error = e
    logger.error(f"💥 Unexpected error in recovery attempt {attempt_count}: {str(e)}")
    
    # If this is the last attempt, escalate to human
    if attempt_count >= max_attempts:
        escalation_data = error_handler.escalate_to_human(error_context, "high")
```

### Visual Integration

#### Status Formatting
```python
retry_info = f'Retrying in {actual_delay}s (attempt {attempt_count}/{max_attempts})'
logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', retry_info)}")
```

#### Recovery Logging
```python
switch_info = f'Switching to alternative: {alternative_tool}'
logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', switch_info)}")
```

### Final Result Structures

#### Successful Recovery Result
```python
{
    "success": True,
    "stdout": str,
    "stderr": str,
    "return_code": int,
    "recovery_info": {
        "attempts_made": int,
        "recovery_applied": bool,
        "recovery_history": List[Dict],
        "final_action": str
    }
}
```

#### Failed Recovery Result
```python
{
    "success": False,
    "error": str,
    "recovery_info": {
        "attempts_made": int,
        "recovery_applied": bool,
        "recovery_history": List[Dict],
        "final_action": str
    }
}
```

#### Human Escalation Result
```python
{
    "success": False,
    "error": str,
    "human_escalation": Dict[str, Any],
    "recovery_info": {
        "attempts_made": int,
        "recovery_applied": bool,
        "recovery_history": List[Dict],
        "final_action": str
    }
}
```

### Integration with Error Handling System

#### Error Handler Integration
- **Error Classification:** Automatic error type classification
- **Recovery Strategy Selection:** Intelligent recovery strategy selection
- **Parameter Adjustment:** Context-aware parameter optimization
- **Alternative Tool Selection:** Intelligent alternative tool recommendation

#### Degradation Manager Integration
- **Operation Type Determination:** Determine operation type for degradation
- **Partial Failure Handling:** Handle partial failures gracefully
- **Fallback Functionality:** Provide fallback functionality when possible

### Use Cases and Applications

#### Automated Security Testing
- **Tool Resilience:** Ensure security tools complete successfully
- **Error Recovery:** Automatically recover from common tool failures
- **Testing Continuity:** Maintain testing continuity despite individual tool failures

#### Production Operations
- **Operational Resilience:** Ensure critical operations complete successfully
- **Automatic Recovery:** Reduce manual intervention requirements
- **Error Escalation:** Escalate complex issues to human operators

#### Development and Testing
- **Development Resilience:** Handle development environment issues
- **Testing Automation:** Ensure automated tests complete reliably
- **Error Analysis:** Provide detailed error analysis for debugging

## Testing & Validation
- Recovery strategy effectiveness testing
- Error handling accuracy verification
- Escalation logic correctness validation
- Recovery history tracking precision assessment

## Code Reproduction
Complete function implementation with comprehensive error handling and recovery, including multiple recovery strategies, attempt management, recovery history tracking, and human escalation. Essential for resilient command execution and automated error recovery.
