# HexStrike AI - Compatibility Shims

**Purpose:** Maintain backward compatibility during the modularization migration by providing import shims and deprecated API wrappers.

**Status:** Proposed (designed for hexstrike_server.py migration)

## Import Compatibility Layer

### legacy/compatibility_shims.py
**Purpose:** Provide seamless import compatibility for existing code that imports from the monolith.

```python
"""
Compatibility shims for HexStrike AI modularization migration.

This module provides backward-compatible imports to ensure existing code
continues to work during the migration from hexstrike_server.py to the
modular architecture.

Usage:
    # Old import (still works)
    from hexstrike_server import IntelligentDecisionEngine
    
    # New import (preferred)
    from hexstrike.services.decision_service import DecisionService
"""

import warnings
from typing import Any, Dict, List, Optional

# Core engine imports
from hexstrike.services.decision_service import DecisionService
from hexstrike.services.tool_execution_service import ToolExecutionService
from hexstrike.services.process_service import ProcessService
from hexstrike.interfaces.visual_engine import VisualEngine
from hexstrike.platform.errors import ErrorHandler, ErrorType, RecoveryAction
from hexstrike.domain.target_analysis import TargetProfile, TargetType, TechnologyStack

# Specialized framework imports
from hexstrike.services.bugbounty_service import BugBountyService
from hexstrike.services.ctf_service import CTFService
from hexstrike.adapters.tool_registry import ToolRegistry

def _deprecation_warning(old_name: str, new_import: str) -> None:
    """Issue deprecation warning for old imports."""
    warnings.warn(
        f"{old_name} is deprecated. Use '{new_import}' instead.",
        DeprecationWarning,
        stacklevel=3
    )

# ============================================================================
# CORE ENGINE COMPATIBILITY
# ============================================================================

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
        return self._service.create_attack_chain(profile, objective)
    
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

# ============================================================================
# PROCESS MANAGEMENT COMPATIBILITY
# ============================================================================

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
        # This was a static method in the original, now delegates to service
        service = ProcessService()
        return service.register_process(pid, command, process_obj)
    
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

# ============================================================================
# SPECIALIZED FRAMEWORK COMPATIBILITY
# ============================================================================

class BugBountyWorkflowManager:
    """
    Compatibility wrapper for bug bounty workflow management.
    
    DEPRECATED: Use hexstrike.services.bugbounty_service.BugBountyService instead.
    """
    
    def __init__(self):
        _deprecation_warning(
            "BugBountyWorkflowManager",
            "hexstrike.services.bugbounty_service.BugBountyService"
        )
        self._service = BugBountyService()
    
    def create_reconnaissance_workflow(self, target):
        """Create reconnaissance workflow (compatibility method)."""
        return self._service.create_reconnaissance_workflow(target)
    
    def create_vulnerability_hunting_workflow(self, target):
        """Create vulnerability hunting workflow (compatibility method)."""
        return self._service.create_vulnerability_hunting_workflow(target)

class CTFWorkflowManager:
    """
    Compatibility wrapper for CTF workflow management.
    
    DEPRECATED: Use hexstrike.services.ctf_service.CTFService instead.
    """
    
    def __init__(self):
        _deprecation_warning(
            "CTFWorkflowManager",
            "hexstrike.services.ctf_service.CTFService"
        )
        self._service = CTFService()
    
    def analyze_challenge(self, challenge):
        """Analyze CTF challenge (compatibility method)."""
        return self._service.analyze_challenge(challenge)
    
    def suggest_tools(self, challenge_type: str, description: str) -> List[str]:
        """Suggest tools for challenge (compatibility method)."""
        return self._service.suggest_tools(challenge_type, description)

# ============================================================================
# GLOBAL INSTANCE COMPATIBILITY
# ============================================================================

# Provide global instances for backward compatibility
decision_engine = IntelligentDecisionEngine()
error_handler = IntelligentErrorHandler()
visual_engine = ModernVisualEngine()
process_manager = ProcessManager()
bugbounty_manager = BugBountyWorkflowManager()
ctf_manager = CTFWorkflowManager()

# ============================================================================
# FUNCTION-LEVEL COMPATIBILITY
# ============================================================================

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
    return service.execute_command(command, use_cache)

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
    return service.execute_with_recovery(tool_name, command, parameters or {}, use_cache, max_attempts)

# ============================================================================
# CONSTANT COMPATIBILITY
# ============================================================================

# Import constants for backward compatibility
from hexstrike.platform.constants import (
    API_PORT,
    API_HOST,
    MAX_CONCURRENT_PROCESSES,
    DEFAULT_CACHE_TTL
)

# Color constants (most commonly used)
from hexstrike.platform.constants import COLORS

# ============================================================================
# MODULE-LEVEL EXPORTS
# ============================================================================

__all__ = [
    # Core engines
    'IntelligentDecisionEngine',
    'ModernVisualEngine', 
    'IntelligentErrorHandler',
    
    # Process management
    'ProcessManager',
    
    # Specialized frameworks
    'BugBountyWorkflowManager',
    'CTFWorkflowManager',
    
    # Global instances
    'decision_engine',
    'error_handler',
    'visual_engine',
    'process_manager',
    'bugbounty_manager',
    'ctf_manager',
    
    # Functions
    'execute_command',
    'execute_command_with_recovery',
    
    # Constants
    'API_PORT',
    'API_HOST',
    'COLORS',
    'MAX_CONCURRENT_PROCESSES',
    'DEFAULT_CACHE_TTL',
    
    # Domain types (commonly used)
    'TargetProfile',
    'TargetType',
    'TechnologyStack',
    'ErrorType',
    'RecoveryAction',
]
```

## Deprecated API Endpoints

### legacy/deprecated_apis.py
**Purpose:** Maintain API endpoint compatibility during migration.

```python
"""
Deprecated API endpoints for backward compatibility.

These endpoints maintain compatibility with the original hexstrike_server.py
API while internally delegating to the new modular services.
"""

import warnings
from flask import Flask, request, jsonify
from typing import Dict, Any

from hexstrike.services.decision_service import DecisionService
from hexstrike.services.tool_execution_service import ToolExecutionService
from hexstrike.adapters.flask_adapter import FlaskAdapter

def register_deprecated_endpoints(app: Flask) -> None:
    """Register deprecated API endpoints for backward compatibility."""
    
    @app.route("/api/legacy/execute", methods=["POST"])
    def legacy_execute():
        """
        Legacy execute endpoint.
        
        DEPRECATED: Use /api/v1/tools/execute instead.
        """
        warnings.warn(
            "Legacy /api/legacy/execute endpoint is deprecated. Use /api/v1/tools/execute instead.",
            DeprecationWarning
        )
        
        # Delegate to new service
        service = ToolExecutionService()
        params = request.json
        
        tool_name = params.get("tool", "")
        tool_params = params.get("params", {})
        
        result = service.execute_tool(tool_name, tool_params)
        
        # Convert to legacy response format
        return jsonify({
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.return_code,
            "execution_time": result.execution_time
        })
    
    @app.route("/api/legacy/intelligence/analyze", methods=["POST"])
    def legacy_intelligence_analyze():
        """
        Legacy intelligence analysis endpoint.
        
        DEPRECATED: Use /api/v1/intelligence/analyze-target instead.
        """
        warnings.warn(
            "Legacy /api/legacy/intelligence/analyze endpoint is deprecated. Use /api/v1/intelligence/analyze-target instead.",
            DeprecationWarning
        )
        
        # Delegate to new service
        service = DecisionService()
        params = request.json
        
        target = params.get("target", "")
        profile = service.analyze_target(target)
        
        # Convert to legacy response format
        return jsonify({
            "success": True,
            "target_profile": profile.to_dict(),
            "timestamp": profile.timestamp if hasattr(profile, 'timestamp') else None
        })

# Additional deprecated endpoints...
```

## Migration Guide

### Phase-by-Phase Import Updates

#### Phase 1: Update Imports (No Functionality Changes)
```python
# Before (works but deprecated)
from hexstrike_server import IntelligentDecisionEngine, ModernVisualEngine

# After (preferred)
from hexstrike.services.decision_service import DecisionService
from hexstrike.interfaces.visual_engine import VisualEngine
```

#### Phase 2: Update Instance Creation
```python
# Before
engine = IntelligentDecisionEngine()

# After  
engine = DecisionService()
```

#### Phase 3: Update Method Calls (if needed)
```python
# Most method calls remain the same due to compatibility layer
profile = engine.analyze_target("example.com")
tools = engine.select_optimal_tools(profile, "comprehensive")
```

### API Endpoint Migration

#### Tool Execution Endpoints
```python
# Old endpoint (deprecated)
POST /api/tools/nmap
{
    "target": "example.com",
    "scan_type": "-sV -sC"
}

# New endpoint (preferred)
POST /api/v1/tools/execute
{
    "tool_name": "nmap",
    "parameters": {
        "target": "example.com",
        "scan_type": "-sV -sC"
    }
}
```

#### Intelligence Endpoints
```python
# Old endpoint (deprecated)
POST /api/intelligence/analyze-target
{
    "target": "example.com"
}

# New endpoint (same, but versioned)
POST /api/v1/intelligence/analyze-target
{
    "target": "example.com"
}
```

## Deprecation Timeline

### Phase 1 (Weeks 1-2): Compatibility Layer Active
- All old imports work through shims
- Deprecation warnings issued
- New modules available alongside old

### Phase 2 (Weeks 3-4): Migration Encouraged  
- Documentation updated to show new imports
- Training provided on new architecture
- Old imports still work but discouraged

### Phase 3 (Weeks 5-6): Deprecation Warnings Increased
- More prominent deprecation warnings
- Old endpoints return deprecation headers
- Migration tools provided

### Phase 4 (Weeks 7-8): Legacy Support Reduced
- Some legacy endpoints disabled
- Import shims remain for critical paths
- Full migration expected

### Phase 5 (Week 9+): Legacy Removal
- All legacy endpoints removed
- Import shims removed
- Only new modular architecture supported

## Testing Compatibility

### Automated Compatibility Tests
```python
def test_legacy_imports():
    """Test that legacy imports still work."""
    from hexstrike_server import IntelligentDecisionEngine
    engine = IntelligentDecisionEngine()
    assert engine is not None

def test_legacy_api_endpoints():
    """Test that legacy API endpoints still work."""
    response = client.post('/api/legacy/execute', json={
        'tool': 'nmap',
        'params': {'target': 'example.com'}
    })
    assert response.status_code == 200

def test_deprecation_warnings():
    """Test that deprecation warnings are issued."""
    with warnings.catch_warnings(record=True) as w:
        from hexstrike_server import IntelligentDecisionEngine
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
```

---

**Note:** This compatibility layer ensures zero-downtime migration from the 15,409-line monolith to the modular architecture while providing clear migration paths for all users.
