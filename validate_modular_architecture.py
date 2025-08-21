#!/usr/bin/env python3
"""
Validation script for HexStrike AI modular architecture.
Tests that all modules can be imported and core functionality works.
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_core_imports():
    """Test that all core modules can be imported"""
    print("Testing core module imports...")
    
    try:
        from hexstrike.platform.constants import API_HOST, API_PORT, COLORS
        print("✅ Platform constants imported")
        
        from hexstrike.platform.errors import ErrorHandler, ErrorType
        print("✅ Platform errors imported")
        
        from hexstrike.platform.logging import configure_logging, LogConfig
        print("✅ Platform logging imported")
        
        from hexstrike.services.decision_service import DecisionService
        print("✅ Decision service imported")
        
        from hexstrike.services.tool_execution_service import ToolExecutionService
        print("✅ Tool execution service imported")
        
        from hexstrike.services.process_service import ProcessService
        print("✅ Process service imported")
        
        from hexstrike.adapters.tool_registry import ToolRegistry
        print("✅ Tool registry imported")
        
        from hexstrike.adapters.flask_adapter import FlaskAdapter
        print("✅ Flask adapter imported")
        
        from hexstrike.interfaces.visual_engine import VisualEngine
        print("✅ Visual engine imported")
        
        from hexstrike.legacy.compatibility_shims import IntelligentDecisionEngine
        print("✅ Compatibility shims imported")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_tool_registry():
    """Test tool registry functionality"""
    print("\nTesting tool registry functionality...")
    
    try:
        from hexstrike.adapters.tool_registry import ToolRegistry
        
        registry = ToolRegistry()
        tools = registry.get_all_tools()
        print(f"✅ Tool registry loaded with {len(tools)} tools")
        
        nmap_tool = registry.get_tool('nmap')
        if nmap_tool:
            print("✅ Nmap tool found in registry")
        else:
            print("❌ Nmap tool not found")
            return False
            
        nuclei_tool = registry.get_tool('nuclei')
        if nuclei_tool:
            print("✅ Nuclei tool found in registry")
        else:
            print("❌ Nuclei tool not found")
            return False
            
        gobuster_tool = registry.get_tool('gobuster')
        if gobuster_tool:
            print("✅ Gobuster tool found in registry")
        else:
            print("❌ Gobuster tool not found")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Tool registry error: {e}")
        return False

def test_service_instantiation():
    """Test that services can be instantiated"""
    print("\nTesting service instantiation...")
    
    try:
        from hexstrike.services.decision_service import DecisionService
        from hexstrike.services.tool_execution_service import ToolExecutionService
        from hexstrike.services.process_service import ProcessService
        from hexstrike.platform.errors import ErrorHandler
        
        decision_service = DecisionService()
        print("✅ Decision service instantiated")
        
        execution_service = ToolExecutionService()
        print("✅ Tool execution service instantiated")
        
        process_service = ProcessService()
        print("✅ Process service instantiated")
        
        error_handler = ErrorHandler()
        print("✅ Error handler instantiated")
        
        return True
        
    except Exception as e:
        print(f"❌ Service instantiation error: {e}")
        return False

def test_compatibility_layer():
    """Test backward compatibility layer"""
    print("\nTesting compatibility layer...")
    
    try:
        from hexstrike.legacy.compatibility_shims import (
            IntelligentDecisionEngine,
            ModernVisualEngine,
            IntelligentErrorHandler
        )
        
        decision_engine = IntelligentDecisionEngine()
        print("✅ Compatibility decision engine instantiated")
        
        visual_engine = ModernVisualEngine()
        print("✅ Compatibility visual engine instantiated")
        
        error_handler = IntelligentErrorHandler()
        print("✅ Compatibility error handler instantiated")
        
        return True
        
    except Exception as e:
        print(f"❌ Compatibility layer error: {e}")
        return False

def check_line_limits():
    """Check that all modules are ≤300 lines"""
    print("\nChecking line limits...")
    
    src_path = Path(__file__).parent / "src" / "hexstrike"
    violations = []
    
    for py_file in src_path.rglob("*.py"):
        if "legacy" in str(py_file) or "__pycache__" in str(py_file):
            continue
        
        with open(py_file, 'r') as f:
            line_count = len(f.readlines())
        
        if line_count > 300:
            violations.append(f"{py_file.relative_to(src_path)}: {line_count} lines")
        else:
            print(f"✅ {py_file.relative_to(src_path)}: {line_count} lines")
    
    if violations:
        print(f"❌ Modules exceeding 300 lines: {violations}")
        return False
    
    print("✅ All modules are ≤300 lines")
    return True

def main():
    """Run all validation tests"""
    print("🚀 HexStrike AI Modular Architecture Validation")
    print("=" * 50)
    
    tests = [
        test_core_imports,
        test_tool_registry,
        test_service_instantiation,
        test_compatibility_layer,
        check_line_limits
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"❌ Test {test.__name__} failed")
        except Exception as e:
            print(f"❌ Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 50)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All validation tests passed!")
        return 0
    else:
        print("❌ Some validation tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
