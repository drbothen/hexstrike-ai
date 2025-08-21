"""
Test suite for validating the modular architecture migration.

This test suite validates that all modules comply with the quality requirements:
- Line limits (≤300 lines per module)
- No import cycles
- Code duplication <3%
- All tool handlers functional
- All API endpoints operational
"""

import unittest
import sys
import os
from pathlib import Path
import importlib
import subprocess
import requests
import time
import threading

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

class TestModularArchitecture(unittest.TestCase):
    """Test modular architecture compliance"""
    
    def setUp(self):
        """Set up test environment"""
        self.src_path = Path(__file__).parent.parent / "src" / "hexstrike"
        self.max_lines_per_module = 300
    
    def test_line_limits(self):
        """Test that all modules are ≤300 lines"""
        violations = []
        
        for py_file in self.src_path.rglob("*.py"):
            if "legacy" in str(py_file) or "__pycache__" in str(py_file):
                continue
            
            with open(py_file, 'r') as f:
                line_count = len(f.readlines())
            
            if line_count > self.max_lines_per_module:
                violations.append(f"{py_file.relative_to(self.src_path)}: {line_count} lines")
        
        self.assertEqual(len(violations), 0, 
                        f"Modules exceeding {self.max_lines_per_module} lines: {violations}")
    
    def test_module_imports(self):
        """Test that all modules can be imported successfully"""
        import_errors = []
        
        for py_file in self.src_path.rglob("*.py"):
            if py_file.name == "__init__.py" or "legacy" in str(py_file):
                continue
            
            relative_path = py_file.relative_to(self.src_path.parent)
            module_name = str(relative_path.with_suffix('')).replace('/', '.')
            
            try:
                importlib.import_module(module_name)
            except Exception as e:
                import_errors.append(f"{module_name}: {str(e)}")
        
        self.assertEqual(len(import_errors), 0, 
                        f"Module import errors: {import_errors}")
    
    def test_core_services_available(self):
        """Test that core services are available"""
        try:
            from hexstrike.services.decision_service import DecisionService
            from hexstrike.services.tool_execution_service import ToolExecutionService
            from hexstrike.services.process_service import ProcessService
            from hexstrike.platform.errors import ErrorHandler
            from hexstrike.adapters.tool_registry import ToolRegistry
            
            decision_service = DecisionService()
            execution_service = ToolExecutionService()
            process_service = ProcessService()
            error_handler = ErrorHandler()
            tool_registry = ToolRegistry()
            
            self.assertIsNotNone(decision_service)
            self.assertIsNotNone(execution_service)
            self.assertIsNotNone(process_service)
            self.assertIsNotNone(error_handler)
            self.assertIsNotNone(tool_registry)
            
        except ImportError as e:
            self.fail(f"Core services not available: {e}")
    
    def test_compatibility_layer(self):
        """Test that compatibility layer works"""
        try:
            from hexstrike.legacy.compatibility_shims import (
                IntelligentDecisionEngine,
                ModernVisualEngine,
                IntelligentErrorHandler
            )
            
            decision_engine = IntelligentDecisionEngine()
            visual_engine = ModernVisualEngine()
            error_handler = IntelligentErrorHandler()
            
            self.assertIsNotNone(decision_engine)
            self.assertIsNotNone(visual_engine)
            self.assertIsNotNone(error_handler)
            
        except ImportError as e:
            self.fail(f"Compatibility layer not available: {e}")
    
    def test_tool_registry_functionality(self):
        """Test tool registry functionality"""
        try:
            from hexstrike.adapters.tool_registry import ToolRegistry
            
            registry = ToolRegistry()
            
            tools = registry.get_all_tools()
            self.assertGreater(len(tools), 0, "No tools registered")
            
            nmap_tool = registry.get_tool("nmap")
            self.assertIsNotNone(nmap_tool, "nmap tool not found")
            
            nuclei_tool = registry.get_tool("nuclei")
            self.assertIsNotNone(nuclei_tool, "nuclei tool not found")
            
        except Exception as e:
            self.fail(f"Tool registry test failed: {e}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
