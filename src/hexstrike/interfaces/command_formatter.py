"""
Command formatting utilities for HexStrike AI.

This module provides formatting functions for command execution results.
"""

from typing import Dict, Any, Optional
from .visual_engine import ModernVisualEngine

class CommandFormatter:
    """Command execution formatting utilities"""
    
    @staticmethod
    def format_command_execution(command: str, output: str, success: bool = True) -> str:
        """Format command execution results"""
        status_color = ModernVisualEngine.COLORS['SUCCESS'] if success else ModernVisualEngine.COLORS['ERROR']
        status_text = "SUCCESS" if success else "FAILED"
        
        return f"""
{ModernVisualEngine.COLORS['PRIMARY_BORDER']}┌─ COMMAND EXECUTION ─ {status_color}{status_text}{ModernVisualEngine.COLORS['PRIMARY_BORDER']} ─{'─' * (50 - len(status_text))}┐
│ {ModernVisualEngine.COLORS['CYBER_ORANGE']}$ {command}{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'.' * (70 - len(command))} │
├─────────────────────────────────────────────────────────────────────────────┤
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}{output[:70]}{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'.' * (70 - len(output[:70]))} │
└─────────────────────────────────────────────────────────────────────────────┘{ModernVisualEngine.COLORS['RESET']}
"""
