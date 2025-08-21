"""
Visual output formatting interfaces and implementations.

This module changes when visual output formatting requirements or color schemes change.
"""

from typing import Dict, Any, Optional
import time
from ..platform.constants import COLORS

class ModernVisualEngine:
    """Beautiful, modern output formatting with animations and colors"""
    
    COLORS = {
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'UNDERLINE': '\033[4m',
        'BLINK': '\033[5m',
        'REVERSE': '\033[7m',
        'STRIKETHROUGH': '\033[9m',
        'BLACK': '\033[30m',
        'RED': '\033[31m',
        'GREEN': '\033[32m',
        'YELLOW': '\033[33m',
        'BLUE': '\033[34m',
        'MAGENTA': '\033[35m',
        'CYAN': '\033[36m',
        'WHITE': '\033[37m',
        'BRIGHT_BLACK': '\033[90m',
        'BRIGHT_RED': '\033[91m',
        'BRIGHT_GREEN': '\033[92m',
        'BRIGHT_YELLOW': '\033[93m',
        'BRIGHT_BLUE': '\033[94m',
        'BRIGHT_MAGENTA': '\033[95m',
        'BRIGHT_CYAN': '\033[96m',
        'BRIGHT_WHITE': '\033[97m',
        'BG_BLACK': '\033[40m',
        'BG_RED': '\033[41m',
        'BG_GREEN': '\033[42m',
        'BG_YELLOW': '\033[43m',
        'BG_BLUE': '\033[44m',
        'BG_MAGENTA': '\033[45m',
        'BG_CYAN': '\033[46m',
        'BG_WHITE': '\033[47m',
        'FIRE_RED': '\033[38;5;196m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'NEON_GREEN': '\033[38;5;46m',
        'ELECTRIC_BLUE': '\033[38;5;33m',
        'PURPLE_GLOW': '\033[38;5;129m',
        'YELLOW_BRIGHT': '\033[38;5;226m',
        'WHITE_BRIGHT': '\033[38;5;15m',
        'GRAY_DARK': '\033[38;5;240m',
        'PRIMARY_BORDER': '\033[38;5;33m',
        'TOOL_RUNNING': '\033[38;5;208m',
        'TOOL_SUCCESS': '\033[38;5;46m',
        'TOOL_ERROR': '\033[38;5;196m',
        'TOOL_WARNING': '\033[38;5;226m',
        'CRITICAL': '\033[38;5;196m',
        'HIGH': '\033[38;5;208m',
        'MEDIUM': '\033[38;5;226m',
        'LOW': '\033[38;5;46m',
        'INFO': '\033[38;5;33m',
        'UNKNOWN': '\033[38;5;240m',
        'SUCCESS': '\033[38;5;46m',
        'WARNING': '\033[38;5;226m',
        'ERROR': '\033[38;5;196m'
    }
    
    @staticmethod
    def create_banner() -> str:
        """Create application banner"""
        banner_lines = [
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╔══════════════════════════════════════════════════════════════════════════════╗{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}                                                                              {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['FIRE_RED']}██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['FIRE_RED']}██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['CYBER_ORANGE']}███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗{ModernVisualEngine.COLORS['RESET']}    {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['CYBER_ORANGE']}██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝{ModernVisualEngine.COLORS['RESET']}    {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['YELLOW_BRIGHT']}██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['YELLOW_BRIGHT']}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}                                                                              {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}           {ModernVisualEngine.COLORS['NEON_GREEN']}🚀 Advanced AI-Powered Penetration Testing Framework 🚀{ModernVisualEngine.COLORS['RESET']}           {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}                                                                              {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['ELECTRIC_BLUE']}Version: 6.0.0{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['GRAY_DARK']}|{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PURPLE_GLOW']}Bug Bounty{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['GRAY_DARK']}|{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PURPLE_GLOW']}CTF{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['GRAY_DARK']}|{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PURPLE_GLOW']}Red Team{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['GRAY_DARK']}|{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PURPLE_GLOW']}Research{ModernVisualEngine.COLORS['RESET']}  {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}                                                                              {ModernVisualEngine.COLORS['PRIMARY_BORDER']}║{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}"
        ]
        return "\n".join(banner_lines)
    
    @staticmethod
    def create_progress_bar(current: int, total: int, width: int = 50, tool: str = "") -> str:
        """Create simple progress bar"""
        if total == 0:
            percentage = 0
        else:
            percentage = (current / total) * 100
        
        filled = int(width * current // total) if total > 0 else 0
        bar = "█" * filled + "░" * (width - filled)
        
        tool_info = f" [{tool}]" if tool else ""
        return f"{ModernVisualEngine.COLORS['CYBER_ORANGE']}[{bar}]{ModernVisualEngine.COLORS['RESET']} {percentage:.1f}%{tool_info}"
    
    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber', 
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render advanced progress bar with cyber styling"""
        percentage = max(0, min(100, progress * 100))
        filled_width = int(width * progress)
        
        if style == 'cyber':
            filled_char = "█"
            empty_char = "░"
            color = ModernVisualEngine.COLORS['NEON_GREEN'] if progress >= 1.0 else ModernVisualEngine.COLORS['CYBER_ORANGE']
        else:
            filled_char = "="
            empty_char = "-"
            color = ModernVisualEngine.COLORS['SUCCESS'] if progress >= 1.0 else ModernVisualEngine.COLORS['INFO']
        
        bar = filled_char * filled_width + empty_char * (width - filled_width)
        
        progress_line = f"{color}[{bar}]{ModernVisualEngine.COLORS['RESET']} {percentage:.1f}%"
        
        if label:
            progress_line = f"{label}: {progress_line}"
        
        if eta > 0:
            eta_str = f" ETA: {eta:.1f}s"
            progress_line += eta_str
        
        if speed:
            progress_line += f" ({speed})"
        
        return progress_line
    
    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create live process dashboard"""
        if not processes:
            return f"{ModernVisualEngine.COLORS['GRAY_DARK']}No active processes{ModernVisualEngine.COLORS['RESET']}"
        
        lines = [
            f"{ModernVisualEngine.COLORS['ELECTRIC_BLUE']}{'='*80}{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['ELECTRIC_BLUE']}🖥️  LIVE PROCESS DASHBOARD{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['ELECTRIC_BLUE']}{'='*80}{ModernVisualEngine.COLORS['RESET']}",
            ""
        ]
        
        for pid, proc_info in processes.items():
            status = proc_info.get('status', 'unknown')
            tool = proc_info.get('tool', 'unknown')
            target = proc_info.get('target', 'unknown')
            progress = proc_info.get('progress', 0.0)
            
            status_color = {
                'running': ModernVisualEngine.COLORS['TOOL_RUNNING'],
                'completed': ModernVisualEngine.COLORS['TOOL_SUCCESS'],
                'failed': ModernVisualEngine.COLORS['TOOL_ERROR'],
                'paused': ModernVisualEngine.COLORS['TOOL_WARNING']
            }.get(status, ModernVisualEngine.COLORS['GRAY_DARK'])
            
            lines.extend([
                f"{ModernVisualEngine.COLORS['WHITE_BRIGHT']}PID {pid}:{ModernVisualEngine.COLORS['RESET']} {status_color}{status.upper()}{ModernVisualEngine.COLORS['RESET']}",
                f"  Tool: {ModernVisualEngine.COLORS['CYBER_ORANGE']}{tool}{ModernVisualEngine.COLORS['RESET']}",
                f"  Target: {ModernVisualEngine.COLORS['NEON_GREEN']}{target}{ModernVisualEngine.COLORS['RESET']}",
                f"  Progress: {ModernVisualEngine.render_progress_bar(progress, width=30)}",
                ""
            ])
        
        return "\n".join(lines)
    
    @staticmethod
    def format_vulnerability_card(vuln_data: Dict[str, Any]) -> str:
        """Format vulnerability information as card"""
        severity = vuln_data.get('severity', 'unknown').lower()
        title = vuln_data.get('title', 'Unknown Vulnerability')
        description = vuln_data.get('description', 'No description available')
        cvss = vuln_data.get('cvss', 'N/A')
        
        severity_colors = {
            'critical': ModernVisualEngine.COLORS['CRITICAL'],
            'high': ModernVisualEngine.COLORS['HIGH'],
            'medium': ModernVisualEngine.COLORS['MEDIUM'],
            'low': ModernVisualEngine.COLORS['LOW'],
            'info': ModernVisualEngine.COLORS['INFO']
        }
        
        severity_color = severity_colors.get(severity, ModernVisualEngine.COLORS['UNKNOWN'])
        
        lines = [
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}┌─ {severity_color}{severity.upper()}{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['PRIMARY_BORDER']}─────────────────────────────────────────────────────────────────┐{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WHITE_BRIGHT']}{title[:65]}{ModernVisualEngine.COLORS['RESET']}{' ' * max(0, 65 - len(title))} {ModernVisualEngine.COLORS['PRIMARY_BORDER']}│{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}├─────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}│{ModernVisualEngine.COLORS['RESET']} {description[:65]}{' ' * max(0, 65 - len(description))} {ModernVisualEngine.COLORS['PRIMARY_BORDER']}│{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}│{ModernVisualEngine.COLORS['RESET']} CVSS: {ModernVisualEngine.COLORS['YELLOW_BRIGHT']}{cvss}{ModernVisualEngine.COLORS['RESET']}{' ' * max(0, 58 - len(str(cvss)))} {ModernVisualEngine.COLORS['PRIMARY_BORDER']}│{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}└─────────────────────────────────────────────────────────────────────┘{ModernVisualEngine.COLORS['RESET']}"
        ]
        
        return "\n".join(lines)
    
    @staticmethod
    def format_error_card(error_type: str, tool_name: str, error_message: str, recovery_action: str = "") -> str:
        """Format error information as card"""
        lines = [
            f"{ModernVisualEngine.COLORS['ERROR']}┌─ ERROR ─────────────────────────────────────────────────────────────────┐{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']} Tool: {ModernVisualEngine.COLORS['CYBER_ORANGE']}{tool_name}{ModernVisualEngine.COLORS['RESET']}{' ' * max(0, 58 - len(tool_name))} {ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']} Type: {ModernVisualEngine.COLORS['WARNING']}{error_type}{ModernVisualEngine.COLORS['RESET']}{' ' * max(0, 58 - len(error_type))} {ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['ERROR']}├─────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}",
            f"{ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']} {error_message[:65]}{' ' * max(0, 65 - len(error_message))} {ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']}"
        ]
        
        if recovery_action:
            lines.extend([
                f"{ModernVisualEngine.COLORS['ERROR']}├─────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}",
                f"{ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']} Recovery: {ModernVisualEngine.COLORS['INFO']}{recovery_action[:55]}{ModernVisualEngine.COLORS['RESET']}{' ' * max(0, 55 - len(recovery_action))} {ModernVisualEngine.COLORS['ERROR']}│{ModernVisualEngine.COLORS['RESET']}"
            ])
        
        lines.append(f"{ModernVisualEngine.COLORS['ERROR']}└─────────────────────────────────────────────────────────────────────┘{ModernVisualEngine.COLORS['RESET']}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "", progress: float = 0.0) -> str:
        """Format tool execution status with enhanced highlighting"""
        status_colors = {
            'RUNNING': ModernVisualEngine.COLORS['TOOL_RUNNING'],
            'SUCCESS': ModernVisualEngine.COLORS['TOOL_SUCCESS'],
            'ERROR': ModernVisualEngine.COLORS['TOOL_ERROR'],
            'WARNING': ModernVisualEngine.COLORS['TOOL_WARNING']
        }
        
        status_color = status_colors.get(status.upper(), ModernVisualEngine.COLORS['GRAY_DARK'])
        
        status_line = f"{ModernVisualEngine.COLORS['CYBER_ORANGE']}[{tool_name}]{ModernVisualEngine.COLORS['RESET']} {status_color}{status}{ModernVisualEngine.COLORS['RESET']}"
        
        if target:
            status_line += f" → {ModernVisualEngine.COLORS['NEON_GREEN']}{target}{ModernVisualEngine.COLORS['RESET']}"
        
        if progress > 0:
            progress_bar = ModernVisualEngine.render_progress_bar(progress, width=20)
            status_line += f" {progress_bar}"
        
        return status_line
    
    @staticmethod
    def format_highlighted_text(text: str, highlight_color: str = None) -> str:
        """Format text with highlighting"""
        if highlight_color is None:
            highlight_color = ModernVisualEngine.COLORS['YELLOW_BRIGHT']
        
        return f"{highlight_color}{text}{ModernVisualEngine.COLORS['RESET']}"
    
    @staticmethod
    def format_vulnerability_severity(severity: str) -> str:
        """Format vulnerability severity with appropriate colors"""
        severity_lower = severity.lower()
        severity_colors = {
            'critical': ModernVisualEngine.COLORS['CRITICAL'],
            'high': ModernVisualEngine.COLORS['HIGH'],
            'medium': ModernVisualEngine.COLORS['MEDIUM'],
            'low': ModernVisualEngine.COLORS['LOW'],
            'info': ModernVisualEngine.COLORS['INFO']
        }
        
        color = severity_colors.get(severity_lower, ModernVisualEngine.COLORS['UNKNOWN'])
        return f"{color}{severity.upper()}{ModernVisualEngine.COLORS['RESET']}"
    
    @staticmethod
    def create_section_header(title: str) -> str:
        """Create section header with styling"""
        return f"\n{ModernVisualEngine.COLORS['ELECTRIC_BLUE']}{'='*60}{ModernVisualEngine.COLORS['RESET']}\n{ModernVisualEngine.COLORS['WHITE_BRIGHT']}{title}{ModernVisualEngine.COLORS['RESET']}\n{ModernVisualEngine.COLORS['ELECTRIC_BLUE']}{'='*60}{ModernVisualEngine.COLORS['RESET']}\n"
    
    @staticmethod
    def format_command_execution(command: str, status: str = "running") -> str:
        """Format command execution display"""
        status_colors = {
            'running': ModernVisualEngine.COLORS['TOOL_RUNNING'],
            'completed': ModernVisualEngine.COLORS['TOOL_SUCCESS'],
            'failed': ModernVisualEngine.COLORS['TOOL_ERROR']
        }
        
        status_color = status_colors.get(status, ModernVisualEngine.COLORS['GRAY_DARK'])
        
        return f"{ModernVisualEngine.COLORS['GRAY_DARK']}${ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WHITE_BRIGHT']}{command}{ModernVisualEngine.COLORS['RESET']} {status_color}[{status.upper()}]{ModernVisualEngine.COLORS['RESET']}"

VisualEngine = ModernVisualEngine
