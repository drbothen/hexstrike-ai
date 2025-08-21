"""
Visual output formatting interfaces and implementations.

This module changes when visual output formatting requirements or color schemes change.
"""

from typing import Dict, Any, Optional
import time
from ..platform.constants import COLORS

class VisualEngine:
    """Main visual formatting interface"""
    
    @staticmethod
    def create_banner() -> str:
        """Create application banner"""
        banner_lines = [
            f"{COLORS['PRIMARY_BORDER']}╔══════════════════════════════════════════════════════════════════════════════╗{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}                                                                              {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['FIRE_RED']}██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗{COLORS['RESET']}  {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['FIRE_RED']}██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝{COLORS['RESET']}  {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['CYBER_ORANGE']}███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗{COLORS['RESET']}    {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['CYBER_ORANGE']}██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝{COLORS['RESET']}    {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['YELLOW_BRIGHT']}██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗{COLORS['RESET']}  {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['YELLOW_BRIGHT']}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{COLORS['RESET']}  {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}                                                                              {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}           {COLORS['NEON_GREEN']}🚀 Advanced AI-Powered Penetration Testing Framework 🚀{COLORS['RESET']}           {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}                                                                              {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}  {COLORS['ELECTRIC_BLUE']}Version: 6.0.0{COLORS['RESET']}  {COLORS['GRAY_DARK']}|{COLORS['RESET']}  {COLORS['PURPLE_GLOW']}Bug Bounty{COLORS['RESET']}  {COLORS['GRAY_DARK']}|{COLORS['RESET']}  {COLORS['PURPLE_GLOW']}CTF{COLORS['RESET']}  {COLORS['GRAY_DARK']}|{COLORS['RESET']}  {COLORS['PURPLE_GLOW']}Red Team{COLORS['RESET']}  {COLORS['GRAY_DARK']}|{COLORS['RESET']}  {COLORS['PURPLE_GLOW']}Research{COLORS['RESET']}  {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}                                                                              {COLORS['PRIMARY_BORDER']}║{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}╚══════════════════════════════════════════════════════════════════════════════╝{COLORS['RESET']}"
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
        return f"{COLORS['CYBER_ORANGE']}[{bar}]{COLORS['RESET']} {percentage:.1f}%{tool_info}"
    
    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber', 
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render advanced progress bar with cyber styling"""
        percentage = max(0, min(100, progress * 100))
        filled_width = int(width * progress)
        
        if style == 'cyber':
            filled_char = "█"
            empty_char = "░"
            color = COLORS['NEON_GREEN'] if progress >= 1.0 else COLORS['CYBER_ORANGE']
        else:
            filled_char = "="
            empty_char = "-"
            color = COLORS['SUCCESS'] if progress >= 1.0 else COLORS['INFO']
        
        bar = filled_char * filled_width + empty_char * (width - filled_width)
        
        progress_line = f"{color}[{bar}]{COLORS['RESET']} {percentage:.1f}%"
        
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
            return f"{COLORS['GRAY_DARK']}No active processes{COLORS['RESET']}"
        
        lines = [
            f"{COLORS['ELECTRIC_BLUE']}{'='*80}{COLORS['RESET']}",
            f"{COLORS['ELECTRIC_BLUE']}🖥️  LIVE PROCESS DASHBOARD{COLORS['RESET']}",
            f"{COLORS['ELECTRIC_BLUE']}{'='*80}{COLORS['RESET']}",
            ""
        ]
        
        for pid, proc_info in processes.items():
            status = proc_info.get('status', 'unknown')
            tool = proc_info.get('tool', 'unknown')
            target = proc_info.get('target', 'unknown')
            progress = proc_info.get('progress', 0.0)
            
            status_color = {
                'running': COLORS['TOOL_RUNNING'],
                'completed': COLORS['TOOL_SUCCESS'],
                'failed': COLORS['TOOL_ERROR'],
                'paused': COLORS['TOOL_WARNING']
            }.get(status, COLORS['GRAY_DARK'])
            
            lines.extend([
                f"{COLORS['WHITE_BRIGHT']}PID {pid}:{COLORS['RESET']} {status_color}{status.upper()}{COLORS['RESET']}",
                f"  Tool: {COLORS['CYBER_ORANGE']}{tool}{COLORS['RESET']}",
                f"  Target: {COLORS['NEON_GREEN']}{target}{COLORS['RESET']}",
                f"  Progress: {VisualEngine.render_progress_bar(progress, width=30)}",
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
            'critical': COLORS['CRITICAL'],
            'high': COLORS['HIGH'],
            'medium': COLORS['MEDIUM'],
            'low': COLORS['LOW'],
            'info': COLORS['INFO']
        }
        
        severity_color = severity_colors.get(severity, COLORS['UNKNOWN'])
        
        lines = [
            f"{COLORS['PRIMARY_BORDER']}┌─ {severity_color}{severity.upper()}{COLORS['RESET']} {COLORS['PRIMARY_BORDER']}─────────────────────────────────────────────────────────────────┐{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}│{COLORS['RESET']} {COLORS['WHITE_BRIGHT']}{title[:65]}{COLORS['RESET']}{' ' * max(0, 65 - len(title))} {COLORS['PRIMARY_BORDER']}│{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}├─────────────────────────────────────────────────────────────────────┤{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}│{COLORS['RESET']} {description[:65]}{' ' * max(0, 65 - len(description))} {COLORS['PRIMARY_BORDER']}│{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}│{COLORS['RESET']} CVSS: {COLORS['YELLOW_BRIGHT']}{cvss}{COLORS['RESET']}{' ' * max(0, 58 - len(str(cvss)))} {COLORS['PRIMARY_BORDER']}│{COLORS['RESET']}",
            f"{COLORS['PRIMARY_BORDER']}└─────────────────────────────────────────────────────────────────────┘{COLORS['RESET']}"
        ]
        
        return "\n".join(lines)
    
    @staticmethod
    def format_error_card(error_type: str, tool_name: str, error_message: str, recovery_action: str = "") -> str:
        """Format error information as card"""
        lines = [
            f"{COLORS['ERROR']}┌─ ERROR ─────────────────────────────────────────────────────────────────┐{COLORS['RESET']}",
            f"{COLORS['ERROR']}│{COLORS['RESET']} Tool: {COLORS['CYBER_ORANGE']}{tool_name}{COLORS['RESET']}{' ' * max(0, 58 - len(tool_name))} {COLORS['ERROR']}│{COLORS['RESET']}",
            f"{COLORS['ERROR']}│{COLORS['RESET']} Type: {COLORS['WARNING']}{error_type}{COLORS['RESET']}{' ' * max(0, 58 - len(error_type))} {COLORS['ERROR']}│{COLORS['RESET']}",
            f"{COLORS['ERROR']}├─────────────────────────────────────────────────────────────────────┤{COLORS['RESET']}",
            f"{COLORS['ERROR']}│{COLORS['RESET']} {error_message[:65]}{' ' * max(0, 65 - len(error_message))} {COLORS['ERROR']}│{COLORS['RESET']}"
        ]
        
        if recovery_action:
            lines.extend([
                f"{COLORS['ERROR']}├─────────────────────────────────────────────────────────────────────┤{COLORS['RESET']}",
                f"{COLORS['ERROR']}│{COLORS['RESET']} Recovery: {COLORS['INFO']}{recovery_action[:55]}{COLORS['RESET']}{' ' * max(0, 55 - len(recovery_action))} {COLORS['ERROR']}│{COLORS['RESET']}"
            ])
        
        lines.append(f"{COLORS['ERROR']}└─────────────────────────────────────────────────────────────────────┘{COLORS['RESET']}")
        
        return "\n".join(lines)
    
    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "", progress: float = 0.0) -> str:
        """Format tool execution status with enhanced highlighting"""
        status_colors = {
            'RUNNING': COLORS['TOOL_RUNNING'],
            'SUCCESS': COLORS['TOOL_SUCCESS'],
            'ERROR': COLORS['TOOL_ERROR'],
            'WARNING': COLORS['TOOL_WARNING']
        }
        
        status_color = status_colors.get(status.upper(), COLORS['GRAY_DARK'])
        
        status_line = f"{COLORS['CYBER_ORANGE']}[{tool_name}]{COLORS['RESET']} {status_color}{status}{COLORS['RESET']}"
        
        if target:
            status_line += f" → {COLORS['NEON_GREEN']}{target}{COLORS['RESET']}"
        
        if progress > 0:
            progress_bar = VisualEngine.render_progress_bar(progress, width=20)
            status_line += f" {progress_bar}"
        
        return status_line
    
    @staticmethod
    def format_highlighted_text(text: str, highlight_color: str = None) -> str:
        """Format text with highlighting"""
        if highlight_color is None:
            highlight_color = COLORS['YELLOW_BRIGHT']
        
        return f"{highlight_color}{text}{COLORS['RESET']}"
    
    @staticmethod
    def format_vulnerability_severity(severity: str) -> str:
        """Format vulnerability severity with appropriate colors"""
        severity_lower = severity.lower()
        severity_colors = {
            'critical': COLORS['CRITICAL'],
            'high': COLORS['HIGH'],
            'medium': COLORS['MEDIUM'],
            'low': COLORS['LOW'],
            'info': COLORS['INFO']
        }
        
        color = severity_colors.get(severity_lower, COLORS['UNKNOWN'])
        return f"{color}{severity.upper()}{COLORS['RESET']}"
    
    @staticmethod
    def create_section_header(title: str) -> str:
        """Create section header with styling"""
        return f"\n{COLORS['ELECTRIC_BLUE']}{'='*60}{COLORS['RESET']}\n{COLORS['WHITE_BRIGHT']}{title}{COLORS['RESET']}\n{COLORS['ELECTRIC_BLUE']}{'='*60}{COLORS['RESET']}\n"
    
    @staticmethod
    def format_command_execution(command: str, status: str = "running") -> str:
        """Format command execution display"""
        status_colors = {
            'running': COLORS['TOOL_RUNNING'],
            'completed': COLORS['TOOL_SUCCESS'],
            'failed': COLORS['TOOL_ERROR']
        }
        
        status_color = status_colors.get(status, COLORS['GRAY_DARK'])
        
        return f"{COLORS['GRAY_DARK']}${COLORS['RESET']} {COLORS['WHITE_BRIGHT']}{command}{COLORS['RESET']} {status_color}[{status.upper()}]{COLORS['RESET']}"
