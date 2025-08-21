"""
Visual output formatting interfaces and implementations.

This module changes when visual output formatting requirements or color schemes change.
"""

from typing import Dict, Any, Optional
import time

VisualEngine = None

class ModernVisualEngine:
    """Beautiful, modern output formatting with animations and colors"""
    
    # Enhanced color palette with reddish tones and better highlighting
    COLORS = {
        'MATRIX_GREEN': '\033[38;5;46m',
        'NEON_BLUE': '\033[38;5;51m', 
        'ELECTRIC_PURPLE': '\033[38;5;129m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'HACKER_RED': '\033[38;5;196m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'BRIGHT_WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        # New reddish tones and highlighting colors
        'BLOOD_RED': '\033[38;5;124m',
        'CRIMSON': '\033[38;5;160m',
        'DARK_RED': '\033[38;5;88m',
        'FIRE_RED': '\033[38;5;202m',
        'ROSE_RED': '\033[38;5;167m',
        'BURGUNDY': '\033[38;5;52m',
        'SCARLET': '\033[38;5;197m',
        'RUBY': '\033[38;5;161m',
        # Unified theme primary/secondary (used going forward instead of legacy blue/green accents)
        'PRIMARY_BORDER': '\033[38;5;160m',  # CRIMSON
        'ACCENT_LINE': '\033[38;5;196m',      # HACKER_RED
        'ACCENT_GRADIENT': '\033[38;5;124m',  # BLOOD_RED (for subtle alternation)
        # Highlighting colors
        'HIGHLIGHT_RED': '\033[48;5;196m\033[38;5;15m',  # Red background, white text
        'HIGHLIGHT_YELLOW': '\033[48;5;226m\033[38;5;16m',  # Yellow background, black text
        'HIGHLIGHT_GREEN': '\033[48;5;46m\033[38;5;16m',  # Green background, black text
        'HIGHLIGHT_BLUE': '\033[48;5;51m\033[38;5;16m',  # Blue background, black text
        'HIGHLIGHT_PURPLE': '\033[48;5;129m\033[38;5;15m',  # Purple background, white text
        # Status colors with reddish tones
        'SUCCESS': '\033[38;5;46m',  # Bright green
        'WARNING': '\033[38;5;208m',  # Orange
        'ERROR': '\033[38;5;196m',  # Bright red
        'CRITICAL': '\033[48;5;196m\033[38;5;15m\033[1m',  # Red background, white bold text
        'INFO': '\033[38;5;51m',  # Cyan
        'DEBUG': '\033[38;5;240m',  # Gray
        # Vulnerability severity colors
        'VULN_CRITICAL': '\033[48;5;124m\033[38;5;15m\033[1m',  # Dark red background
        'VULN_HIGH': '\033[38;5;196m\033[1m',  # Bright red bold
        'VULN_MEDIUM': '\033[38;5;208m\033[1m',  # Orange bold
        'VULN_LOW': '\033[38;5;226m',  # Yellow
        'VULN_INFO': '\033[38;5;51m',  # Cyan
        # Tool status colors
        'TOOL_RUNNING': '\033[38;5;46m\033[5m',  # Blinking green
        'TOOL_SUCCESS': '\033[38;5;46m\033[1m',  # Bold green
        'TOOL_FAILED': '\033[38;5;196m\033[1m',  # Bold red
        'TOOL_TIMEOUT': '\033[38;5;208m\033[1m',  # Bold orange
        'TOOL_RECOVERY': '\033[38;5;129m\033[1m',  # Bold purple
        # Progress and animation colors
        'PROGRESS_BAR': '\033[38;5;46m',  # Green
        'PROGRESS_EMPTY': '\033[38;5;240m',  # Gray
        'SPINNER': '\033[38;5;51m',  # Cyan
        'PULSE': '\033[38;5;196m\033[5m'  # Blinking red
    }
    
    # Progress animation styles
    PROGRESS_STYLES = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
        'bars': ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
        'arrows': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        'pulse': ['●', '◐', '◑', '◒', '◓', '◔', '◕', '◖', '◗', '◘']
    }
    
    @staticmethod
    def create_banner() -> str:
        """Create the enhanced HexStrike banner"""
        # Build a blood-red themed border using primary/gradient alternation
        border_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        accent = ModernVisualEngine.COLORS['ACCENT_LINE']
        gradient = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        RESET = ModernVisualEngine.COLORS['RESET']
        BOLD = ModernVisualEngine.COLORS['BOLD']
        title_block = f"{accent}{BOLD}"
        banner = f"""
{title_block}
██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
{RESET}
{border_color}┌─────────────────────────────────────────────────────────────────────┐
│  {ModernVisualEngine.COLORS['BRIGHT_WHITE']}🚀 HexStrike AI - Blood-Red Offensive Intelligence Core{border_color}        │
│  {accent}⚡ AI-Automated Recon | Exploitation | Analysis Pipeline{border_color}          │
│  {gradient}🎯 Bug Bounty | CTF | Red Team | Zero-Day Research{border_color}              │
└─────────────────────────────────────────────────────────────────────┘{RESET}

{ModernVisualEngine.COLORS['TERMINAL_GRAY']}[INFO] Server starting on 127.0.0.1:8888
[INFO] 150+ integrated modules | Adaptive AI decision engine active
[INFO] Blood-red theme engaged – unified offensive operations UI{RESET}
"""
        return banner
    
    @staticmethod
    def create_progress_bar(current: int, total: int, width: int = 50, tool: str = "") -> str:
        """Create a beautiful progress bar with cyberpunk styling"""
        if total == 0:
            percentage = 0
        else:
            percentage = min(100, (current / total) * 100)
        
        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)
        
        border = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        fill_col = ModernVisualEngine.COLORS['ACCENT_LINE']
        return f"""
{border}┌─ {tool} ─{'─' * (width - len(tool) - 4)}┐
│ {fill_col}{bar}{border} │ {percentage:6.1f}%
└─{'─' * (width + 10)}┘{ModernVisualEngine.COLORS['RESET']}"""

    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber', 
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a beautiful progress bar with multiple styles"""
        
        # Clamp progress between 0 and 1
        progress = max(0.0, min(1.0, progress))
        
        # Calculate filled and empty portions
        filled_width = int(width * progress)
        empty_width = width - filled_width
        
        # Style-specific rendering
        if style == 'cyber':
            filled_char = '█'
            empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        elif style == 'matrix':
            filled_char = '▓'
            empty_char = '▒'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        elif style == 'neon':
            filled_char = '━'
            empty_char = '─'
            bar_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
            progress_color = ModernVisualEngine.COLORS['CYBER_ORANGE']
        else:  # default
            filled_char = '█'
            empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        
        # Build the progress bar
        filled_part = bar_color + filled_char * filled_width
        empty_part = ModernVisualEngine.COLORS['TERMINAL_GRAY'] + empty_char * empty_width
        percentage = f"{progress * 100:.1f}%"
        
        # Add ETA and speed if provided
        extra_info = ""
        if eta > 0:
            extra_info += f" ETA: {eta:.1f}s"
        if speed:
            extra_info += f" Speed: {speed}"
        
        # Build final progress bar
        bar_display = f"[{filled_part}{empty_part}{ModernVisualEngine.COLORS['RESET']}] {progress_color}{percentage}{ModernVisualEngine.COLORS['RESET']}"
        
        if label:
            return f"{label}: {bar_display}{extra_info}"
        else:
            return f"{bar_display}{extra_info}"

    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create a live dashboard showing all active processes"""
        
        if not processes:
            return f"""
{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╭─────────────────────────────────────────────────────────────────────────────╮
│ {ModernVisualEngine.COLORS['ACCENT_LINE']}📊 HEXSTRIKE LIVE DASHBOARD{ModernVisualEngine.COLORS['PRIMARY_BORDER']}                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}No active processes currently running{ModernVisualEngine.COLORS['PRIMARY_BORDER']}                                    │
╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
        
        dashboard_lines = [
            f"{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╭─────────────────────────────────────────────────────────────────────────────╮",
            f"│ {ModernVisualEngine.COLORS['ACCENT_LINE']}📊 HEXSTRIKE LIVE DASHBOARD{ModernVisualEngine.COLORS['PRIMARY_BORDER']}                                           │",
            f"├─────────────────────────────────────────────────────────────────────────────┤"
        ]
        
        for pid, proc_info in processes.items():
            status = proc_info.get('status', 'unknown')
            tool = proc_info.get('tool', 'unknown')
            target = proc_info.get('target', 'N/A')
            
            status_color = ModernVisualEngine.COLORS.get(f'TOOL_{status.upper()}', ModernVisualEngine.COLORS['INFO'])
            dashboard_lines.append(
                f"│ {status_color}PID {pid}: {tool} → {target[:30]}{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'.' * (40 - len(target[:30]))} │"
            )
        
        dashboard_lines.append(f"╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}")
        
        return '\n'.join(dashboard_lines)

    @staticmethod
    def format_vulnerability_card(vuln: Dict[str, Any]) -> str:
        """Format vulnerability information as a beautiful card"""
        severity = vuln.get('severity', 'info').upper()
        severity_color = ModernVisualEngine.COLORS.get(f'VULN_{severity}', ModernVisualEngine.COLORS['INFO'])
        
        title = vuln.get('title', 'Unknown Vulnerability')
        description = vuln.get('description', 'No description available')
        cvss = vuln.get('cvss', 'N/A')
        
        card = f"""
{ModernVisualEngine.COLORS['PRIMARY_BORDER']}╭─ {severity_color}{severity} VULNERABILITY{ModernVisualEngine.COLORS['PRIMARY_BORDER']} ─{'─' * (50 - len(severity))}╮
│ {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{title[:70]}{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'.' * (70 - len(title[:70]))} │
├─────────────────────────────────────────────────────────────────────────────┤
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}{description[:70]}{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'.' * (70 - len(description[:70]))} │
│ {ModernVisualEngine.COLORS['CYBER_ORANGE']}CVSS Score: {cvss}{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'.' * (60 - len(str(cvss)))} │
╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
        return card

    @staticmethod
    def format_error_card(error: str, context: str = "") -> str:
        """Format error information as a beautiful card"""
        
        card = f"""
{ModernVisualEngine.COLORS['ERROR']}╭─ ERROR ─{'─' * 70}╮
│ {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{error[:70]}{ModernVisualEngine.COLORS['ERROR']}{'.' * (70 - len(error[:70]))} │"""
        
        if context:
            card += f"""
├─────────────────────────────────────────────────────────────────────────────┤
│ {ModernVisualEngine.COLORS['TERMINAL_GRAY']}{context[:70]}{ModernVisualEngine.COLORS['ERROR']}{'.' * (70 - len(context[:70]))} │"""
        
        card += f"""
╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
        return card

    @staticmethod
    def format_tool_status(tool: str, status: str, details: str = "") -> str:
        """Format tool execution status with beautiful styling"""
        status_color = ModernVisualEngine.COLORS.get(f'TOOL_{status.upper()}', ModernVisualEngine.COLORS['INFO'])
        
        status_line = f"{status_color}[{status.upper()}]{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{tool}{ModernVisualEngine.COLORS['RESET']}"
        
        if details:
            status_line += f" - {ModernVisualEngine.COLORS['TERMINAL_GRAY']}{details}{ModernVisualEngine.COLORS['RESET']}"
        
        return status_line

    @staticmethod
    def format_highlighted_text(text: str, highlight_type: str = 'red') -> str:
        """Format text with highlighting"""
        highlight_color = ModernVisualEngine.COLORS.get(f'HIGHLIGHT_{highlight_type.upper()}', ModernVisualEngine.COLORS['HIGHLIGHT_RED'])
        return f"{highlight_color}{text}{ModernVisualEngine.COLORS['RESET']}"

    @staticmethod
    def format_vulnerability_severity(severity: str) -> str:
        """Format vulnerability severity with appropriate colors"""
        severity_upper = severity.upper()
        color = ModernVisualEngine.COLORS.get(f'VULN_{severity_upper}', ModernVisualEngine.COLORS['INFO'])
        
        if severity_upper == 'CRITICAL':
            return f"{color} ⚠️  CRITICAL {ModernVisualEngine.COLORS['RESET']}"
        elif severity_upper == 'HIGH':
            return f"{color} 🔴 HIGH {ModernVisualEngine.COLORS['RESET']}"
        elif severity_upper == 'MEDIUM':
            return f"{color} 🟡 MEDIUM {ModernVisualEngine.COLORS['RESET']}"
        elif severity_upper == 'LOW':
            return f"{color} 🟢 LOW {ModernVisualEngine.COLORS['RESET']}"
        else:
            return f"{color} ℹ️  INFO {ModernVisualEngine.COLORS['RESET']}"

    @staticmethod
    def create_section_header(title: str) -> str:
        """Create a beautiful section header"""
        return f"\n{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'═' * 80}\n{ModernVisualEngine.COLORS['ACCENT_LINE']}  {title}\n{ModernVisualEngine.COLORS['PRIMARY_BORDER']}{'═' * 80}{ModernVisualEngine.COLORS['RESET']}\n"

VisualEngine = ModernVisualEngine
