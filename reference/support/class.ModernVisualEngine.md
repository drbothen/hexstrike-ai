---
title: class.ModernVisualEngine
kind: class
module: __main__
line_range: [105, 439]
discovered_in_chunk: 1
---

# ModernVisualEngine Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Beautiful, modern output formatting with animations and colors

## Complete Signature & Definition
```python
class ModernVisualEngine:
    """Beautiful, modern output formatting with animations and colors"""
```

## Purpose & Behavior
Provides comprehensive visual formatting capabilities for the HexStrike AI framework with:
- Enhanced color palette with reddish hacker theme
- Progress bars and animations
- Vulnerability cards and error formatting
- Live dashboard displays
- Command execution status formatting

## Dependencies & Usage
- **Depends on:** None (standalone utility class)
- **Used by:** Throughout the application for visual output formatting
- **Static Methods:** All methods are static, no instance creation required

## Implementation Details

### Color Palette
- **Primary Theme:** Reddish hacker aesthetic with blood-red tones
- **Color Categories:** Matrix green, neon blue, electric purple, cyber orange, hacker red
- **Specialized Colors:** Vulnerability severity, tool status, progress indicators
- **Highlighting:** Background/foreground color combinations

### Key Methods
1. **create_banner()** - ASCII art banner with HexStrike branding
2. **create_progress_bar()** - Cyberpunk-styled progress indicators
3. **render_progress_bar()** - Multiple progress bar styles (cyber, matrix, neon)
4. **create_live_dashboard()** - Real-time process monitoring display
5. **format_vulnerability_card()** - Security finding presentation
6. **format_error_card()** - Error display with recovery actions
7. **format_tool_status()** - Tool execution status indicators
8. **format_highlighted_text()** - Text highlighting utilities
9. **format_vulnerability_severity()** - Severity-based color coding
10. **create_section_header()** - Styled section dividers
11. **format_command_execution()** - Command status with timing

### Visual Features
- **ANSI Color Codes:** Full 256-color palette support
- **Animation Styles:** Dots, bars, arrows, pulse patterns
- **Responsive Design:** Adjustable width and styling options
- **Status Indicators:** Running, success, failed, timeout states

## Testing & Validation
- Visual output testing through console display
- Color compatibility across terminal types
- Animation timing and performance validation

## Code Reproduction
```python
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
        # Unified theme primary/secondary
        'PRIMARY_BORDER': '\033[38;5;160m',  # CRIMSON
        'ACCENT_LINE': '\033[38;5;196m',      # HACKER_RED
        'ACCENT_GRADIENT': '\033[38;5;124m',  # BLOOD_RED
        # Additional color definitions...
    }
    
    @staticmethod
    def create_banner() -> str:
        """Create the enhanced HexStrike banner"""
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

{ModernVisualEngine.COLORS['TERMINAL_GRAY']}[INFO] Server starting on {API_HOST}:{API_PORT}
[INFO] 150+ integrated modules | Adaptive AI decision engine active
[INFO] Blood-red theme engaged – unified offensive operations UI{RESET}
"""
        return banner
    
    # Additional methods: create_progress_bar, render_progress_bar, create_live_dashboard,
    # format_vulnerability_card, format_error_card, format_tool_status, etc.
```
