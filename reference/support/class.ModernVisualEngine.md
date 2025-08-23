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
Complete class with all static methods for visual formatting, color management, and status display functionality. Essential for user interface consistency throughout the HexStrike framework.
