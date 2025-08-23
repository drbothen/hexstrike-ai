---
title: constant.visual.color_codes
kind: constant
scope: module
module: __main__
line_range: [5689, 5703]
discovered_in_chunk: 5
---

# Visual Color Codes Constants

## Entity Classification & Context
- **Kind:** Module-level constants
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Enhanced color codes and visual elements for modern terminal output

## Complete Signature & Definition
```python
# Enhanced color codes and visual elements for modern terminal output
# All color references consolidated to ModernVisualEngine.COLORS for consistency
BG_GREEN = '\033[42m'
BG_YELLOW = '\033[43m'
BG_BLUE = '\033[44m'
BG_MAGENTA = '\033[45m'
BG_CYAN = '\033[46m'
BG_WHITE = '\033[47m'

# Text effects
DIM = '\033[2m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'
STRIKETHROUGH = '\033[9m'
```

## Purpose & Behavior
ANSI color codes and text effects for enhanced terminal output formatting, providing background colors and text styling effects for modern terminal interfaces.

## Dependencies & Usage
- **Depends on:** ANSI terminal support
- **Used by:** Terminal output formatting, visual enhancement systems
- **Note:** References consolidated to ModernVisualEngine.COLORS for consistency

## Implementation Details

### Background Colors (6 Colors)
- **BG_GREEN:** '\033[42m' - Green background
- **BG_YELLOW:** '\033[43m' - Yellow background  
- **BG_BLUE:** '\033[44m' - Blue background
- **BG_MAGENTA:** '\033[45m' - Magenta background
- **BG_CYAN:** '\033[46m' - Cyan background
- **BG_WHITE:** '\033[47m' - White background

### Text Effects (5 Effects)
- **DIM:** '\033[2m' - Dimmed text
- **UNDERLINE:** '\033[4m' - Underlined text
- **BLINK:** '\033[5m' - Blinking text
- **REVERSE:** '\033[7m' - Reversed colors
- **STRIKETHROUGH:** '\033[9m' - Strikethrough text

## Testing & Validation
- ANSI code compatibility testing
- Terminal rendering verification
- Color and effect display validation

## Code Reproduction
```python
# Enhanced color codes and visual elements for modern terminal output
# All color references consolidated to ModernVisualEngine.COLORS for consistency
BG_GREEN = '\033[42m'
BG_YELLOW = '\033[43m'
BG_BLUE = '\033[44m'
BG_MAGENTA = '\033[45m'
BG_CYAN = '\033[46m'
BG_WHITE = '\033[47m'

# Text effects
DIM = '\033[2m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
REVERSE = '\033[7m'
STRIKETHROUGH = '\033[9m'
```
