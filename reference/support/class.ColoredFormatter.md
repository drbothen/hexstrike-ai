---
title: class.ColoredFormatter
kind: class
module: __main__
line_range: [5956, 5981]
discovered_in_chunk: 5
---

# ColoredFormatter Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Custom formatter with colors and emojis for enhanced logging

## Complete Signature & Definition
```python
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""
    
    COLORS = {
        'DEBUG': ModernVisualEngine.COLORS['DEBUG'],
        'INFO': ModernVisualEngine.COLORS['SUCCESS'],
        'WARNING': ModernVisualEngine.COLORS['WARNING'],
        'ERROR': ModernVisualEngine.COLORS['ERROR'],
        'CRITICAL': ModernVisualEngine.COLORS['CRITICAL']
    }
    
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }
    
    def format(self, record):
        """Format log record with colors and emojis"""
```

## Purpose & Behavior
Enhanced logging formatter providing:
- **Color-coded Logging:** Different colors for each log level
- **Emoji Integration:** Visual emoji indicators for log levels
- **ModernVisualEngine Integration:** Consistent color scheme with visual framework
- **Enhanced Readability:** Improved log message visibility and categorization

## Dependencies & Usage
- **Depends on:**
  - logging.Formatter as base class
  - ModernVisualEngine.COLORS for color constants
- **Used by:**
  - Enhanced logging setup
  - Console log output formatting
  - Development and debugging workflows

## Implementation Details

### Core Attributes
- **COLORS:** Log level to color mapping (5 levels)
- **EMOJIS:** Log level to emoji mapping (5 levels)

### Key Methods

#### Log Formatting
1. **format(record):** Format log record with colors and emojis

### Color Mapping (5 Log Levels)

#### Log Level Colors
- **DEBUG:** ModernVisualEngine.COLORS['DEBUG']
- **INFO:** ModernVisualEngine.COLORS['SUCCESS']
- **WARNING:** ModernVisualEngine.COLORS['WARNING']
- **ERROR:** ModernVisualEngine.COLORS['ERROR']
- **CRITICAL:** ModernVisualEngine.COLORS['CRITICAL']

### Emoji Mapping (5 Log Levels)

#### Log Level Emojis
- **DEBUG:** 🔍 (magnifying glass for investigation)
- **INFO:** ✅ (check mark for success/information)
- **WARNING:** ⚠️ (warning sign for caution)
- **ERROR:** ❌ (cross mark for errors)
- **CRITICAL:** 🔥 (fire for critical issues)

### Log Record Formatting

#### Formatting Process
1. **Emoji Selection:** Get emoji for log level (default: 📝)
2. **Color Selection:** Get color for log level (default: BRIGHT_WHITE)
3. **Message Enhancement:** Add color and emoji to message
4. **Reset Integration:** Add color reset after message
5. **Parent Formatting:** Call parent formatter for final formatting

#### Formatting Algorithm
```python
emoji = self.EMOJIS.get(record.levelname, '📝')
color = self.COLORS.get(record.levelname, ModernVisualEngine.COLORS['BRIGHT_WHITE'])
record.msg = f"{color}{emoji} {record.msg}{ModernVisualEngine.COLORS['RESET']}"
return super().format(record)
```

### Visual Enhancement Features

#### Color Integration
- **Consistent Colors:** Uses ModernVisualEngine color constants
- **Level Differentiation:** Different colors for easy level identification
- **Reset Handling:** Proper color reset to avoid bleeding

#### Emoji Enhancement
- **Visual Indicators:** Clear visual indicators for log levels
- **Quick Recognition:** Fast visual recognition of log importance
- **Unicode Support:** Rich unicode emoji support

### Integration with Logging Framework

#### Formatter Inheritance
- **Base Class:** Inherits from logging.Formatter
- **Standard Interface:** Maintains standard logging formatter interface
- **Enhanced Output:** Adds visual enhancements to standard formatting

#### Message Processing
- **Record Modification:** Modifies record.msg with visual enhancements
- **Parent Delegation:** Delegates final formatting to parent class
- **Compatibility:** Maintains compatibility with logging framework

### Use Cases and Applications

#### Development Logging
- **Enhanced Debugging:** Visual debugging with color-coded logs
- **Quick Issue Identification:** Fast identification of errors and warnings
- **Improved Development Experience:** Better visual feedback during development

#### Production Monitoring
- **Log Level Visualization:** Clear visual distinction between log levels
- **Alert Recognition:** Quick recognition of critical issues
- **Operational Monitoring:** Enhanced operational log monitoring

### Configuration Integration

#### Setup Integration
- **Console Handler:** Designed for console output formatting
- **Format String:** Works with standard logging format strings
- **DateTime Integration:** Supports datetime formatting in logs

## Testing & Validation
- Color and emoji rendering testing
- Log level mapping verification
- Formatter inheritance functionality validation
- Visual output quality assessment

## Code Reproduction
Complete class implementation with 1 method for custom log formatting with colors and emojis, including comprehensive log level mapping and visual enhancement integration. Essential for enhanced logging and development experience.
