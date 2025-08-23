---
title: function.setup_logging
kind: function
scope: module
module: __main__
line_range: [5984, 6001]
discovered_in_chunk: 5
---

# Function: setup_logging

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Setup enhanced logging with colors and formatting

## Complete Signature & Definition
```python
def setup_logging():
    """Setup enhanced logging with colors and formatting"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(console_handler)
    
    return logger
```

## Purpose & Behavior
Enhanced logging setup function providing:
- **Logger Configuration:** Configure root logger with INFO level
- **Handler Management:** Clear existing handlers and add enhanced console handler
- **ColoredFormatter Integration:** Apply custom colored formatter with emojis
- **Consistent Format:** Standardized log format with HexStrike AI branding

## Dependencies & Usage
- **Depends on:**
  - logging module for logger configuration
  - sys.stdout for console output
  - ColoredFormatter for enhanced formatting
- **Used by:**
  - Application initialization
  - Logging system setup
  - Development and production environments

## Implementation Details

### Logging Configuration
- **Log Level:** Set to logging.INFO for standard information logging
- **Handler Cleanup:** Remove all existing handlers to avoid conflicts
- **Console Output:** Direct logging to sys.stdout for console visibility

### Formatter Configuration
- **Format String:** "[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s"
- **Date Format:** "%Y-%m-%d %H:%M:%S" for consistent timestamp format
- **Branding:** Includes HexStrike AI branding with fire emoji

### Setup Process
1. **Logger Retrieval:** Get root logger instance
2. **Level Setting:** Set logging level to INFO
3. **Handler Cleanup:** Remove existing handlers to prevent duplicates
4. **Console Handler Creation:** Create StreamHandler for console output
5. **Formatter Application:** Apply ColoredFormatter with custom format
6. **Handler Registration:** Add console handler to logger
7. **Logger Return:** Return configured logger instance

## Testing & Validation
- Logger configuration verification
- Handler setup and cleanup testing
- Formatter application validation
- Log output format and color testing

## Code Reproduction
```python
def setup_logging():
    """Setup enhanced logging with colors and formatting"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(console_handler)
    
    return logger
```
