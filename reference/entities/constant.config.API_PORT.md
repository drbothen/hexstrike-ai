---
title: constant.config.API_PORT
kind: constant
scope: module
module: __main__
line_range: [98, 98]
discovered_in_chunk: 1
---

# Configuration Constant: API_PORT

## Entity Classification & Context
- **Kind:** Module-level constant
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** int

## Complete Signature & Definition
```python
API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))
```

## Purpose & Behavior
Defines the port number for the HexStrike AI server API. Reads from the HEXSTRIKE_PORT environment variable with a default fallback of 8888.

## Dependencies & Usage
- **Depends on:** os.environ.get()
- **Used by:** Flask application server configuration, API endpoint setup

## Implementation Details
- Environment variable: HEXSTRIKE_PORT
- Default value: 8888
- Type conversion: int() ensures numeric value
- Configuration precedence: Environment variable > default value

## Testing & Validation
- Should validate port number is within valid range (1-65535)
- Environment variable override functionality

## Code Reproduction
```python
API_PORT = int(os.environ.get('HEXSTRIKE_PORT', 8888))
```
