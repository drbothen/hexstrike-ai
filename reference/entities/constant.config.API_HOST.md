---
title: constant.config.API_HOST
kind: constant
scope: module
module: __main__
line_range: [99, 99]
discovered_in_chunk: 1
---

# Configuration Constant: API_HOST

## Entity Classification & Context
- **Kind:** Module-level constant
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** str

## Complete Signature & Definition
```python
API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')
```

## Purpose & Behavior
Defines the host address for the HexStrike AI server API. Reads from the HEXSTRIKE_HOST environment variable with a default fallback of localhost (127.0.0.1).

## Dependencies & Usage
- **Depends on:** os.environ.get()
- **Used by:** Flask application server configuration, API binding

## Implementation Details
- Environment variable: HEXSTRIKE_HOST
- Default value: '127.0.0.1' (localhost)
- Configuration precedence: Environment variable > default value
- Allows binding to different interfaces (0.0.0.0 for all interfaces)

## Testing & Validation
- Should validate host address format
- Environment variable override functionality

## Code Reproduction
```python
API_HOST = os.environ.get('HEXSTRIKE_HOST', '127.0.0.1')
```
