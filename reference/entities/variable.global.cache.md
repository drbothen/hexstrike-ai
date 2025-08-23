---
title: variable.global.cache
kind: variable
scope: module
module: __main__
line_range: [6075, 6075]
discovered_in_chunk: 6
---

# Global Variable: cache

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** HexStrikeCache

## Complete Signature & Definition
```python
cache = HexStrikeCache()
```

## Purpose & Behavior
Global singleton instance of the HexStrikeCache for centralized command result caching throughout the application.

## Dependencies & Usage
- **Depends on:** HexStrikeCache class, CACHE_SIZE and CACHE_TTL constants
- **Used by:** Command execution systems, performance optimization frameworks, result caching systems
- **Initialization:** Creates instance with default cache size (1000) and TTL (3600 seconds)

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide command result caching
- **Cache Management:** Advanced caching with TTL, LRU eviction, and performance analytics
- **Key Generation:** MD5-based key generation from command and parameters

## Testing & Validation
- Instance creation validation
- Cache functionality testing
- Performance analytics verification

## Code Reproduction
```python
cache = HexStrikeCache()
```
