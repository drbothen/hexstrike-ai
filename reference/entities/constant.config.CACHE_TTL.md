---
title: constant.config.CACHE_TTL
kind: constant
scope: module
module: __main__
line_range: [6007, 6007]
discovered_in_chunk: 5
---

# Configuration Constant: CACHE_TTL

## Entity Classification & Context
- **Kind:** Module-level constant
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Default cache time-to-live for caching systems

## Complete Signature & Definition
```python
CACHE_TTL = 3600  # 1 hour
```

## Purpose & Behavior
Default time-to-live value in seconds for cache entries, set to 1 hour (3600 seconds) to balance data freshness with cache efficiency.

## Dependencies & Usage
- **Used by:** HexStrikeCache, caching systems, TTL management
- **Value:** 3600 seconds (1 hour)
- **Purpose:** Control cache entry expiration and data freshness

## Implementation Details
- **Type:** Integer (seconds)
- **Value:** 3600 seconds = 1 hour
- **Scope:** Global default for cache TTL

## Testing & Validation
- TTL expiration behavior testing
- Cache freshness validation
- Performance impact assessment

## Code Reproduction
```python
CACHE_TTL = 3600  # 1 hour
```
