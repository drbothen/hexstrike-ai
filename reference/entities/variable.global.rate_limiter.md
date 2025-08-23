---
title: variable.global.rate_limiter
kind: variable
scope: module
module: __main__
line_range: [5556, 5556]
discovered_in_chunk: 5
---

# Global Variable: rate_limiter

## Entity Classification & Context
- **Kind:** Module-level global variable
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Type:** RateLimitDetector

## Complete Signature & Definition
```python
rate_limiter = RateLimitDetector()
```

## Purpose & Behavior
Global singleton instance of the RateLimitDetector for centralized rate limiting detection and automatic timing adjustment throughout the application.

## Dependencies & Usage
- **Depends on:** RateLimitDetector class
- **Used by:** Parameter optimization systems, stealth mode activation, timing profile adjustment
- **Initialization:** Creates instance with intelligent rate limiting detection capabilities

## Implementation Details
- **Singleton Pattern:** Single global instance for application-wide rate limiting detection
- **Detection Capabilities:** Multi-source rate limit detection with confidence scoring
- **Timing Profiles:** 4 timing profiles for different scenarios

## Testing & Validation
- Instance creation validation
- Rate limit detection accuracy testing
- Timing profile effectiveness verification

## Code Reproduction
```python
rate_limiter = RateLimitDetector()
```
