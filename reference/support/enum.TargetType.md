---
title: enum.TargetType
kind: enum
module: __main__
line_range: [445, 453]
discovered_in_chunk: 1
---

# TargetType Enumeration

## Entity Classification & Context
- **Kind:** Enumeration class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Base Class:** Enum

## Complete Signature & Definition
```python
class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"
```

## Purpose & Behavior
Defines standardized target types for the intelligent decision engine to:
- Categorize different types of security testing targets
- Enable tool selection based on target characteristics
- Provide context for parameter optimization
- Support attack surface analysis

## Dependencies & Usage
- **Depends on:** enum.Enum (standard library)
- **Used by:** 
  - IntelligentDecisionEngine for tool selection
  - TargetProfile for target classification
  - Parameter optimization methods

## Implementation Details
- **Values:** String-based enumeration values for JSON serialization
- **Categories:** Covers web apps, network hosts, APIs, cloud services, mobile apps, binaries
- **Default:** UNKNOWN for unclassified targets
- **Extensible:** Can be extended for new target types

## Testing & Validation
- Enum value validation
- JSON serialization compatibility
- Integration with decision engine logic

## Code Reproduction
```python
class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"
```
