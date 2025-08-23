---
title: enum.TechnologyStack
kind: enum
module: __main__
line_range: [455, 471]
discovered_in_chunk: 1
---

# TechnologyStack Enumeration

## Entity Classification & Context
- **Kind:** Enumeration class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Base Class:** Enum

## Complete Signature & Definition
```python
class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"
```

## Purpose & Behavior
Defines technology stacks for intelligent tool selection and parameter optimization:
- **Web Servers:** Apache, Nginx, IIS
- **Runtime Environments:** Node.js, PHP, Python, Java, .NET
- **Content Management:** WordPress, Drupal, Joomla
- **Frontend Frameworks:** React, Angular, Vue
- **Fallback:** UNKNOWN for undetected technologies

## Dependencies & Usage
- **Depends on:** enum.Enum (standard library)
- **Used by:**
  - IntelligentDecisionEngine for technology-specific tool selection
  - TargetProfile for technology detection storage
  - Parameter optimization methods for technology-aware configuration

## Implementation Details
- **String Values:** Enables JSON serialization and external API compatibility
- **Technology Categories:** Covers major web technologies and frameworks
- **Tool Mapping:** Each technology maps to specific security tools and techniques
- **Detection Logic:** Used in technology fingerprinting and CMS detection

## Testing & Validation
- Technology detection accuracy
- Tool mapping validation
- Parameter optimization effectiveness per technology

## Code Reproduction
```python
class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"
```
