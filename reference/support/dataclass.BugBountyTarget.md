---
title: dataclass.BugBountyTarget
kind: dataclass
module: __main__
line_range: [2437, 2445]
discovered_in_chunk: 2
---

# BugBountyTarget Dataclass

## Entity Classification & Context
- **Kind:** Dataclass
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Decorators:** @dataclass

## Complete Signature & Definition
```python
@dataclass
class BugBountyTarget:
    """Bug bounty target information"""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"  # web, api, mobile, iot
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])
    bounty_range: str = "unknown"
```

## Purpose & Behavior
Specialized data structure for bug bounty hunting targets with:
- **Target Definition:** Primary domain and scope boundaries
- **Scope Management:** In-scope and out-of-scope asset lists
- **Program Classification:** Target type (web, api, mobile, iot)
- **Vulnerability Priorities:** High-value vulnerability types for targeting
- **Bounty Information:** Expected reward range for planning

## Dependencies & Usage
- **Depends on:**
  - dataclasses.dataclass, field
  - typing.List
- **Used by:**
  - BugBountyWorkflowManager for target management
  - Bug bounty hunting workflows
  - Target prioritization systems

## Implementation Details

### Key Fields
- **domain:** Primary target domain
- **scope:** List of in-scope assets and subdomains
- **out_of_scope:** List of explicitly excluded assets
- **program_type:** Target classification (web, api, mobile, iot)
- **priority_vulns:** High-priority vulnerability types to focus on
- **bounty_range:** Expected bounty payout range

### Default Configurations
- **Program Type:** Defaults to "web" for web applications
- **Priority Vulnerabilities:** ["rce", "sqli", "xss", "idor", "ssrf"] - high-impact vulnerabilities
- **Bounty Range:** "unknown" when not specified

### Vulnerability Priorities
Focus on high-impact vulnerabilities:
- **RCE:** Remote Code Execution
- **SQLi:** SQL Injection
- **XSS:** Cross-Site Scripting
- **IDOR:** Insecure Direct Object References
- **SSRF:** Server-Side Request Forgery

## Testing & Validation
- Field validation and type checking
- Scope boundary validation
- Program type classification accuracy
- Priority vulnerability mapping

## Code Reproduction
```python
@dataclass
class BugBountyTarget:
    """Bug bounty target information"""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"  # web, api, mobile, iot
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])
    bounty_range: str = "unknown"
```
