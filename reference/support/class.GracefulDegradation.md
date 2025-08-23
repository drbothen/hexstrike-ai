---
title: class.GracefulDegradation
kind: class
module: __main__
line_range: [2201, 2427]
discovered_in_chunk: 2
---

# GracefulDegradation Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Ensure system continues operating even with partial tool failures

## Complete Signature & Definition
```python
class GracefulDegradation:
    """Ensure system continues operating even with partial tool failures"""
    
    def __init__(self):
        self.fallback_chains = self._initialize_fallback_chains()
        self.critical_operations = self._initialize_critical_operations()
```

## Purpose & Behavior
Comprehensive fallback system for maintaining operational capability during tool failures:
- **Fallback Chains:** Multi-tier tool alternatives for critical operations
- **Critical Operations:** Identification of operations that must not fail completely
- **Partial Results:** Enhancement of incomplete results with alternative methods
- **Manual Recommendations:** Guidance for human intervention when automation fails
- **Basic Checks:** Minimal functionality fallbacks for essential operations

## Dependencies & Usage
- **Depends on:**
  - socket for basic network connectivity checks
  - requests for HTTP operations
  - datetime for timestamp management
  - logging for status reporting
- **Used by:**
  - Tool execution workflows
  - Attack chain execution
  - Error recovery systems

## Implementation Details

### Core Attributes
- **fallback_chains:** Multi-tier tool alternatives by operation type
- **critical_operations:** Set of operations requiring guaranteed fallback

### Key Methods

#### Initialization
1. **_initialize_fallback_chains():** Multi-tier fallback tool chains
2. **_initialize_critical_operations():** Critical operation identification

#### Fallback Management
3. **create_fallback_chain(operation: str, failed_tools: List[str]) -> List[str]:** Create viable fallback chain
4. **handle_partial_failure(operation: str, partial_results: Dict, failed_components: List[str]) -> Dict:** Enhance partial results
5. **is_critical_operation(operation: str) -> bool:** Check if operation is critical

#### Basic Fallback Methods
6. **_basic_port_check(target: str) -> List[int]:** Socket-based port connectivity
7. **_basic_directory_check(target: str) -> List[str]:** HTTP-based directory discovery
8. **_basic_security_check(target: str) -> List[Dict]:** Basic security header analysis
9. **_get_manual_recommendations(operation: str, failed_components: List[str]) -> List[str]:** Manual intervention guidance

### Fallback Chain Architecture

#### Network Discovery
- **Tier 1:** nmap, rustscan, masscan
- **Tier 2:** rustscan, nmap
- **Tier 3:** ping, telnet (basic fallback)

#### Web Discovery
- **Tier 1:** gobuster, feroxbuster, dirsearch
- **Tier 2:** feroxbuster, ffuf
- **Tier 3:** curl, wget (basic fallback)

#### Vulnerability Scanning
- **Tier 1:** nuclei, jaeles, nikto
- **Tier 2:** nikto, w3af
- **Tier 3:** curl (basic manual testing)

#### Subdomain Enumeration
- **Tier 1:** subfinder, amass, assetfinder
- **Tier 2:** amass, findomain
- **Tier 3:** dig, nslookup (basic DNS tools)

#### Parameter Discovery
- **Tier 1:** arjun, paramspider, x8
- **Tier 2:** ffuf, wfuzz
- **Tier 3:** manual_testing

### Basic Fallback Implementations

#### Port Checking
- Socket-based connectivity testing for common ports
- 2-second timeout per port
- Common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995

#### Directory Discovery
- HTTP HEAD requests for common directories
- Status code validation (200, 301, 302, 403)
- Common paths: /admin, /login, /api, /wp-admin, /phpmyadmin, /robots.txt

#### Security Analysis
- HTTP header analysis for security misconfigurations
- Missing security headers detection
- Basic vulnerability classification

### Manual Recommendations
Structured guidance for human intervention:
- **Network Discovery:** Manual port testing, service banner checking
- **Web Discovery:** Manual browsing, robots.txt analysis
- **Vulnerability Scanning:** Manual testing, security header analysis
- **Subdomain Enumeration:** Online tools, certificate transparency

## Testing & Validation
- Fallback chain viability testing
- Basic check accuracy validation
- Manual recommendation effectiveness
- Critical operation coverage verification

## Code Reproduction
Complete class implementation with 9 methods for graceful degradation, fallback chain management, and basic operational fallbacks. Essential for maintaining system functionality during tool failures and providing structured recovery paths.
