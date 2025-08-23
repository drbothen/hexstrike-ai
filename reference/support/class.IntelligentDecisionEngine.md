---
title: class.IntelligentDecisionEngine
kind: class
module: __main__
line_range: [572, 1542]
discovered_in_chunk: 1
---

# IntelligentDecisionEngine Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** AI-powered tool selection and parameter optimization engine

## Complete Signature & Definition
```python
class IntelligentDecisionEngine:
    """AI-powered tool selection and parameter optimization engine"""
    
    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
        self._use_advanced_optimizer = True  # Enable advanced optimization by default
```

## Purpose & Behavior
Core intelligence engine for automated security testing with:
- **Target Analysis:** Comprehensive target profiling and classification
- **Tool Selection:** AI-driven selection of optimal security tools
- **Parameter Optimization:** Intelligent parameter tuning for each tool
- **Attack Planning:** Creation of coordinated attack chains
- **Technology Detection:** Fingerprinting of target technologies
- **Risk Assessment:** Attack surface and risk level calculation

## Dependencies & Usage
- **Depends on:**
  - TargetProfile, AttackChain, AttackStep classes
  - TargetType, TechnologyStack enums
  - typing.Dict, List, Optional, Any
  - socket, urllib.parse for network operations
- **Used by:**
  - Main application for security testing workflows
  - API endpoints for tool selection and optimization

## Implementation Details

### Core Attributes
- **tool_effectiveness:** Mapping of tools to effectiveness scores by target type
- **technology_signatures:** Patterns for technology detection
- **attack_patterns:** Predefined attack sequences for different scenarios
- **_use_advanced_optimizer:** Flag for advanced parameter optimization

### Key Methods

#### Target Analysis
1. **analyze_target(target: str) -> TargetProfile:** Complete target analysis
2. **_determine_target_type(target: str) -> TargetType:** Classify target type
3. **_resolve_domain(target: str) -> List[str]:** DNS resolution
4. **_detect_technologies(target: str) -> List[TechnologyStack]:** Technology fingerprinting
5. **_detect_cms(target: str) -> Optional[str]:** CMS detection
6. **_calculate_attack_surface(profile: TargetProfile) -> float:** Attack surface scoring
7. **_determine_risk_level(profile: TargetProfile) -> str:** Risk classification
8. **_calculate_confidence(profile: TargetProfile) -> float:** Analysis confidence

#### Tool Selection & Optimization
9. **select_optimal_tools(profile: TargetProfile, objective: str) -> List[str]:** Tool selection
10. **optimize_parameters(tool: str, profile: TargetProfile, context: Dict) -> Dict:** Parameter optimization
11. **enable_advanced_optimization():** Enable advanced parameter optimization
12. **disable_advanced_optimization():** Disable advanced parameter optimization

#### Tool-Specific Optimizers (25 methods)
- **_optimize_nmap_params:** Network mapping optimization
- **_optimize_gobuster_params:** Directory brute-forcing optimization
- **_optimize_nuclei_params:** Vulnerability scanning optimization
- **_optimize_sqlmap_params:** SQL injection testing optimization
- **_optimize_ffuf_params:** Web fuzzing optimization
- **_optimize_hydra_params:** Password attack optimization
- **_optimize_rustscan_params:** Fast port scanning optimization
- **_optimize_masscan_params:** Mass port scanning optimization
- **_optimize_nmap_advanced_params:** Advanced network scanning
- **_optimize_enum4linux_ng_params:** SMB enumeration optimization
- **_optimize_autorecon_params:** Automated reconnaissance optimization
- **_optimize_ghidra_params:** Binary analysis optimization
- **_optimize_pwntools_params:** Exploit development optimization
- **_optimize_ropper_params:** ROP gadget finding optimization
- **_optimize_angr_params:** Symbolic execution optimization
- **_optimize_prowler_params:** AWS security assessment optimization
- **_optimize_scout_suite_params:** Multi-cloud security optimization
- **_optimize_kube_hunter_params:** Kubernetes security optimization
- **_optimize_trivy_params:** Container vulnerability scanning optimization
- **_optimize_checkov_params:** Infrastructure as Code security optimization

#### Attack Planning
13. **create_attack_chain(profile: TargetProfile, objective: str) -> AttackChain:** Attack chain creation

### Tool Effectiveness Mapping
Comprehensive effectiveness ratings for 100+ security tools across target types:
- **Web Applications:** High effectiveness for web-focused tools (nuclei: 0.95, wpscan: 0.95)
- **Network Hosts:** Optimized for network scanning and enumeration
- **API Endpoints:** Specialized for API testing and fuzzing
- **Binary Files:** Focused on reverse engineering and exploitation tools
- **Cloud Services:** Cloud-specific security assessment tools

### Attack Patterns
Predefined attack sequences for various scenarios:
- **Web Reconnaissance:** Discovery and enumeration phases
- **Vulnerability Assessment:** Comprehensive vulnerability scanning
- **API Testing:** API-specific testing methodologies
- **Network Discovery:** Network mapping and service enumeration
- **Binary Exploitation:** Reverse engineering and exploit development
- **Bug Bounty Workflows:** Specialized bug bounty hunting patterns
- **Cloud Security Assessment:** Multi-cloud security testing
- **Container Security:** Container and Kubernetes security testing

### Parameter Optimization Intelligence
- **Context-Aware:** Adjusts parameters based on stealth, aggressive, or comprehensive modes
- **Technology-Specific:** Customizes parameters based on detected technologies
- **Performance Tuning:** Optimizes timing, threads, and resource usage
- **Evasion Techniques:** Implements stealth and evasion strategies

## Testing & Validation
- Tool effectiveness validation across target types
- Parameter optimization accuracy testing
- Attack chain success probability validation
- Technology detection accuracy metrics

## Code Reproduction
Complete class implementation with all 30+ methods for intelligent security testing automation. Essential for AI-driven tool selection, parameter optimization, and attack planning in the HexStrike framework.
