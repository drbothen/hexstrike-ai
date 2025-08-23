---
title: class.ParameterOptimizer
kind: class
module: __main__
line_range: [4635, 4871]
discovered_in_chunk: 4
---

# ParameterOptimizer Class

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced parameter optimization system with intelligent context-aware selection

## Complete Signature & Definition
```python
class ParameterOptimizer:
    """Advanced parameter optimization system with intelligent context-aware selection"""
    
    def __init__(self):
        self.tech_detector = TechnologyDetector()
        self.rate_limiter = RateLimitDetector()
        self.failure_recovery = FailureRecoverySystem()
        self.performance_monitor = PerformanceMonitor()
        
        # Tool-specific optimization profiles
        self.optimization_profiles = {
            # Comprehensive tool optimization profiles
        }
```

## Purpose & Behavior
Comprehensive parameter optimization system providing:
- **Multi-dimensional Optimization:** Technology, performance, and profile-based parameter tuning
- **Context-aware Intelligence:** Intelligent parameter selection based on detected technologies
- **Failure Recovery Integration:** Automatic parameter adjustment for tool failures
- **Performance-aware Optimization:** Resource-conscious parameter optimization

## Dependencies & Usage
- **Depends on:**
  - TechnologyDetector for technology detection
  - RateLimitDetector for rate limiting detection
  - FailureRecoverySystem for failure handling
  - PerformanceMonitor for resource monitoring
  - TargetProfile for target information
  - datetime for timestamp generation
  - typing.Dict, Any for type annotations
- **Used by:**
  - Tool execution systems
  - Parameter optimization workflows
  - Context-aware security testing

## Implementation Details

### Core Attributes
- **tech_detector:** TechnologyDetector instance for technology detection
- **rate_limiter:** RateLimitDetector instance for rate limiting detection
- **failure_recovery:** FailureRecoverySystem instance for failure handling
- **performance_monitor:** PerformanceMonitor instance for resource monitoring
- **optimization_profiles:** Tool-specific optimization profiles (3 tools)

### Key Methods

#### Advanced Optimization
1. **optimize_parameters_advanced(tool: str, target_profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:** Main advanced optimization entry point
2. **_get_base_parameters(tool: str, profile: TargetProfile) -> Dict[str, Any]:** Base parameter generation
3. **_apply_technology_optimizations(tool: str, params: Dict[str, Any], detected_tech: Dict[str, List[str]]) -> Dict[str, Any]:** Technology-specific optimizations
4. **_apply_profile_optimizations(tool: str, params: Dict[str, Any], profile: str) -> Dict[str, Any]:** Profile-based optimizations
5. **handle_tool_failure(tool: str, error_output: str, exit_code: int, current_params: Dict[str, Any]) -> Dict[str, Any]:** Tool failure handling

### Tool Optimization Profiles (3 Tools)

#### Nmap Optimization Profiles
- **Stealth Profile:**
  - scan_type: "-sS" (SYN scan)
  - timing: "-T2" (Polite timing)
  - additional_args: "--max-retries 1 --host-timeout 300s"

- **Normal Profile:**
  - scan_type: "-sS -sV" (SYN + Version detection)
  - timing: "-T4" (Aggressive timing)
  - additional_args: "--max-retries 2"

- **Aggressive Profile:**
  - scan_type: "-sS -sV -sC -O" (Full scan with scripts and OS detection)
  - timing: "-T5" (Insane timing)
  - additional_args: "--max-retries 3 --min-rate 1000"

#### Gobuster Optimization Profiles
- **Stealth Profile:**
  - threads: 5
  - delay: "1s"
  - timeout: "30s"

- **Normal Profile:**
  - threads: 20
  - delay: "0s"
  - timeout: "10s"

- **Aggressive Profile:**
  - threads: 50
  - delay: "0s"
  - timeout: "5s"

#### SQLMap Optimization Profiles
- **Stealth Profile:**
  - level: 1
  - risk: 1
  - threads: 1
  - delay: 1

- **Normal Profile:**
  - level: 2
  - risk: 2
  - threads: 5
  - delay: 0

- **Aggressive Profile:**
  - level: 3
  - risk: 3
  - threads: 10
  - delay: 0

### Advanced Parameter Optimization Workflow

#### Multi-stage Optimization Process
1. **Base Parameter Generation:** Tool-specific default parameters
2. **Technology Detection:** Comprehensive technology stack analysis
3. **Technology Optimization:** Technology-specific parameter adjustments
4. **Resource Optimization:** Performance-aware parameter tuning
5. **Profile Application:** Optimization profile-based final adjustments
6. **Metadata Generation:** Comprehensive optimization metadata

#### Optimization Pipeline
```python
base_params = self._get_base_parameters(tool, target_profile)
detected_tech = self.tech_detector.detect_technologies(...)
tech_optimized_params = self._apply_technology_optimizations(tool, base_params, detected_tech)
resource_optimized_params = self.performance_monitor.optimize_based_on_resources(tech_optimized_params, resource_usage)
profile_optimized_params = self._apply_profile_optimizations(tool, resource_optimized_params, profile)
```

### Base Parameter Generation

#### Tool-specific Base Parameters

##### Nmap Base Parameters
- **scan_type:** "-sS" (SYN scan)
- **ports:** "1-1000" (Common ports)
- **timing:** "-T4" (Aggressive timing)

##### Gobuster Base Parameters
- **mode:** "dir" (Directory enumeration)
- **threads:** 20 (Moderate concurrency)
- **wordlist:** "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

##### SQLMap Base Parameters
- **batch:** True (Non-interactive mode)
- **level:** 1 (Basic testing level)
- **risk:** 1 (Low risk level)

##### Nuclei Base Parameters
- **severity:** "critical,high,medium" (Important vulnerabilities)
- **threads:** 25 (Moderate concurrency)

### Technology-specific Optimizations

#### Web Server Optimizations

##### Apache Optimizations
- **Gobuster:** extensions: "php,html,txt,xml,conf"
- **Nuclei:** tags: "+apache"

##### Nginx Optimizations
- **Gobuster:** extensions: "php,html,txt,json,conf"
- **Nuclei:** tags: "+nginx"

#### CMS Optimizations

##### WordPress Optimizations
- **Gobuster:** 
  - extensions: "php,html,txt,xml"
  - additional_paths: "/wp-content/,/wp-admin/,/wp-includes/"
- **Nuclei:** tags: "+wordpress"
- **WPScan:** enumerate: "ap,at,cb,dbe"

#### Language-specific Optimizations

##### PHP Optimizations
- **Gobuster:** extensions: "php,php3,php4,php5,phtml,html"
- **SQLMap:** dbms: "mysql"

##### .NET Optimizations
- **Gobuster:** extensions: "aspx,asp,html,txt"
- **SQLMap:** dbms: "mssql"

#### Security Feature Adaptations

##### WAF Detection and Stealth Mode
- **Detection:** Cloudflare, Incapsula, Sucuri WAF detection
- **Stealth Activation:** _stealth_mode flag set to True
- **Parameter Adjustments:**
  - **Gobuster:** threads ≤ 5, delay: "2s"
  - **SQLMap:** delay: 2, randomize: True

### Profile-based Optimization

#### Profile Application Logic
- **Profile Settings:** Apply tool-specific profile configurations
- **Stealth Override:** Force stealth settings when _stealth_mode detected
- **Parameter Merging:** Intelligent parameter combination and override

#### Stealth Mode Enforcement
```python
if params.get("_stealth_mode", False) and profile != "stealth":
    # Force stealth settings even if different profile requested
    stealth_settings = self.optimization_profiles[tool].get("stealth", {})
    for key, value in stealth_settings.items():
        optimized_params[key] = value
```

### Tool Failure Handling

#### Failure Recovery Integration
- **Failure Analysis:** Comprehensive failure analysis using FailureRecoverySystem
- **Recovery Plan Generation:** Structured recovery plan with multiple strategies
- **Parameter Adjustment:** Automatic parameter tuning based on failure type

#### Recovery Plan Structure
```python
{
    "original_tool": str,                   # Failed tool name
    "failure_analysis": Dict[str, Any],     # Detailed failure analysis
    "recovery_actions": List[str],          # Applied recovery actions
    "alternative_tools": List[str],         # Alternative tool suggestions
    "adjusted_parameters": Dict[str, Any]   # Adjusted parameters
}
```

#### Failure-specific Adjustments

##### Timeout Failure Recovery
- **Timeout Doubling:** Increase timeout parameters by 2x
- **Thread Reduction:** Reduce thread count by 50% (minimum 1)
- **Recovery Action:** "Increased timeout and reduced threads"

##### Rate Limiting Recovery
- **Stealth Profile Application:** Apply stealth timing profile
- **Parameter Integration:** Merge stealth timing with current parameters
- **Recovery Action:** "Applied stealth timing profile"

### Optimization Metadata

#### Comprehensive Metadata Generation
```python
{
    "detected_technologies": Dict[str, List[str]],  # Technology detection results
    "resource_usage": Dict[str, float],             # System resource usage
    "optimization_profile": str,                    # Applied optimization profile
    "optimizations_applied": List[str],             # Resource optimizations applied
    "timestamp": str                                # ISO format timestamp
}
```

#### Metadata Integration
- **Technology Context:** Complete technology detection results
- **Resource Context:** System resource usage at optimization time
- **Optimization History:** Detailed log of applied optimizations
- **Temporal Context:** Precise timestamp for optimization tracking

### Use Cases and Applications

#### Context-aware Security Testing
- **Technology-specific Testing:** Tailored testing based on detected technologies
- **Resource-aware Execution:** Optimal performance within system constraints
- **Failure-resilient Testing:** Automatic recovery and parameter adjustment

#### Intelligent Tool Selection
- **Profile-based Optimization:** Appropriate optimization level selection
- **Stealth Mode Activation:** Automatic stealth mode for WAF-protected targets
- **Performance Optimization:** Maximum efficiency with minimal resource impact

## Testing & Validation
- Multi-dimensional optimization accuracy testing
- Technology detection integration validation
- Failure recovery effectiveness assessment
- Performance optimization impact verification

## Code Reproduction
Complete class implementation with 5 methods for advanced parameter optimization, including multi-dimensional optimization, context-aware intelligence, failure recovery integration, and comprehensive metadata generation. Essential for intelligent security testing and automated parameter tuning.
