"""
Bug bounty workflow management and hunting automation.

This module changes when bug bounty strategies or vulnerability priorities change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    RCE = "rce"
    SQLI = "sqli"
    XSS = "xss"
    IDOR = "idor"
    SSRF = "ssrf"
    LFI = "lfi"
    XXE = "xxe"
    CSRF = "csrf"

@dataclass
class BugBountyTarget:
    """Bug bounty target information"""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])
    bounty_range: str = "unknown"

class BugBountyWorkflowManager:
    """Specialized workflow manager for bug bounty hunting"""
    
    def __init__(self):
        self.high_impact_vulns = self._initialize_vulnerability_priorities()
        self.reconnaissance_tools = self._initialize_reconnaissance_tools()
        self.hunting_strategies = self._initialize_hunting_strategies()
    
    def _initialize_vulnerability_priorities(self) -> Dict[str, Dict[str, Any]]:
        """Initialize vulnerability priorities and associated tools"""
        return {
            "rce": {
                "priority": 10,
                "tools": ["nuclei", "jaeles", "sqlmap"],
                "payloads": "command_injection",
                "bounty_multiplier": 3.0
            },
            "sqli": {
                "priority": 9,
                "tools": ["sqlmap", "nuclei"],
                "payloads": "sql_injection",
                "bounty_multiplier": 2.5
            },
            "ssrf": {
                "priority": 8,
                "tools": ["nuclei", "ffuf"],
                "payloads": "ssrf",
                "bounty_multiplier": 2.0
            },
            "idor": {
                "priority": 8,
                "tools": ["arjun", "paramspider", "ffuf"],
                "payloads": "idor",
                "bounty_multiplier": 1.8
            },
            "xss": {
                "priority": 7,
                "tools": ["dalfox", "nuclei"],
                "payloads": "xss",
                "bounty_multiplier": 1.5
            },
            "lfi": {
                "priority": 7,
                "tools": ["ffuf", "nuclei"],
                "payloads": "lfi",
                "bounty_multiplier": 1.5
            },
            "xxe": {
                "priority": 6,
                "tools": ["nuclei"],
                "payloads": "xxe",
                "bounty_multiplier": 1.3
            },
            "csrf": {
                "priority": 5,
                "tools": ["nuclei"],
                "payloads": "csrf",
                "bounty_multiplier": 1.0
            }
        }
    
    def _initialize_reconnaissance_tools(self) -> List[Dict[str, Any]]:
        """Initialize reconnaissance tool chain"""
        return [
            {"tool": "amass", "phase": "subdomain_enum", "priority": 1, "estimated_time": 600},
            {"tool": "subfinder", "phase": "subdomain_enum", "priority": 2, "estimated_time": 300},
            {"tool": "httpx", "phase": "http_probe", "priority": 3, "estimated_time": 180},
            {"tool": "katana", "phase": "crawling", "priority": 4, "estimated_time": 900},
            {"tool": "gau", "phase": "url_discovery", "priority": 5, "estimated_time": 400},
            {"tool": "waybackurls", "phase": "url_discovery", "priority": 6, "estimated_time": 300},
            {"tool": "paramspider", "phase": "parameter_discovery", "priority": 7, "estimated_time": 500},
            {"tool": "arjun", "phase": "parameter_discovery", "priority": 8, "estimated_time": 600}
        ]
    
    def _initialize_hunting_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Initialize bug bounty hunting strategies"""
        return {
            "comprehensive_recon": {
                "description": "Comprehensive reconnaissance workflow",
                "phases": ["subdomain_enum", "http_probe", "crawling", "url_discovery", "parameter_discovery"],
                "estimated_time": 3600,
                "success_rate": 0.8
            },
            "vulnerability_focused": {
                "description": "Focus on high-impact vulnerability discovery",
                "phases": ["quick_recon", "vulnerability_scanning", "exploitation"],
                "estimated_time": 2400,
                "success_rate": 0.6
            },
            "business_logic": {
                "description": "Business logic vulnerability testing",
                "phases": ["application_mapping", "workflow_analysis", "logic_testing"],
                "estimated_time": 4800,
                "success_rate": 0.4
            },
            "osint_focused": {
                "description": "OSINT-driven vulnerability discovery",
                "phases": ["osint_gathering", "credential_hunting", "exposed_assets"],
                "estimated_time": 1800,
                "success_rate": 0.7
            }
        }
    
    def create_reconnaissance_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create comprehensive reconnaissance workflow"""
        workflow = {
            "target": target.domain,
            "phases": [],
            "estimated_time": 0,
            "tools_count": 0
        }
        
        subdomain_phase = {
            "name": "subdomain_discovery",
            "description": "Comprehensive subdomain enumeration",
            "tools": [
                {"tool": "amass", "params": {"domain": target.domain, "mode": "enum"}},
                {"tool": "subfinder", "params": {"domain": target.domain, "silent": True}},
                {"tool": "assetfinder", "params": {"domain": target.domain}}
            ],
            "expected_outputs": ["subdomains.txt"],
            "estimated_time": 600
        }
        workflow["phases"].append(subdomain_phase)
        
        http_phase = {
            "name": "http_service_discovery",
            "description": "Identify live HTTP services",
            "tools": [
                {"tool": "httpx", "params": {"probe": True, "tech_detect": True, "status_code": True}},
                {"tool": "nuclei", "params": {"tags": "tech", "severity": "info"}}
            ],
            "expected_outputs": ["live_hosts.txt", "technologies.json"],
            "estimated_time": 180
        }
        workflow["phases"].append(http_phase)
        
        content_phase = {
            "name": "content_discovery",
            "description": "Discover hidden content and endpoints",
            "tools": [
                {"tool": "katana", "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "params": {"include_subs": True}},
                {"tool": "waybackurls", "params": {}},
                {"tool": "dirsearch", "params": {"extensions": "php,html,js,txt,json,xml"}}
            ],
            "expected_outputs": ["endpoints.txt", "js_files.txt"],
            "estimated_time": 900
        }
        workflow["phases"].append(content_phase)
        
        param_phase = {
            "name": "parameter_discovery",
            "description": "Discover hidden parameters and endpoints",
            "tools": [
                {"tool": "paramspider", "params": {"domain": target.domain}},
                {"tool": "arjun", "params": {"wordlist": "common", "threads": 25}}
            ],
            "expected_outputs": ["parameters.txt"],
            "estimated_time": 600
        }
        workflow["phases"].append(param_phase)
        
        workflow["estimated_time"] = sum(phase["estimated_time"] for phase in workflow["phases"])
        workflow["tools_count"] = sum(len(phase["tools"]) for phase in workflow["phases"])
        
        return workflow
    
    def create_vulnerability_hunting_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create vulnerability hunting workflow prioritized by impact"""
        workflow = {
            "target": target.domain,
            "vulnerability_focus": target.priority_vulns,
            "phases": [],
            "estimated_time": 0
        }
        
        quick_recon = {
            "name": "quick_reconnaissance",
            "description": "Fast reconnaissance for immediate testing",
            "tools": [
                {"tool": "httpx", "params": {"probe": True, "tech_detect": True}},
                {"tool": "katana", "params": {"depth": 2, "js_crawl": False}}
            ],
            "estimated_time": 300
        }
        workflow["phases"].append(quick_recon)
        
        vuln_scanning = {
            "name": "vulnerability_scanning",
            "description": "Scan for high-impact vulnerabilities",
            "tools": [],
            "estimated_time": 0
        }
        
        for vuln_type in target.priority_vulns:
            if vuln_type in self.high_impact_vulns:
                vuln_info = self.high_impact_vulns[vuln_type]
                for tool in vuln_info["tools"]:
                    vuln_scanning["tools"].append({
                        "tool": tool,
                        "params": {"target_vuln": vuln_type, "severity": "high,critical"}
                    })
                vuln_scanning["estimated_time"] += 400
        
        workflow["phases"].append(vuln_scanning)
        
        manual_testing = {
            "name": "manual_testing",
            "description": "Manual testing of discovered endpoints",
            "tools": [{"tool": "manual", "params": {"focus": "business_logic"}}],
            "estimated_time": 1800
        }
        workflow["phases"].append(manual_testing)
        
        workflow["estimated_time"] = sum(phase["estimated_time"] for phase in workflow["phases"])
        
        return workflow
    
    def create_business_logic_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create business logic testing workflow"""
        workflow = {
            "target": target.domain,
            "focus": "business_logic_vulnerabilities",
            "phases": [
                {
                    "name": "application_mapping",
                    "description": "Map application functionality and workflows",
                    "tools": [
                        {"tool": "katana", "params": {"depth": 5, "js_crawl": True, "form_extraction": True}},
                        {"tool": "manual", "params": {"focus": "workflow_mapping"}}
                    ],
                    "estimated_time": 1200
                },
                {
                    "name": "authentication_testing",
                    "description": "Test authentication and authorization mechanisms",
                    "tools": [
                        {"tool": "manual", "params": {"focus": "auth_bypass"}},
                        {"tool": "nuclei", "params": {"tags": "auth"}}
                    ],
                    "estimated_time": 900
                },
                {
                    "name": "business_logic_testing",
                    "description": "Test for business logic flaws",
                    "tools": [
                        {"tool": "manual", "params": {"focus": "logic_flaws"}},
                        {"tool": "custom_scripts", "params": {"type": "business_logic"}}
                    ],
                    "estimated_time": 2400
                }
            ],
            "estimated_time": 4500
        }
        
        return workflow
    
    def create_osint_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create OSINT gathering workflow"""
        workflow = {
            "target": target.domain,
            "focus": "osint_intelligence",
            "phases": [
                {
                    "name": "domain_intelligence",
                    "description": "Gather domain and infrastructure intelligence",
                    "tools": [
                        {"tool": "amass", "params": {"mode": "intel", "domain": target.domain}},
                        {"tool": "shodan", "params": {"query": f"hostname:{target.domain}"}},
                        {"tool": "censys", "params": {"query": target.domain}}
                    ],
                    "estimated_time": 600
                },
                {
                    "name": "credential_hunting",
                    "description": "Search for exposed credentials and secrets",
                    "tools": [
                        {"tool": "github_dorking", "params": {"domain": target.domain}},
                        {"tool": "truffleHog", "params": {"target": target.domain}},
                        {"tool": "gitleaks", "params": {"search": target.domain}}
                    ],
                    "estimated_time": 900
                },
                {
                    "name": "social_engineering_prep",
                    "description": "Gather information for social engineering",
                    "tools": [
                        {"tool": "sherlock", "params": {"username_search": True}},
                        {"tool": "linkedin_osint", "params": {"company": target.domain}},
                        {"tool": "email_enumeration", "params": {"domain": target.domain}}
                    ],
                    "estimated_time": 1200
                }
            ],
            "estimated_time": 2700
        }
        
        return workflow
    
    def prioritize_vulnerabilities(self, discovered_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize discovered vulnerabilities by impact and bounty potential"""
        prioritized = []
        
        for vuln in discovered_vulns:
            vuln_type = vuln.get("type", "unknown").lower()
            vuln_info = self.high_impact_vulns.get(vuln_type, {})
            
            priority_score = vuln_info.get("priority", 1)
            bounty_multiplier = vuln_info.get("bounty_multiplier", 1.0)
            
            vuln_with_priority = vuln.copy()
            vuln_with_priority["priority_score"] = priority_score
            vuln_with_priority["bounty_potential"] = bounty_multiplier
            vuln_with_priority["recommended_tools"] = vuln_info.get("tools", [])
            
            prioritized.append(vuln_with_priority)
        
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        return prioritized
    
    def suggest_next_steps(self, current_findings: Dict[str, Any]) -> List[str]:
        """Suggest next steps based on current findings"""
        suggestions = []
        
        if current_findings.get("subdomains_found", 0) > 50:
            suggestions.append("Large attack surface detected - consider automated scanning")
        
        if current_findings.get("js_files_found", 0) > 10:
            suggestions.append("Many JS files found - analyze for API endpoints and secrets")
        
        if current_findings.get("parameters_found", 0) > 20:
            suggestions.append("Many parameters discovered - focus on injection testing")
        
        if current_findings.get("admin_panels_found", 0) > 0:
            suggestions.append("Admin panels discovered - test for authentication bypass")
        
        if current_findings.get("api_endpoints_found", 0) > 5:
            suggestions.append("API endpoints found - test for IDOR and injection vulnerabilities")
        
        return suggestions
    
    def estimate_bounty_potential(self, target: BugBountyTarget, workflow_results: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate bounty potential based on target and findings"""
        base_multiplier = 1.0
        
        if target.program_type == "web":
            base_multiplier = 1.0
        elif target.program_type == "api":
            base_multiplier = 1.2
        elif target.program_type == "mobile":
            base_multiplier = 1.1
        
        attack_surface = workflow_results.get("subdomains_found", 0)
        if attack_surface > 100:
            base_multiplier *= 1.3
        elif attack_surface > 50:
            base_multiplier *= 1.1
        
        vulnerability_count = workflow_results.get("vulnerabilities_found", 0)
        high_impact_vulns = workflow_results.get("high_impact_vulns", 0)
        
        estimated_bounty = {
            "low": int(100 * base_multiplier),
            "medium": int(500 * base_multiplier),
            "high": int(2000 * base_multiplier * (1 + high_impact_vulns * 0.5)),
            "critical": int(10000 * base_multiplier * (1 + high_impact_vulns))
        }
        
        return {
            "base_multiplier": base_multiplier,
            "estimated_ranges": estimated_bounty,
            "factors": {
                "program_type": target.program_type,
                "attack_surface": attack_surface,
                "vulnerability_count": vulnerability_count,
                "high_impact_count": high_impact_vulns
            }
        }
