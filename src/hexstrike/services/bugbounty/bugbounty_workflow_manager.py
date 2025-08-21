"""
Bug bounty workflow management and hunting automation.

This module changes when bug bounty strategies or vulnerability priorities change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging
from .bugbounty_target import BugBountyTarget
from .bugbounty_strategies import BugBountyStrategies, VulnerabilityType

logger = logging.getLogger(__name__)

class BugBountyWorkflowManager:
    """Specialized workflow manager for bug bounty hunting"""
    
    def __init__(self):
        try:
            self.strategies = BugBountyStrategies()
            self.high_impact_vulns = self.strategies.vulnerability_priorities
            self.reconnaissance_tools = self.strategies.recon_tools
            self.hunting_strategies = self.strategies.hunting_strategies
        except ImportError:
            self.high_impact_vulns = {
                "rce": {"priority": 10, "bounty_multiplier": 3.0, "tools": ["nuclei", "commix"]},
                "sqli": {"priority": 9, "bounty_multiplier": 2.5, "tools": ["sqlmap", "nuclei"]},
                "xss": {"priority": 7, "bounty_multiplier": 1.5, "tools": ["dalfox", "nuclei"]},
                "idor": {"priority": 8, "bounty_multiplier": 2.0, "tools": ["nuclei", "manual"]},
                "ssrf": {"priority": 8, "bounty_multiplier": 2.0, "tools": ["nuclei", "manual"]}
            }
            self.reconnaissance_tools = ["amass", "subfinder", "httpx", "nuclei"]
            self.hunting_strategies = {}
    
    
    
    
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
        from .bugbounty_patterns import BugBountyPatterns
        
        suggestions = []
        thresholds = BugBountyPatterns.get_next_step_thresholds()
        suggestion_messages = BugBountyPatterns.get_next_step_suggestions()
        
        for key, threshold in thresholds.items():
            if current_findings.get(key, 0) > threshold:
                suggestions.append(suggestion_messages[key])
        
        return suggestions
    
    def estimate_bounty_potential(self, target: BugBountyTarget, workflow_results: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate bounty potential based on target and findings"""
        from .bugbounty_patterns import BugBountyPatterns
        
        program_multipliers = BugBountyPatterns.get_bounty_multipliers()
        surface_multipliers = BugBountyPatterns.get_attack_surface_multipliers()
        base_amounts = BugBountyPatterns.get_bounty_base_amounts()
        
        base_multiplier = program_multipliers.get(target.program_type, 1.0)
        
        # Apply attack surface multiplier
        attack_surface = workflow_results.get("subdomains_found", 0)
        if attack_surface > 100:
            base_multiplier *= surface_multipliers["large"]
        elif attack_surface > 50:
            base_multiplier *= surface_multipliers["medium"]
        
        vulnerability_count = workflow_results.get("vulnerabilities_found", 0)
        high_impact_vulns = workflow_results.get("high_impact_vulns", 0)
        
        estimated_bounty = {
            "low": int(base_amounts["low"] * base_multiplier),
            "medium": int(base_amounts["medium"] * base_multiplier),
            "high": int(base_amounts["high"] * base_multiplier * (1 + high_impact_vulns * 0.5)),
            "critical": int(base_amounts["critical"] * base_multiplier * (1 + high_impact_vulns))
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
    
    def _get_test_scenarios(self, target_type: str) -> List[Dict[str, Any]]:
        """Get test scenarios based on target type"""
        scenarios = {
            "web_application": [
                {"name": "authentication_bypass", "priority": "high", "tools": ["nuclei", "manual"]},
                {"name": "injection_testing", "priority": "high", "tools": ["sqlmap", "nuclei", "commix"]},
                {"name": "business_logic_flaws", "priority": "medium", "tools": ["manual"]},
                {"name": "session_management", "priority": "medium", "tools": ["manual", "nuclei"]},
                {"name": "file_upload_bypass", "priority": "high", "tools": ["manual"]},
                {"name": "access_control", "priority": "high", "tools": ["nuclei", "manual"]}
            ],
            "api": [
                {"name": "authentication_bypass", "priority": "high", "tools": ["nuclei", "manual"]},
                {"name": "authorization_flaws", "priority": "high", "tools": ["manual"]},
                {"name": "injection_attacks", "priority": "high", "tools": ["sqlmap", "nuclei"]},
                {"name": "rate_limiting", "priority": "medium", "tools": ["manual"]},
                {"name": "data_exposure", "priority": "high", "tools": ["manual", "nuclei"]}
            ],
            "mobile": [
                {"name": "insecure_storage", "priority": "medium", "tools": ["manual"]},
                {"name": "weak_cryptography", "priority": "high", "tools": ["manual"]},
                {"name": "insecure_communication", "priority": "high", "tools": ["manual"]},
                {"name": "authentication_bypass", "priority": "high", "tools": ["manual"]},
                {"name": "code_injection", "priority": "high", "tools": ["manual"]}
            ]
        }
        
        return scenarios.get(target_type, scenarios["web_application"])
