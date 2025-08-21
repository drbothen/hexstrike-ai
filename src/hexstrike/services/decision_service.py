"""
AI-powered tool selection and optimization service.

This module changes when tool selection algorithms or optimization strategies change.
"""

from typing import Dict, Any, List, Optional, Set
import logging
from ..domain.target_analysis import TargetProfile, TargetType, TechnologyStack
from ..platform.constants import TOOL_CATEGORIES, DEFAULT_TIMEOUTS

logger = logging.getLogger(__name__)

class DecisionService:
    """Main decision orchestrator for tool selection and optimization"""
    
    def __init__(self):
        self.tool_effectiveness = self._initialize_tool_effectiveness()
        self.technology_signatures = self._initialize_technology_signatures()
        self.attack_patterns = self._initialize_attack_patterns()
        self._use_advanced_optimizer = True
    
    def _initialize_tool_effectiveness(self) -> Dict[str, Dict[str, float]]:
        """Initialize tool effectiveness scores for different target types"""
        return {
            "nmap": {
                "network_host": 0.95,
                "web_application": 0.85,
                "api_endpoint": 0.80,
                "cloud_service": 0.75,
                "mobile_app": 0.30,
                "binary_file": 0.10
            },
            "gobuster": {
                "web_application": 0.90,
                "api_endpoint": 0.85,
                "network_host": 0.20,
                "cloud_service": 0.70,
                "mobile_app": 0.15,
                "binary_file": 0.05
            },
            "nuclei": {
                "web_application": 0.95,
                "api_endpoint": 0.90,
                "network_host": 0.60,
                "cloud_service": 0.85,
                "mobile_app": 0.25,
                "binary_file": 0.10
            },
            "sqlmap": {
                "web_application": 0.85,
                "api_endpoint": 0.80,
                "network_host": 0.30,
                "cloud_service": 0.70,
                "mobile_app": 0.40,
                "binary_file": 0.05
            },
            "hydra": {
                "network_host": 0.80,
                "web_application": 0.60,
                "api_endpoint": 0.55,
                "cloud_service": 0.65,
                "mobile_app": 0.30,
                "binary_file": 0.10
            },
            "rustscan": {
                "network_host": 0.90,
                "web_application": 0.75,
                "api_endpoint": 0.70,
                "cloud_service": 0.70,
                "mobile_app": 0.25,
                "binary_file": 0.10
            },
            "amass": {
                "web_application": 0.85,
                "api_endpoint": 0.75,
                "network_host": 0.40,
                "cloud_service": 0.80,
                "mobile_app": 0.20,
                "binary_file": 0.05
            },
            "subfinder": {
                "web_application": 0.80,
                "api_endpoint": 0.70,
                "network_host": 0.35,
                "cloud_service": 0.75,
                "mobile_app": 0.15,
                "binary_file": 0.05
            },
            "prowler": {
                "cloud_service": 0.95,
                "web_application": 0.30,
                "api_endpoint": 0.35,
                "network_host": 0.20,
                "mobile_app": 0.10,
                "binary_file": 0.05
            },
            "ghidra": {
                "binary_file": 0.95,
                "mobile_app": 0.80,
                "web_application": 0.15,
                "api_endpoint": 0.10,
                "network_host": 0.20,
                "cloud_service": 0.10
            }
        }
    
    def _initialize_technology_signatures(self) -> Dict[TechnologyStack, List[str]]:
        """Initialize technology-specific tool recommendations"""
        return {
            TechnologyStack.WORDPRESS: ["wpscan", "nuclei", "gobuster", "sqlmap"],
            TechnologyStack.DRUPAL: ["droopescan", "nuclei", "gobuster", "sqlmap"],
            TechnologyStack.JOOMLA: ["joomscan", "nuclei", "gobuster", "sqlmap"],
            TechnologyStack.PHP: ["nuclei", "gobuster", "sqlmap", "ffuf"],
            TechnologyStack.NODEJS: ["nuclei", "gobuster", "retire.js", "ffuf"],
            TechnologyStack.PYTHON: ["nuclei", "gobuster", "bandit", "ffuf"],
            TechnologyStack.JAVA: ["nuclei", "gobuster", "dependency-check", "ffuf"],
            TechnologyStack.APACHE: ["nuclei", "nikto", "gobuster", "ffuf"],
            TechnologyStack.NGINX: ["nuclei", "nikto", "gobuster", "ffuf"],
            TechnologyStack.IIS: ["nuclei", "nikto", "gobuster", "ffuf"]
        }
    
    def _initialize_attack_patterns(self) -> Dict[str, List[str]]:
        """Initialize attack pattern to tool mappings"""
        return {
            "reconnaissance": ["nmap", "rustscan", "amass", "subfinder", "gobuster"],
            "vulnerability_scanning": ["nuclei", "nikto", "wpscan", "sqlmap"],
            "web_discovery": ["gobuster", "feroxbuster", "ffuf", "dirsearch"],
            "subdomain_enumeration": ["amass", "subfinder", "assetfinder", "fierce"],
            "password_attacks": ["hydra", "john", "hashcat", "medusa"],
            "cloud_security": ["prowler", "scout-suite", "trivy", "kube-hunter"],
            "binary_analysis": ["ghidra", "radare2", "binwalk", "strings"],
            "network_discovery": ["nmap", "rustscan", "masscan", "autorecon"],
            "api_testing": ["nuclei", "ffuf", "arjun", "paramspider"],
            "forensics": ["volatility", "steghide", "foremost", "exiftool"]
        }
    
    def analyze_target(self, target: str) -> TargetProfile:
        """Analyze target and create profile"""
        from ..domain.target_analysis import TargetAnalyzer
        
        analyzer = TargetAnalyzer()
        profile = analyzer.analyze_target(target)
        
        profile.calculate_attack_surface()
        profile.assess_risk_level()
        
        return profile
    
    def select_optimal_tools(self, profile: TargetProfile, objective: str = "comprehensive", max_tools: int = 10) -> List[str]:
        """Select optimal tools for target based on profile and objective"""
        target_type = profile.target_type.value
        selected_tools = []
        
        if objective in self.attack_patterns:
            candidate_tools = self.attack_patterns[objective].copy()
        else:
            candidate_tools = []
            for pattern_tools in self.attack_patterns.values():
                candidate_tools.extend(pattern_tools)
            candidate_tools = list(set(candidate_tools))  # Remove duplicates
        
        tool_scores = []
        for tool in candidate_tools:
            if tool in self.tool_effectiveness:
                effectiveness = self.tool_effectiveness[tool].get(target_type, 0.1)
                
                for tech in profile.technologies:
                    if tech in self.technology_signatures:
                        if tool in self.technology_signatures[tech]:
                            effectiveness += 0.2
                
                if profile.attack_surface_score > 3.0:
                    effectiveness += 0.1
                
                tool_scores.append((tool, effectiveness))
        
        tool_scores.sort(key=lambda x: x[1], reverse=True)
        selected_tools = [tool for tool, score in tool_scores[:max_tools]]
        
        essential_tools = self._get_essential_tools(profile.target_type)
        for tool in essential_tools:
            if tool not in selected_tools and len(selected_tools) < max_tools:
                selected_tools.append(tool)
        
        logger.info(f"Selected {len(selected_tools)} tools for {target_type}: {selected_tools}")
        return selected_tools
    
    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Optimize tool parameters based on target profile"""
        if context is None:
            context = {}
        
        base_params = {"target": profile.target}
        
        if tool == "nmap":
            return self._optimize_nmap_params(profile, base_params)
        elif tool == "gobuster":
            return self._optimize_gobuster_params(profile, base_params)
        elif tool == "nuclei":
            return self._optimize_nuclei_params(profile, base_params)
        elif tool == "sqlmap":
            return self._optimize_sqlmap_params(profile, base_params)
        elif tool == "hydra":
            return self._optimize_hydra_params(profile, base_params)
        elif tool == "rustscan":
            return self._optimize_rustscan_params(profile, base_params)
        elif tool == "amass":
            return self._optimize_amass_params(profile, base_params)
        elif tool == "prowler":
            return self._optimize_prowler_params(profile, base_params)
        elif tool == "ghidra":
            return self._optimize_ghidra_params(profile, base_params)
        else:
            base_params.update({
                "timeout": DEFAULT_TIMEOUTS.get(tool, 300),
                "threads": 10
            })
            return base_params
    
    def _optimize_nmap_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize nmap parameters"""
        params = base_params.copy()
        
        if profile.target_type == TargetType.WEB_APPLICATION:
            params["scan_type"] = "-sV -sC"
            params["ports"] = "80,443,8080,8443,8000,8888"
        elif profile.target_type == TargetType.NETWORK_HOST:
            params["scan_type"] = "-sS -sV -sC"
            params["ports"] = "1-1000"
        else:
            params["scan_type"] = "-sV"
            params["ports"] = "1-65535"
        
        if profile.risk_level in ["critical", "high"]:
            params["additional_args"] = "-T4 -Pn --min-rate=1000"
        else:
            params["additional_args"] = "-T3 -Pn"
        
        params["timeout"] = DEFAULT_TIMEOUTS.get("nmap", 300)
        return params
    
    def _optimize_gobuster_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize gobuster parameters"""
        params = base_params.copy()
        
        params["mode"] = "dir"
        params["wordlist"] = "/usr/share/wordlists/dirb/common.txt"
        
        if profile.attack_surface_score > 3.0:
            params["threads"] = 50
        else:
            params["threads"] = 20
        
        extensions = []
        for tech in profile.technologies:
            if tech == TechnologyStack.PHP:
                extensions.extend(["php", "php3", "php4", "php5"])
            elif tech == TechnologyStack.PYTHON:
                extensions.extend(["py", "pyc"])
            elif tech == TechnologyStack.JAVA:
                extensions.extend(["jsp", "jsf", "do"])
            elif tech == TechnologyStack.DOTNET:
                extensions.extend(["asp", "aspx", "ashx"])
        
        if extensions:
            params["extensions"] = ",".join(set(extensions))
        
        params["timeout"] = DEFAULT_TIMEOUTS.get("gobuster", 600)
        return params
    
    def _optimize_nuclei_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize nuclei parameters"""
        params = base_params.copy()
        
        if profile.risk_level in ["critical", "high"]:
            params["severity"] = "critical,high,medium"
        else:
            params["severity"] = "critical,high"
        
        tags = []
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS:
                tags.append("wordpress")
            elif tech == TechnologyStack.DRUPAL:
                tags.append("drupal")
            elif tech == TechnologyStack.JOOMLA:
                tags.append("joomla")
        
        if tags:
            params["tags"] = ",".join(tags)
        
        params["concurrency"] = 25
        params["rate_limit"] = 150
        params["timeout"] = DEFAULT_TIMEOUTS.get("nuclei", 180)
        return params
    
    def _optimize_sqlmap_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize sqlmap parameters"""
        params = base_params.copy()
        
        params["level"] = 3
        params["risk"] = 2
        
        if any(port in profile.open_ports for port in [3306, 1433, 5432]):
            params["level"] = 4
            params["risk"] = 3
        
        params["timeout"] = DEFAULT_TIMEOUTS.get("sqlmap", 900)
        return params
    
    def _optimize_hydra_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize hydra parameters"""
        params = base_params.copy()
        
        if 22 in profile.open_ports:
            params["service"] = "ssh"
        elif 21 in profile.open_ports:
            params["service"] = "ftp"
        elif 23 in profile.open_ports:
            params["service"] = "telnet"
        elif 3389 in profile.open_ports:
            params["service"] = "rdp"
        else:
            params["service"] = "http-get"
        
        params["threads"] = 16
        params["timeout"] = DEFAULT_TIMEOUTS.get("hydra", 600)
        return params
    
    def _optimize_rustscan_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize rustscan parameters"""
        params = base_params.copy()
        
        if profile.target_type == TargetType.NETWORK_HOST:
            params["batch_size"] = 5000
            params["timeout"] = 2000
        else:
            params["batch_size"] = 3000
            params["timeout"] = 1500
        
        params["ulimit"] = 5000
        return params
    
    def _optimize_amass_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize amass parameters"""
        params = base_params.copy()
        
        params["mode"] = "enum"
        params["passive"] = True
        params["active"] = False  # Start with passive
        
        if profile.risk_level in ["critical", "high"]:
            params["active"] = True
        
        params["timeout"] = DEFAULT_TIMEOUTS.get("amass", 1800)
        return params
    
    def _optimize_prowler_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize prowler parameters"""
        params = base_params.copy()
        
        if profile.cloud_provider == "AWS":
            params["provider"] = "aws"
            params["services"] = "s3,ec2,iam,rds"
        elif profile.cloud_provider == "Microsoft Azure":
            params["provider"] = "azure"
        elif profile.cloud_provider == "Google Cloud":
            params["provider"] = "gcp"
        
        params["timeout"] = DEFAULT_TIMEOUTS.get("prowler", 1800)
        return params
    
    def _optimize_ghidra_params(self, profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize ghidra parameters"""
        params = base_params.copy()
        
        params["headless"] = True
        params["analyze"] = True
        params["import"] = True
        
        params["timeout"] = DEFAULT_TIMEOUTS.get("ghidra", 1800)
        return params
    
    def _get_essential_tools(self, target_type: TargetType) -> List[str]:
        """Get essential tools for target type"""
        essential_map = {
            TargetType.WEB_APPLICATION: ["nmap", "gobuster", "nuclei"],
            TargetType.NETWORK_HOST: ["nmap", "rustscan"],
            TargetType.API_ENDPOINT: ["nuclei", "ffuf"],
            TargetType.CLOUD_SERVICE: ["prowler", "nuclei"],
            TargetType.BINARY_FILE: ["ghidra", "strings"],
            TargetType.MOBILE_APP: ["ghidra", "strings"]
        }
        
        return essential_map.get(target_type, ["nmap"])
    
    def enable_advanced_optimization(self) -> None:
        """Enable advanced optimization features"""
        self._use_advanced_optimizer = True
        logger.info("Advanced optimization enabled")
    
    def disable_advanced_optimization(self) -> None:
        """Disable advanced optimization features"""
        self._use_advanced_optimizer = False
        logger.info("Advanced optimization disabled")
    
    def calculate_tool_effectiveness(self, tool: str, target_type: TargetType) -> float:
        """Calculate tool effectiveness for target type"""
        if tool in self.tool_effectiveness:
            return self.tool_effectiveness[tool].get(target_type.value, 0.1)
        return 0.1
    
    def update_tool_effectiveness(self, tool: str, target_type: str, effectiveness: float) -> None:
        """Update tool effectiveness based on results"""
        if tool not in self.tool_effectiveness:
            self.tool_effectiveness[tool] = {}
        
        self.tool_effectiveness[tool][target_type] = effectiveness
        logger.info(f"Updated effectiveness for {tool} on {target_type}: {effectiveness}")
