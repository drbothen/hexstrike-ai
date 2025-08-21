"""
Parameter optimization service for security tools.

This module changes when tool parameter optimization strategies change.
"""

from typing import Dict, Any
import logging
from ..domain.target_analysis import TargetProfile, TargetType

logger = logging.getLogger(__name__)

class ParameterOptimizer:
    """Optimizes tool parameters based on target analysis"""
    
    def __init__(self):
        self._use_advanced_optimizer = True
    
    def optimize_parameters(self, tool: str, target_profile: TargetProfile, base_params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize parameters for specific tool and target"""
        optimized_params = base_params.copy()
        
        if tool == "nmap":
            optimized_params.update(self._optimize_nmap_params(target_profile, base_params))
        elif tool == "gobuster":
            optimized_params.update(self._optimize_gobuster_params(target_profile, base_params))
        elif tool == "nuclei":
            optimized_params.update(self._optimize_nuclei_params(target_profile, base_params))
        elif tool == "sqlmap":
            optimized_params.update(self._optimize_sqlmap_params(target_profile, base_params))
        elif tool == "hydra":
            optimized_params.update(self._optimize_hydra_params(target_profile, base_params))
        elif tool == "rustscan":
            optimized_params.update(self._optimize_rustscan_params(target_profile, base_params))
        elif tool == "amass":
            optimized_params.update(self._optimize_amass_params(target_profile, base_params))
        elif tool == "prowler":
            optimized_params.update(self._optimize_prowler_params(target_profile, base_params))
        elif tool == "ghidra":
            optimized_params.update(self._optimize_ghidra_params(target_profile, base_params))
        
        return optimized_params
    
    def _optimize_nmap_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize nmap parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.WEB_APPLICATION:
            optimizations["ports"] = "80,443,8080,8443,8000,8888,3000,5000"
            optimizations["scan_type"] = "-sV -sC --script=http-*"
        elif target_profile.target_type == TargetType.NETWORK_HOST:
            optimizations["ports"] = "1-65535"
            optimizations["scan_type"] = "-sS -sV -sC -O"
            optimizations["additional_args"] = "-T4 -Pn --min-rate=1000"
        
        if target_profile.risk_level == "high":
            optimizations["additional_args"] = optimizations.get("additional_args", "") + " --script=vuln"
        
        return optimizations
    
    def _optimize_gobuster_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize gobuster parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.WEB_APPLICATION:
            optimizations["mode"] = "dir"
            optimizations["extensions"] = "php,html,js,txt,xml,json"
            optimizations["threads"] = 20
            
            for tech in target_profile.technologies:
                if tech.name.lower() == "wordpress":
                    optimizations["wordlist"] = "/usr/share/wordlists/dirb/wordpress.txt"
                elif tech.name.lower() == "drupal":
                    optimizations["wordlist"] = "/usr/share/wordlists/dirb/drupal.txt"
        
        elif target_profile.target_type == TargetType.API_ENDPOINT:
            optimizations["mode"] = "dir"
            optimizations["extensions"] = "json,xml,api"
            optimizations["wordlist"] = "/usr/share/wordlists/api/api-endpoints.txt"
        
        return optimizations
    
    def _optimize_nuclei_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize nuclei parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.WEB_APPLICATION:
            optimizations["tags"] = "cve,oast,default-logins,exposures"
            optimizations["severity"] = "critical,high,medium"
            
            for tech in target_profile.technologies:
                if tech.name.lower() in ["wordpress", "drupal", "joomla"]:
                    optimizations["tags"] += f",{tech.name.lower()}"
        
        elif target_profile.target_type == TargetType.API_ENDPOINT:
            optimizations["tags"] = "api,injection,auth-bypass"
            optimizations["severity"] = "critical,high"
        
        if target_profile.risk_level == "high":
            optimizations["concurrency"] = 50
        else:
            optimizations["concurrency"] = 25
        
        return optimizations
    
    def _optimize_sqlmap_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize sqlmap parameters"""
        optimizations = {}
        
        if target_profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            optimizations["level"] = 3
            optimizations["risk"] = 2
            optimizations["batch"] = True
            
            if target_profile.risk_level == "high":
                optimizations["level"] = 5
                optimizations["risk"] = 3
        
        return optimizations
    
    def _optimize_hydra_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize hydra parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.NETWORK_HOST:
            optimizations["threads"] = 16
            optimizations["services"] = ["ssh", "ftp", "telnet", "http-get", "http-post-form"]
        elif target_profile.target_type == TargetType.WEB_APPLICATION:
            optimizations["threads"] = 10
            optimizations["services"] = ["http-get", "http-post-form", "https-get", "https-post-form"]
        
        return optimizations
    
    def _optimize_rustscan_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize rustscan parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.NETWORK_HOST:
            optimizations["batch_size"] = 4500
            optimizations["timeout"] = 2000
            optimizations["tries"] = 1
        
        return optimizations
    
    def _optimize_amass_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize amass parameters"""
        optimizations = {}
        
        if target_profile.target_type in [TargetType.WEB_APPLICATION, TargetType.API_ENDPOINT]:
            optimizations["active"] = True
            optimizations["brute"] = True
            optimizations["min_for_recursive"] = 3
        
        return optimizations
    
    def _optimize_prowler_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize prowler parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.CLOUD_SERVICE:
            optimizations["services"] = ["s3", "ec2", "iam", "rds", "lambda"]
            optimizations["severity"] = "critical,high"
        
        return optimizations
    
    def _optimize_ghidra_params(self, target_profile: TargetProfile, params: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize ghidra parameters"""
        optimizations = {}
        
        if target_profile.target_type == TargetType.BINARY_FILE:
            optimizations["analyze"] = True
            optimizations["import"] = True
            optimizations["processor"] = "auto"
        
        return optimizations
    
    def enable_advanced_optimization(self) -> None:
        """Enable advanced parameter optimization"""
        self._use_advanced_optimizer = True
        logger.info("Advanced parameter optimization enabled")
    
    def disable_advanced_optimization(self) -> None:
        """Disable advanced parameter optimization"""
        self._use_advanced_optimizer = False
        logger.info("Advanced parameter optimization disabled")
