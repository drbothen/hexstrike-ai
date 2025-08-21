"""
Tool parameter optimization service.

This module provides parameter optimization for various security tools.
"""

from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class ToolParameterOptimizer:
    """Optimizes parameters for security tools based on target profiles"""
    
    def __init__(self):
        pass
    
    def optimize_parameters(self, tool_name: str, target_profile: Any) -> Dict[str, Any]:
        """Optimize tool parameters based on target profile and context"""
        base_params = {"target": target_profile.target}
        
        optimization_methods = {
            "nmap": self._optimize_nmap_params,
            "gobuster": self._optimize_gobuster_params,
            "nuclei": self._optimize_nuclei_params,
            "sqlmap": self._optimize_sqlmap_params,
            "ffuf": self._optimize_ffuf_params,
            "hydra": self._optimize_hydra_params,
            "masscan": self._optimize_masscan_params,
            "nmap-advanced": self._optimize_nmap_advanced_params,
            "enum4linux-ng": self._optimize_enum4linux_ng_params,
            "autorecon": self._optimize_autorecon_params,
            "ghidra": self._optimize_ghidra_params,
            "pwntools": self._optimize_pwntools_params,
            "ropper": self._optimize_ropper_params,
            "angr": self._optimize_angr_params,
            "prowler": self._optimize_prowler_params,
            "scout-suite": self._optimize_scout_suite_params,
            "kube-hunter": self._optimize_kube_hunter_params,
            "trivy": self._optimize_trivy_params,
            "checkov": self._optimize_checkov_params
        }
        
        optimizer = optimization_methods.get(tool_name)
        if optimizer:
            optimized = optimizer(target_profile)
            base_params.update(optimized)
        
        return base_params
    
    def _optimize_nmap_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Nmap parameters"""
        params = {}
        
        if target_profile.target_type.value == "WEB_APPLICATION":
            params["scan_type"] = "-sS -sV"
            params["ports"] = "80,443,8080,8443"
        else:
            params["scan_type"] = "-sS -sV -sC"
            params["ports"] = "1-1000"
        
        return params
    
    def _optimize_gobuster_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Gobuster parameters"""
        params = {
            "mode": "dir",
            "threads": 50,
            "extensions": "php,html,txt,js"
        }
        
        if "wordpress" in target_profile.technologies:
            params["wordlist"] = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            params["extensions"] = "php"
        
        return params
    
    def _optimize_nuclei_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Nuclei parameters"""
        params = {
            "templates": "cves,vulnerabilities",
            "severity": "medium,high,critical"
        }
        
        if target_profile.technologies:
            tech_templates = []
            for tech in target_profile.technologies:
                if tech in ["wordpress", "drupal", "joomla"]:
                    tech_templates.append(tech)
            
            if tech_templates:
                params["templates"] = ",".join(tech_templates)
        
        return params
    
    def _optimize_sqlmap_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize SQLMap parameters"""
        return {
            "level": 3,
            "risk": 2,
            "batch": True,
            "random_agent": True
        }
    
    def _optimize_ffuf_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize FFuf parameters"""
        return {
            "threads": 40,
            "rate": 100,
            "timeout": 10,
            "follow_redirects": True
        }
    
    def _optimize_hydra_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Hydra parameters"""
        return {
            "threads": 16,
            "timeout": 30,
            "exit_on_first": True
        }
    
    def _optimize_masscan_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Masscan parameters"""
        return {
            "rate": 1000,
            "ports": "0-65535",
            "wait": 0,
            "interfaces": "eth0"
        }
    
    def _optimize_nmap_advanced_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize advanced Nmap parameters"""
        return {
            "scan_type": "-sS -sV -sC -O --script vuln",
            "ports": "1-65535",
            "timing": "-T4",
            "output_format": "all"
        }
    
    def _optimize_enum4linux_ng_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize enum4linux-ng parameters"""
        return {
            "detailed": True,
            "user_list": "/usr/share/wordlists/metasploit/unix_users.txt",
            "password_list": "/usr/share/wordlists/metasploit/unix_passwords.txt",
            "timeout": 60
        }
    
    def _optimize_autorecon_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize AutoRecon parameters"""
        return {
            "only_scans_dir": True,
            "single_target": True,
            "output_dir": f"autorecon_{target_profile.target.replace('.', '_')}",
            "heartbeat": 60
        }
    
    def _optimize_ghidra_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Ghidra parameters"""
        return {
            "analyze": True,
            "import_options": "elf,pe,macho",
            "project_name": f"ghidra_{target_profile.target.replace('.', '_')}",
            "headless": True
        }
    
    def _optimize_pwntools_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize pwntools parameters"""
        return {
            "context_arch": "amd64",
            "context_os": "linux",
            "context_endian": "little",
            "context_word_size": 64,
            "log_level": "info"
        }
    
    def _optimize_ropper_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Ropper parameters"""
        return {
            "arch": "x86_64",
            "type": "elf",
            "detailed": True,
            "search_rop_gadgets": True,
            "search_jop_gadgets": True
        }
    
    def _optimize_angr_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Angr parameters"""
        return {
            "auto_load_libs": False,
            "use_sim_procedures": True,
            "remove_options": ["LAZY_SOLVES"],
            "add_options": ["SYMBOLIC_WRITE_ADDRESSES"],
            "max_steps": 10000
        }
    
    def _optimize_prowler_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Prowler parameters"""
        return {
            "checks": "cis,extras,forensics-ready",
            "severity": "High,Medium,Low",
            "compliance": "cis,hipaa,gdpr",
            "output_formats": "json,html"
        }
    
    def _optimize_scout_suite_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize ScoutSuite parameters"""
        return {
            "provider": "aws",
            "regions": "all",
            "services": "ec2,s3,iam,rds,lambda",
            "report_dir": f"scout_{target_profile.target.replace('.', '_')}"
        }
    
    def _optimize_kube_hunter_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize kube-hunter parameters"""
        return {
            "remote": True,
            "cidr": "10.0.0.0/8",
            "active": True,
            "log": "INFO"
        }
    
    def _optimize_trivy_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Trivy parameters"""
        return {
            "severity": "CRITICAL,HIGH",
            "vuln_type": "os,library",
            "format": "json",
            "output": f"trivy_{target_profile.target.replace('.', '_')}.json"
        }
    
    def _optimize_checkov_params(self, target_profile: Any) -> Dict[str, Any]:
        """Optimize Checkov parameters"""
        return {
            "framework": "all",
            "skip_check": "CKV_AWS_1,CKV_AWS_2",
            "quiet": True,
            "compact": True,
            "output": "json"
        }
