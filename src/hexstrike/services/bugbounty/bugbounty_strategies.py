"""
Bug bounty hunting strategies and configurations.

This module changes when hunting strategies change.
"""

from typing import Dict, List

class BugBountyStrategies:
    """Bug bounty hunting strategies and tool configurations"""
    
    def __init__(self):
        self.vulnerability_priorities = {
            'critical': ['rce', 'sqli', 'auth_bypass', 'privilege_escalation'],
            'high': ['xss_stored', 'csrf', 'idor', 'file_upload'],
            'medium': ['xss_reflected', 'info_disclosure', 'subdomain_takeover'],
            'low': ['clickjacking', 'missing_headers', 'weak_ssl']
        }
        
        self.recon_tools = [
            'subfinder', 'amass', 'assetfinder', 'findomain',
            'httpx', 'naabu', 'nuclei', 'waybackurls'
        ]
        
        self.hunting_strategies = {
            'web_app': ['directory_bruteforce', 'parameter_discovery', 'js_analysis'],
            'api': ['endpoint_discovery', 'parameter_pollution', 'rate_limiting'],
            'mobile': ['static_analysis', 'dynamic_analysis', 'api_testing'],
            'infrastructure': ['subdomain_enum', 'port_scanning', 'service_enum']
        }
        
        self.workflow_templates = {
            'reconnaissance': {
                'steps': [
                    'subdomain_enumeration',
                    'port_scanning', 
                    'service_detection',
                    'technology_identification',
                    'content_discovery'
                ],
                'tools': ['subfinder', 'nmap', 'httpx', 'nuclei', 'gobuster']
            },
            'vulnerability_hunting': {
                'steps': [
                    'automated_scanning',
                    'manual_testing',
                    'parameter_fuzzing',
                    'authentication_testing'
                ],
                'tools': ['nuclei', 'burp', 'ffuf', 'sqlmap']
            },
            'business_logic': {
                'steps': [
                    'workflow_analysis',
                    'privilege_testing',
                    'rate_limit_testing',
                    'input_validation'
                ],
                'tools': ['burp', 'custom_scripts']
            }
        }
    
    def get_strategy_for_target_type(self, target_type: str) -> List[str]:
        """Get hunting strategy for target type"""
        return self.hunting_strategies.get(target_type, [])
    
    def get_tools_for_workflow(self, workflow: str) -> List[str]:
        """Get tools for specific workflow"""
        return self.workflow_templates.get(workflow, {}).get('tools', [])
    
    def get_vulnerability_priority(self, vuln_type: str) -> str:
        """Get priority level for vulnerability type"""
        for priority, vulns in self.vulnerability_priorities.items():
            if vuln_type in vulns:
                return priority
        return 'low'
