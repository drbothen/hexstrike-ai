"""
Graceful degradation service for handling partial system failures.

This module changes when fallback strategies or critical operations change.
"""

from typing import Dict, Any, List, Set
import logging

logger = logging.getLogger(__name__)

class GracefulDegradation:
    """Ensure system continues operating even with partial tool failures"""
    
    def __init__(self):
        self.fallback_chains = self._initialize_fallback_chains()
        self.critical_operations = self._initialize_critical_operations()
        
    def _initialize_fallback_chains(self) -> Dict[str, List[List[str]]]:
        """Initialize fallback tool chains for critical operations"""
        return {
            "network_discovery": [
                ["nmap", "rustscan", "masscan"],
                ["rustscan", "nmap"],
                ["ping", "telnet"]
            ],
            "web_discovery": [
                ["gobuster", "feroxbuster", "dirsearch"],
                ["feroxbuster", "ffuf"],
                ["curl", "wget"]
            ],
            "vulnerability_scanning": [
                ["nuclei", "jaeles", "nikto"],
                ["nikto", "w3af"],
                ["curl"]
            ],
            "subdomain_enumeration": [
                ["subfinder", "amass", "assetfinder"],
                ["amass", "findomain"],
                ["dig", "nslookup"]
            ],
            "parameter_discovery": [
                ["arjun", "paramspider", "x8"],
                ["ffuf", "wfuzz"],
                ["manual_testing"]
            ]
        }
    
    def _initialize_critical_operations(self) -> Set[str]:
        """Initialize set of critical operations that must not fail completely"""
        return {
            "network_discovery",
            "web_discovery", 
            "vulnerability_scanning",
            "subdomain_enumeration"
        }
    
    def create_fallback_chain(self, operation: str, failed_tools: List[str] = None) -> List[str]:
        """Create fallback tool chain for critical operations"""
        if failed_tools is None:
            failed_tools = []
        
        chains = self.fallback_chains.get(operation, [])
        
        for chain in chains:
            viable_chain = [tool for tool in chain if tool not in failed_tools]
            if viable_chain:
                logger.info(f"🔄 Fallback chain for {operation}: {viable_chain}")
                return viable_chain
        
        basic_fallbacks = {
            "network_discovery": ["ping"],
            "web_discovery": ["curl"],
            "vulnerability_scanning": ["manual_testing"],
            "subdomain_enumeration": ["dig"],
            "parameter_discovery": ["manual_testing"]
        }
        
        fallback = basic_fallbacks.get(operation, ["manual_testing"])
        logger.warning(f"⚠️ Using basic fallback for {operation}: {fallback}")
        return fallback
    
    def handle_partial_failure(self, operation: str, failed_tools: List[str], 
                             partial_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """Handle partial failure and provide degraded functionality"""
        if partial_results is None:
            partial_results = {}
        
        fallback_chain = self.create_fallback_chain(operation, failed_tools)
        
        degraded_response = {
            "status": "degraded",
            "operation": operation,
            "failed_tools": failed_tools,
            "fallback_tools": fallback_chain,
            "partial_results": partial_results,
            "recommendations": []
        }
        
        if operation == "network_discovery":
            degraded_response["recommendations"] = [
                "Use basic connectivity checks",
                "Perform manual port verification",
                "Consider alternative scanning methods"
            ]
            if partial_results:
                degraded_response["basic_checks"] = self._basic_port_check(
                    partial_results.get("target", "")
                )
        
        elif operation == "web_discovery":
            degraded_response["recommendations"] = [
                "Use manual directory enumeration",
                "Check common web paths",
                "Perform basic HTTP requests"
            ]
            if partial_results:
                degraded_response["basic_checks"] = self._basic_directory_check(
                    partial_results.get("target", "")
                )
        
        elif operation == "vulnerability_scanning":
            degraded_response["recommendations"] = [
                "Perform manual security testing",
                "Use basic vulnerability checks",
                "Review common security issues"
            ]
            if partial_results:
                degraded_response["basic_checks"] = self._basic_security_check(
                    partial_results.get("target", "")
                )
        
        else:
            degraded_response["recommendations"] = self._get_manual_recommendations(operation)
        
        return degraded_response
    
    def _basic_port_check(self, target: str) -> Dict[str, Any]:
        """Perform basic port connectivity check"""
        import socket
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        
        return {
            "method": "basic_socket_check",
            "open_ports": open_ports,
            "total_checked": len(common_ports),
            "success_rate": len(open_ports) / len(common_ports)
        }
    
    def _basic_directory_check(self, target: str) -> Dict[str, Any]:
        """Perform basic directory/file check"""
        import requests
        
        common_paths = [
            "/", "/admin", "/login", "/dashboard", "/api", "/robots.txt", 
            "/sitemap.xml", "/.well-known", "/wp-admin", "/phpmyadmin"
        ]
        
        found_paths = []
        
        for path in common_paths:
            try:
                url = f"http://{target}{path}" if not target.startswith('http') else f"{target}{path}"
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        "path": path,
                        "status_code": response.status_code,
                        "size": len(response.content)
                    })
            except Exception:
                continue
        
        return {
            "method": "basic_http_check",
            "found_paths": found_paths,
            "total_checked": len(common_paths),
            "success_rate": len(found_paths) / len(common_paths)
        }
    
    def _basic_security_check(self, target: str) -> Dict[str, Any]:
        """Perform basic security checks"""
        import requests
        
        security_checks = []
        
        try:
            url = f"http://{target}" if not target.startswith('http') else target
            response = requests.get(url, timeout=10)
            
            headers = response.headers
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            
            security_checks.append({
                "check": "security_headers",
                "missing_headers": missing_headers,
                "severity": "medium" if missing_headers else "low"
            })
            
            if 'Server' in headers:
                security_checks.append({
                    "check": "server_disclosure",
                    "server": headers['Server'],
                    "severity": "low"
                })
            
            if response.status_code == 200 and len(response.text) > 0:
                if '<script>' in response.text.lower():
                    security_checks.append({
                        "check": "javascript_present",
                        "severity": "info"
                    })
                
                if 'error' in response.text.lower() and 'sql' in response.text.lower():
                    security_checks.append({
                        "check": "potential_sql_error",
                        "severity": "high"
                    })
        
        except Exception as e:
            security_checks.append({
                "check": "connection_error",
                "error": str(e),
                "severity": "info"
            })
        
        return {
            "method": "basic_security_scan",
            "checks": security_checks,
            "total_checks": len(security_checks)
        }
    
    def _get_manual_recommendations(self, operation: str) -> List[str]:
        """Get manual recommendations for failed operations"""
        recommendations = {
            "network_discovery": [
                "Manually verify target connectivity",
                "Use alternative network tools",
                "Check firewall and network configuration"
            ],
            "web_discovery": [
                "Manually browse the application",
                "Check robots.txt and sitemap.xml",
                "Use browser developer tools"
            ],
            "vulnerability_scanning": [
                "Perform manual security testing",
                "Review application for common vulnerabilities",
                "Use browser-based security tools"
            ],
            "subdomain_enumeration": [
                "Use DNS lookup tools",
                "Check certificate transparency logs",
                "Perform manual subdomain discovery"
            ],
            "parameter_discovery": [
                "Manually analyze application requests",
                "Use browser network tab",
                "Review application source code"
            ]
        }
        
        return recommendations.get(operation, [
            "Review operation requirements",
            "Use alternative approaches",
            "Consult documentation for manual methods"
        ])
    
    def is_critical_operation(self, operation: str) -> bool:
        """Check if operation is critical and requires fallback"""
        return operation in self.critical_operations
