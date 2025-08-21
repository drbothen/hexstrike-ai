"""
Bug bounty patterns and strategies for HexStrike AI.

This module provides patterns, strategies, and tool mappings for bug bounty hunting.
"""

from typing import Dict, Any, List

class BugBountyPatterns:
    """Provides patterns and strategies for bug bounty hunting"""
    
    @staticmethod
    def get_bounty_multipliers() -> Dict[str, float]:
        """Get bounty multipliers for different program types"""
        return {
            "web": 1.0,
            "api": 1.2,
            "mobile": 1.1
        }
    
    @staticmethod
    def get_attack_surface_multipliers() -> Dict[str, float]:
        """Get attack surface multipliers based on subdomain count"""
        return {
            "large": 1.3,  # > 100 subdomains
            "medium": 1.1,  # > 50 subdomains
            "small": 1.0   # <= 50 subdomains
        }
    
    @staticmethod
    def get_bounty_base_amounts() -> Dict[str, int]:
        """Get base bounty amounts by severity"""
        return {
            "low": 100,
            "medium": 500,
            "high": 2000,
            "critical": 10000
        }
    
    @staticmethod
    def get_next_step_thresholds() -> Dict[str, int]:
        """Get thresholds for suggesting next steps"""
        return {
            "subdomains_found": 50,
            "js_files_found": 10,
            "parameters_found": 20,
            "admin_panels_found": 0,
            "api_endpoints_found": 5
        }
    
    @staticmethod
    def get_next_step_suggestions() -> Dict[str, str]:
        """Get suggestion messages for next steps"""
        return {
            "subdomains_found": "Large attack surface detected - consider automated scanning",
            "js_files_found": "Many JS files found - analyze for API endpoints and secrets",
            "parameters_found": "Many parameters discovered - focus on injection testing",
            "admin_panels_found": "Admin panels discovered - test for authentication bypass",
            "api_endpoints_found": "API endpoints found - test for IDOR and injection vulnerabilities"
        }
