"""
Parameter optimization service for intelligent tool configuration.

This module changes when parameter optimization algorithms change.
"""

from typing import Dict, Any
import logging
from ..domain.target_analysis import TargetProfile, TargetType
from ..adapters.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

class ParameterOptimizationService:
    """Service for optimizing tool parameters based on target and context"""
    
    def __init__(self):
        self.tool_registry = ToolRegistry()
    
    def optimize_parameters(self, tool: str, target: TargetProfile, context) -> Dict[str, Any]:
        """Optimize tool parameters based on target and context"""
        try:
            base_params = self.tool_registry.get_tool_definition(tool).get('default_params', {})
            optimized_params = base_params.copy()
            
            if tool == 'nmap':
                optimized_params = self._optimize_nmap_params(optimized_params, target, context)
            elif tool == 'gobuster':
                optimized_params = self._optimize_gobuster_params(optimized_params, target, context)
            elif tool == 'nuclei':
                optimized_params = self._optimize_nuclei_params(optimized_params, target, context)
            elif tool == 'sqlmap':
                optimized_params = self._optimize_sqlmap_params(optimized_params, target, context)
            
            logger.info(f"⚙️ Optimized parameters for {tool}")
            
            return optimized_params
            
        except Exception as e:
            logger.error(f"💥 Parameter optimization failed for {tool}: {str(e)}")
            return {}

    def _optimize_nmap_params(self, params: Dict[str, Any], target: TargetProfile, context) -> Dict[str, Any]:
        """Optimize nmap parameters"""
        if context.stealth_required:
            params['scan_type'] = '-sS'
            params['timing'] = '-T2'
        else:
            params['scan_type'] = '-sS'
            params['timing'] = '-T4'
        
        if target.target_type == TargetType.NETWORK:
            params['port_range'] = '1-65535'
        else:
            params['port_range'] = '1-1000'
        
        return params

    def _optimize_gobuster_params(self, params: Dict[str, Any], target: TargetProfile, context) -> Dict[str, Any]:
        """Optimize gobuster parameters"""
        if context.stealth_required:
            params['threads'] = 10
            params['delay'] = '100ms'
        else:
            params['threads'] = 50
            params['delay'] = '0ms'
        
        if 'wordpress' in target.technologies:
            params['wordlist'] = 'wordpress.txt'
        elif 'api' in str(target.target_type).lower():
            params['wordlist'] = 'api_endpoints.txt'
        else:
            params['wordlist'] = 'common.txt'
        
        return params

    def _optimize_nuclei_params(self, params: Dict[str, Any], target: TargetProfile, context) -> Dict[str, Any]:
        """Optimize nuclei parameters"""
        if context.stealth_required:
            params['rate_limit'] = 10
            params['severity'] = 'critical,high'
        else:
            params['rate_limit'] = 100
            params['severity'] = 'critical,high,medium'
        
        if target.technologies:
            params['tags'] = ','.join(target.technologies)
        
        return params

    def _optimize_sqlmap_params(self, params: Dict[str, Any], target: TargetProfile, context) -> Dict[str, Any]:
        """Optimize sqlmap parameters"""
        if context.stealth_required:
            params['level'] = 1
            params['risk'] = 1
            params['delay'] = 2
        else:
            params['level'] = 3
            params['risk'] = 2
            params['delay'] = 0
        
        return params
</new_str>
