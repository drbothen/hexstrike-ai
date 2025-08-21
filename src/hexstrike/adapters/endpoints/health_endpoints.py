"""
Health and system status endpoint handlers.

This module changes when health check or system monitoring requirements change.
"""

from typing import Dict, Any
from flask import jsonify
import logging
import time
import psutil
import os

logger = logging.getLogger(__name__)

class HealthEndpoints:
    """Health and system status endpoint handlers"""
    
    def __init__(self):
        self.start_time = time.time()
    
    def health_check(self) -> Dict[str, Any]:
        """Health check endpoint with comprehensive tool detection"""
        try:
            health_status = {
                "status": "healthy",
                "timestamp": time.time(),
                "uptime": time.time() - self.start_time,
                "version": "5.0",
                "system": {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent
                }
            }
            
            tools_status = self._check_tool_availability()
            health_status["tools"] = tools_status
            
            logger.info("🏥 Health check completed successfully")
            
            return jsonify(health_status)
            
        except Exception as e:
            logger.error(f"💥 Error in health check: {str(e)}")
            return jsonify({
                "status": "unhealthy",
                "error": str(e),
                "timestamp": time.time()
            }), 500
    
    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check availability of security tools"""
        tools_to_check = [
            'nmap', 'gobuster', 'nuclei', 'sqlmap', 'ffuf',
            'nikto', 'hydra', 'masscan', 'rustscan', 'feroxbuster'
        ]
        
        tools_status = {}
        for tool in tools_to_check:
            try:
                result = os.system(f"which {tool} > /dev/null 2>&1")
                tools_status[tool] = result == 0
            except Exception:
                tools_status[tool] = False
        
        return tools_status
