"""
Performance monitoring service with automatic resource allocation.

This module changes when performance monitoring or resource optimization strategies change.
"""

import psutil
import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """Advanced performance monitoring with automatic resource allocation"""
    
    def __init__(self):
        self.performance_metrics = {}
        self.resource_thresholds = {
            "cpu_high": 80.0,
            "memory_high": 85.0,
            "disk_high": 90.0,
            "network_high": 80.0
        }
        
        self.optimization_rules = {
            "high_cpu": {
                "reduce_threads": 0.5,
                "increase_delay": 2.0,
                "enable_nice": True
            },
            "high_memory": {
                "reduce_batch_size": 0.6,
                "enable_streaming": True,
                "clear_cache": True
            },
            "high_disk": {
                "reduce_output_verbosity": True,
                "enable_compression": True,
                "cleanup_temp_files": True
            },
            "high_network": {
                "reduce_concurrent_connections": 0.7,
                "increase_timeout": 1.5,
                "enable_connection_pooling": True
            }
        }
    
    def monitor_system_resources(self) -> Dict[str, Any]:
        """Monitor current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            resources = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
                "process_count": len(psutil.pids())
            }
            
            resources["status"] = self._determine_resource_status(resources)
            
            return resources
            
        except Exception as e:
            logger.error(f"Error monitoring system resources: {e}")
            return {"error": str(e)}
    
    def optimize_based_on_resources(self, current_resources: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize performance profile based on current resource usage"""
        cpu_percent = current_resources.get("cpu_percent", 0)
        memory_percent = current_resources.get("memory_percent", 0)
        disk_percent = current_resources.get("disk_percent", 0)
        
        if (cpu_percent > self.resource_thresholds["cpu_critical"] or 
            memory_percent > self.resource_thresholds["memory_critical"]):
            recommended_profile = "minimal"
            urgency = "critical"
        elif (cpu_percent > self.resource_thresholds["cpu_high"] or 
              memory_percent > self.resource_thresholds["memory_high"]):
            recommended_profile = "conservative"
            urgency = "high"
        elif (cpu_percent < 50 and memory_percent < 60 and disk_percent < 70):
            recommended_profile = "high_performance"
            urgency = "low"
        else:
            recommended_profile = "balanced"
            urgency = "medium"
        
        if recommended_profile != self.current_profile:
            self.current_profile = recommended_profile
            logger.info(f"🔧 Performance profile changed to: {recommended_profile} (urgency: {urgency})")
        
        optimization = {
            "current_profile": self.current_profile,
            "recommended_profile": recommended_profile,
            "urgency": urgency,
            "profile_settings": self.optimization_profiles[recommended_profile],
            "resource_status": current_resources.get("status", "unknown")
        }
        
        return optimization
    
    def _determine_resource_status(self, resources: Dict[str, Any]) -> str:
        """Determine overall resource status"""
        cpu = resources.get("cpu_percent", 0)
        memory = resources.get("memory_percent", 0)
        disk = resources.get("disk_percent", 0)
        
        if (cpu > self.resource_thresholds["cpu_critical"] or 
            memory > self.resource_thresholds["memory_critical"] or
            disk > self.resource_thresholds["disk_critical"]):
            return "critical"
        elif (cpu > self.resource_thresholds["cpu_high"] or 
              memory > self.resource_thresholds["memory_high"] or
              disk > self.resource_thresholds["disk_high"]):
            return "high"
        elif cpu < 30 and memory < 40 and disk < 50:
            return "low"
        else:
            return "normal"
