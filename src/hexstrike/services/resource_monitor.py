"""
Resource monitoring service with historical tracking.

This module changes when system monitoring requirements or metrics change.
"""

from typing import Dict, Any, List
import logging
import time
import threading
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)

class ResourceMonitor:
    """Advanced resource monitoring with historical tracking"""
    
    def __init__(self, history_size=100):
        self.history_size = history_size
        self.cpu_history = deque(maxlen=history_size)
        self.memory_history = deque(maxlen=history_size)
        self.disk_history = deque(maxlen=history_size)
        self.network_history = deque(maxlen=history_size)
        self.process_history = deque(maxlen=history_size)
        self.monitoring_active = False
        self.monitor_thread = None
        self.lock = threading.RLock()
        
    def start_monitoring(self, interval: int = 15):
        """Start continuous resource monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        logger.info(f"Resource monitoring started with {interval}s interval")
    
    def stop_monitoring(self):
        """Stop continuous resource monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Resource monitoring stopped")
    
    def _monitor_loop(self, interval: int):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._collect_metrics()
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(interval)
    
    def _collect_metrics(self):
        """Collect current system metrics"""
        try:
            import psutil
            
            timestamp = datetime.now()
            
            with self.lock:
                self.cpu_history.append({
                    "timestamp": timestamp,
                    "percent": psutil.cpu_percent(interval=1),
                    "count": psutil.cpu_count(),
                    "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
                })
                
                memory = psutil.virtual_memory()
                self.memory_history.append({
                    "timestamp": timestamp,
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                })
                
                disk = psutil.disk_usage('/')
                self.disk_history.append({
                    "timestamp": timestamp,
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100
                })
                
                net_io = psutil.net_io_counters()
                self.network_history.append({
                    "timestamp": timestamp,
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                })
                
                process_count = len(psutil.pids())
                self.process_history.append({
                    "timestamp": timestamp,
                    "count": process_count,
                    "running": len([p for p in psutil.process_iter() if p.status() == 'running'])
                })
                
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get current system resource status"""
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": psutil.cpu_count(),
                    "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
                },
                "memory": {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "used_gb": round(memory.used / (1024**3), 2),
                    "percent": memory.percent
                },
                "disk": {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "used_gb": round(disk.used / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "percent": round((disk.used / disk.total) * 100, 2)
                },
                "processes": {
                    "total": len(psutil.pids()),
                    "running": len([p for p in psutil.process_iter() if p.status() == 'running'])
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting current status: {str(e)}")
            return {"error": str(e)}
    
    def get_historical_data(self, metric: str = "all", 
                           minutes: int = 60) -> Dict[str, Any]:
        """Get historical data for specified metric"""
        cutoff_time = datetime.now().timestamp() - (minutes * 60)
        
        with self.lock:
            if metric == "cpu" or metric == "all":
                cpu_data = [
                    entry for entry in self.cpu_history 
                    if entry["timestamp"].timestamp() > cutoff_time
                ]
            else:
                cpu_data = []
            
            if metric == "memory" or metric == "all":
                memory_data = [
                    entry for entry in self.memory_history 
                    if entry["timestamp"].timestamp() > cutoff_time
                ]
            else:
                memory_data = []
            
            if metric == "disk" or metric == "all":
                disk_data = [
                    entry for entry in self.disk_history 
                    if entry["timestamp"].timestamp() > cutoff_time
                ]
            else:
                disk_data = []
            
            if metric == "network" or metric == "all":
                network_data = [
                    entry for entry in self.network_history 
                    if entry["timestamp"].timestamp() > cutoff_time
                ]
            else:
                network_data = []
        
        return {
            "cpu": cpu_data,
            "memory": memory_data,
            "disk": disk_data,
            "network": network_data,
            "time_range_minutes": minutes
        }
    
    def get_resource_trends(self, minutes: int = 30) -> Dict[str, Any]:
        """Analyze resource usage trends"""
        historical_data = self.get_historical_data("all", minutes)
        
        trends = {}
        
        if historical_data["cpu"]:
            cpu_values = [entry["percent"] for entry in historical_data["cpu"]]
            trends["cpu"] = self._calculate_trend(cpu_values)
        
        if historical_data["memory"]:
            memory_values = [entry["percent"] for entry in historical_data["memory"]]
            trends["memory"] = self._calculate_trend(memory_values)
        
        if historical_data["disk"]:
            disk_values = [entry["percent"] for entry in historical_data["disk"]]
            trends["disk"] = self._calculate_trend(disk_values)
        
        recent = historical_data["cpu"][-10:] if len(historical_data["cpu"]) >= 10 else historical_data["cpu"]
        
        return {
            "trends": trends,
            "analysis_period_minutes": minutes,
            "data_points_analyzed": len(recent),
            "trend_period_minutes": len(recent) * 15 / 60
        }
    
    def _calculate_trend(self, values: List[float]) -> Dict[str, Any]:
        """Calculate trend for a series of values"""
        if len(values) < 2:
            return {"direction": "insufficient_data", "slope": 0, "confidence": 0}
        
        n = len(values)
        x_values = list(range(n))
        
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n
        
        numerator = sum((x_values[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x_values[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator
        
        if abs(slope) < 0.1:
            direction = "stable"
        elif slope > 0:
            direction = "increasing"
        else:
            direction = "decreasing"
        
        confidence = min(1.0, abs(slope) * 10)
        
        return {
            "direction": direction,
            "slope": round(slope, 4),
            "confidence": round(confidence, 2),
            "current": values[-1] if values else 0,
            "average": round(y_mean, 2),
            "min": min(values),
            "max": max(values)
        }
