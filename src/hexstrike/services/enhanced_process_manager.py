"""
Enhanced process management with intelligent resource allocation.

This module changes when process management or resource allocation strategies change.
"""

import threading
import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class EnhancedProcessManager:
    """Advanced process management with intelligent resource allocation"""
    
    def __init__(self):
        from src.hexstrike.services.process_pool import ProcessPool
        from src.hexstrike.services.advanced_cache import AdvancedCache
        from src.hexstrike.services.resource_monitor import ResourceMonitor
        from src.hexstrike.services.performance_dashboard import PerformanceDashboard
        
        self.process_pool = ProcessPool(min_workers=4, max_workers=32)
        self.cache = AdvancedCache(max_size=2000, default_ttl=1800)  # 30 minutes default TTL
        self.resource_monitor = ResourceMonitor()
        self.process_registry = {}
        self.registry_lock = threading.RLock()
        self.performance_dashboard = PerformanceDashboard()
        
        # Process termination and recovery
        self.termination_handlers = {}
        self.recovery_strategies = {}
        
        # Auto-scaling configuration
        self.auto_scaling_enabled = True
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0,
            "disk_high": 95.0,
            "load_high": 0.8
        }
        
        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
    
    def execute_command_async(self, command: str, context: Dict[str, Any] = None) -> str:
        """Execute command asynchronously using process pool"""
        task_id = f"cmd_{int(time.time() * 1000)}_{hash(command) % 10000}"
        
        # Check cache first
        cache_key = f"cmd_result_{hash(command)}"
        cached_result = self.cache.get(cache_key)
        if cached_result and context and context.get("use_cache", True):
            logger.info(f"📋 Using cached result for command: {command[:50]}...")
            return cached_result
        
        # Submit to process pool
        def execute_wrapper():
            import subprocess
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=context.get("timeout", 300) if context else 300
                )
                
                execution_result = {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                    "execution_time": time.time()
                }
                
                # Cache successful results
                if result.returncode == 0 and context and context.get("cache_result", True):
                    self.cache.set(cache_key, execution_result, ttl=context.get("cache_ttl", 1800))
                
                return execution_result
                
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "Command timed out",
                    "return_code": -1,
                    "execution_time": time.time()
                }
            except Exception as e:
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": str(e),
                    "return_code": -1,
                    "execution_time": time.time()
                }
        
        self.process_pool.submit_task(task_id, execute_wrapper)
        
        # Register process
        with self.registry_lock:
            self.process_registry[task_id] = {
                "command": command,
                "status": "running",
                "submitted_at": time.time(),
                "context": context or {}
            }
        
        return task_id
    
    def _execute_command_internal(self, command: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Internal command execution with enhanced monitoring"""
        start_time = time.time()
        
        try:
            import subprocess
            
            # Get current resource usage
            pre_execution_resources = self.resource_monitor.get_current_usage()
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=context.get("timeout", 300) if context else 300
            )
            
            execution_time = time.time() - start_time
            post_execution_resources = self.resource_monitor.get_current_usage()
            
            resource_delta = {
                "cpu_delta": post_execution_resources.get("cpu_percent", 0) - pre_execution_resources.get("cpu_percent", 0),
                "memory_delta": post_execution_resources.get("memory_percent", 0) - pre_execution_resources.get("memory_percent", 0)
            }
            
            execution_result = {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "execution_time": execution_time,
                "resource_usage": resource_delta
            }
            
            self.performance_dashboard.record_execution(command, execution_result)
            
            return execution_result
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return {
                "success": False,
                "stdout": "",
                "stderr": "Command execution timed out",
                "return_code": -1,
                "execution_time": execution_time,
                "resource_usage": {}
            }
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Execution error: {str(e)}",
                "return_code": -1,
                "execution_time": execution_time,
                "resource_usage": {}
            }
    
    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of an async task"""
        return self.process_pool.get_task_result(task_id)
    
    def terminate_process_gracefully(self, task_id: str) -> bool:
        """Terminate a process gracefully"""
        with self.registry_lock:
            if task_id not in self.process_registry:
                return False
            
            self.process_registry[task_id]["status"] = "terminating"
            
            if task_id in self.termination_handlers:
                try:
                    self.termination_handlers[task_id]()
                except Exception as e:
                    logger.error(f"💥 Termination handler error for {task_id}: {str(e)}")
            
            del self.process_registry[task_id]
            if task_id in self.termination_handlers:
                del self.termination_handlers[task_id]
            if task_id in self.recovery_strategies:
                del self.recovery_strategies[task_id]
            
            logger.info(f"🛑 Process terminated gracefully: {task_id}")
            return True
    
    def _monitor_system(self):
        """Monitor system resources and auto-scale"""
        while True:
            try:
                time.sleep(15)  # Monitor every 15 seconds
                
                if not self.auto_scaling_enabled:
                    continue
                
                # Get current resource usage
                usage = self.resource_monitor.get_current_usage()
                
                # Update performance dashboard
                self.performance_dashboard.update_system_metrics(usage)
                
                self._auto_scale_based_on_resources(usage)
                
            except Exception as e:
                logger.error(f"💥 System monitoring error: {str(e)}")
                continue
    
    def _auto_scale_based_on_resources(self, usage: Dict[str, float]):
        """Auto-scale process pool based on resource usage"""
        try:
            cpu_percent = usage.get("cpu_percent", 0)
            memory_percent = usage.get("memory_percent", 0)
            
            pool_stats = self.process_pool.get_pool_stats()
            active_workers = pool_stats.get("active_workers", 0)
            queue_size = pool_stats.get("queue_size", 0)
            
            if (queue_size > active_workers * 2 and 
                cpu_percent < self.resource_thresholds["cpu_high"] and
                memory_percent < self.resource_thresholds["memory_high"]):
                logger.info(f"🔧 Auto-scaling up due to queue backlog (queue: {queue_size}, workers: {active_workers})")
            
            elif (queue_size == 0 and 
                  cpu_percent < 30 and 
                  memory_percent < 50):
                logger.info(f"🔧 Auto-scaling down due to low resource usage")
                
        except Exception as e:
            logger.error(f"💥 Auto-scaling error: {str(e)}")
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive process manager statistics"""
        with self.registry_lock:
            return {
                "process_pool_stats": self.process_pool.get_pool_stats(),
                "cache_stats": self.cache.get_stats(),
                "resource_usage": self.resource_monitor.get_current_usage(),
                "active_processes": len(self.process_registry),
                "performance_dashboard": self.performance_dashboard.get_summary(),
                "auto_scaling_enabled": self.auto_scaling_enabled,
                "resource_thresholds": self.resource_thresholds
            }
