"""
Intelligent process pool with auto-scaling capabilities.

This module changes when process management or auto-scaling logic changes.
"""

import queue
import threading
import time
import logging
from typing import Dict, Any, Callable

logger = logging.getLogger(__name__)

class ProcessPool:
    """Intelligent process pool with auto-scaling capabilities"""
    
    def __init__(self, min_workers=2, max_workers=20, scale_threshold=0.8):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_threshold = scale_threshold
        self.workers = []
        self.task_queue = queue.Queue()
        self.results = {}
        self.pool_lock = threading.Lock()
        self.active_tasks = {}
        self.performance_metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_task_time": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0
        }
        
        # Initialize minimum workers
        self._scale_up(self.min_workers)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()
    
    def submit_task(self, task_id: str, func: Callable, *args, **kwargs) -> str:
        """Submit a task to the process pool"""
        task = {
            "id": task_id,
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "submitted_at": time.time(),
            "status": "queued"
        }
        
        with self.pool_lock:
            self.active_tasks[task_id] = task
            self.task_queue.put(task)
        
        logger.info(f"📋 Task submitted to pool: {task_id}")
        return task_id
    
    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of a submitted task"""
        with self.pool_lock:
            if task_id in self.results:
                return self.results[task_id]
            elif task_id in self.active_tasks:
                return {"status": self.active_tasks[task_id]["status"], "result": None}
            else:
                return {"status": "not_found", "result": None}
    
    def _worker_thread(self, worker_id: int):
        """Worker thread that processes tasks"""
        logger.info(f"🔧 Process pool worker {worker_id} started")
        
        while True:
            try:
                # Get task from queue with timeout
                task = self.task_queue.get(timeout=30)
                if task is None:  # Shutdown signal
                    break
                
                task_id = task["id"]
                start_time = time.time()
                
                # Update task status
                with self.pool_lock:
                    if task_id in self.active_tasks:
                        self.active_tasks[task_id]["status"] = "running"
                        self.active_tasks[task_id]["started_at"] = start_time
                        self.active_tasks[task_id]["worker_id"] = worker_id
                
                try:
                    result = task["func"](*task["args"], **task["kwargs"])
                    execution_time = time.time() - start_time
                    
                    # Store result
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "completed",
                            "result": result,
                            "execution_time": execution_time,
                            "worker_id": worker_id
                        }
                        
                        self.performance_metrics["tasks_completed"] += 1
                        current_avg = self.performance_metrics["avg_task_time"]
                        total_tasks = self.performance_metrics["tasks_completed"]
                        self.performance_metrics["avg_task_time"] = (
                            (current_avg * (total_tasks - 1) + execution_time) / total_tasks
                        )
                        
                        # Remove from active tasks
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]
                    
                    logger.info(f"✅ Task completed: {task_id} in {execution_time:.2f}s")
                    
                except Exception as e:
                    execution_time = time.time() - start_time
                    
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "failed",
                            "error": str(e),
                            "execution_time": execution_time,
                            "worker_id": worker_id
                        }
                        
                        self.performance_metrics["tasks_failed"] += 1
                        
                        # Remove from active tasks
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]
                    
                    logger.error(f"❌ Task failed: {task_id} - {str(e)}")
                
                self.task_queue.task_done()
                
            except queue.Empty:
                # No tasks available, continue waiting
                continue
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {str(e)}")
                continue
    
    def _monitor_performance(self):
        """Monitor pool performance and auto-scale"""
        import psutil
        
        while True:
            try:
                time.sleep(10)  # Check every 10 seconds
                
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_percent = psutil.virtual_memory().percent
                
                with self.pool_lock:
                    self.performance_metrics["cpu_usage"] = cpu_percent
                    self.performance_metrics["memory_usage"] = memory_percent
                    
                    # Auto-scaling logic
                    queue_size = self.task_queue.qsize()
                    active_workers = len([w for w in self.workers if w.is_alive()])
                    
                    if (queue_size > active_workers * 2 and 
                        active_workers < self.max_workers and
                        cpu_percent < 80 and memory_percent < 80):
                        self._scale_up(1)
                    
                    elif (queue_size == 0 and 
                          active_workers > self.min_workers and
                          cpu_percent < 50):
                        self._scale_down(1)
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {str(e)}")
                continue
    
    def _scale_up(self, count: int):
        """Add workers to the pool"""
        for i in range(count):
            worker_id = len(self.workers)
            worker = threading.Thread(
                target=self._worker_thread,
                args=(worker_id,),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        logger.info(f"🔧 Scaled up process pool by {count} workers (total: {len(self.workers)})")
    
    def _scale_down(self, count: int):
        """Remove workers from the pool"""
        for _ in range(min(count, len(self.workers) - self.min_workers)):
            # Signal worker to shutdown by putting None in queue
            self.task_queue.put(None)
        
        self.workers = [w for w in self.workers if w.is_alive()]
        
        logger.info(f"🔧 Scaled down process pool (total: {len(self.workers)})")
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get current pool statistics"""
        with self.pool_lock:
            active_workers = len([w for w in self.workers if w.is_alive()])
            return {
                "active_workers": active_workers,
                "queue_size": self.task_queue.qsize(),
                "active_tasks": len(self.active_tasks),
                "completed_results": len(self.results),
                "performance_metrics": self.performance_metrics.copy()
            }
