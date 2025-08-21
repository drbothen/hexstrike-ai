"""
Process lifecycle management and monitoring.

This module changes when process management logic or monitoring requirements change.
"""

import os
import signal
import psutil
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import logging
from ..utils.system import get_process_info, kill_process

logger = logging.getLogger(__name__)

@dataclass
class ProcessInfo:
    """Process information data structure"""
    pid: int
    command: str
    tool_name: str
    target: str
    status: str
    start_time: datetime
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    progress: float = 0.0

class ProcessService:
    """Process lifecycle management service"""
    
    def __init__(self):
        self.active_processes: Dict[int, ProcessInfo] = {}
        self.process_history: List[ProcessInfo] = []
        self.max_concurrent_processes = 20
    
    def register_process(self, pid: int, command: str, tool_name: str = "", target: str = "") -> bool:
        """Register a new process for monitoring"""
        try:
            if len(self.active_processes) >= self.max_concurrent_processes:
                logger.warning(f"Maximum concurrent processes ({self.max_concurrent_processes}) reached")
                return False
            
            process_info = ProcessInfo(
                pid=pid,
                command=command,
                tool_name=tool_name,
                target=target,
                status="running",
                start_time=datetime.now()
            )
            
            self.active_processes[pid] = process_info
            logger.info(f"Registered process {pid}: {tool_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error registering process {pid}: {str(e)}")
            return False
    
    def terminate_process(self, pid: int) -> bool:
        """Terminate a specific process"""
        try:
            if pid not in self.active_processes:
                logger.warning(f"Process {pid} not found in active processes")
                return False
            
            success = kill_process(pid, force=False)
            
            if success:
                process_info = self.active_processes[pid]
                process_info.status = "terminated"
                self._move_to_history(pid)
                logger.info(f"Terminated process {pid}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error terminating process {pid}: {str(e)}")
            return False
    
    def pause_process(self, pid: int) -> bool:
        """Pause a specific process"""
        try:
            if pid not in self.active_processes:
                logger.warning(f"Process {pid} not found in active processes")
                return False
            
            os.kill(pid, signal.SIGSTOP)
            self.active_processes[pid].status = "paused"
            logger.info(f"Paused process {pid}")
            return True
            
        except (OSError, ProcessLookupError) as e:
            logger.error(f"Error pausing process {pid}: {str(e)}")
            return False
    
    def resume_process(self, pid: int) -> bool:
        """Resume a paused process"""
        try:
            if pid not in self.active_processes:
                logger.warning(f"Process {pid} not found in active processes")
                return False
            
            os.kill(pid, signal.SIGCONT)
            self.active_processes[pid].status = "running"
            logger.info(f"Resumed process {pid}")
            return True
            
        except (OSError, ProcessLookupError) as e:
            logger.error(f"Error resuming process {pid}: {str(e)}")
            return False
    
    def kill_process(self, pid: int) -> bool:
        """Force kill a specific process"""
        try:
            if pid not in self.active_processes:
                logger.warning(f"Process {pid} not found in active processes")
                return False
            
            success = kill_process(pid, force=True)
            
            if success:
                process_info = self.active_processes[pid]
                process_info.status = "killed"
                self._move_to_history(pid)
                logger.info(f"Killed process {pid}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error killing process {pid}: {str(e)}")
            return False
    
    def update_process_status(self, pid: int, status: str, progress: float = None) -> bool:
        """Update process status and progress"""
        try:
            if pid not in self.active_processes:
                return False
            
            self.active_processes[pid].status = status
            
            if progress is not None:
                self.active_processes[pid].progress = max(0.0, min(1.0, progress))
            
            if status in ["completed", "failed", "terminated", "killed"]:
                self._move_to_history(pid)
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating process {pid} status: {str(e)}")
            return False
    
    def get_process_status(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get status of a specific process"""
        if pid in self.active_processes:
            process_info = self.active_processes[pid]
            
            sys_info = get_process_info(pid)
            if sys_info:
                process_info.cpu_percent = sys_info.get("cpu_percent", 0.0)
                process_info.memory_percent = sys_info.get("memory_percent", 0.0)
            
            return {
                "pid": process_info.pid,
                "command": process_info.command,
                "tool_name": process_info.tool_name,
                "target": process_info.target,
                "status": process_info.status,
                "start_time": process_info.start_time.isoformat(),
                "cpu_percent": process_info.cpu_percent,
                "memory_percent": process_info.memory_percent,
                "progress": process_info.progress,
                "runtime": (datetime.now() - process_info.start_time).total_seconds()
            }
        
        return None
    
    def list_active_processes(self) -> Dict[int, Dict[str, Any]]:
        """List all active processes"""
        active = {}
        
        self._cleanup_dead_processes()
        
        for pid, process_info in self.active_processes.items():
            sys_info = get_process_info(pid)
            if sys_info:
                process_info.cpu_percent = sys_info.get("cpu_percent", 0.0)
                process_info.memory_percent = sys_info.get("memory_percent", 0.0)
            
            active[pid] = {
                "command": process_info.command,
                "tool_name": process_info.tool_name,
                "target": process_info.target,
                "status": process_info.status,
                "start_time": process_info.start_time.isoformat(),
                "cpu_percent": process_info.cpu_percent,
                "memory_percent": process_info.memory_percent,
                "progress": process_info.progress,
                "runtime": (datetime.now() - process_info.start_time).total_seconds()
            }
        
        return active
    
    def get_process_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get process execution history"""
        history = self.process_history[-limit:] if limit > 0 else self.process_history
        
        return [
            {
                "pid": process_info.pid,
                "command": process_info.command,
                "tool_name": process_info.tool_name,
                "target": process_info.target,
                "status": process_info.status,
                "start_time": process_info.start_time.isoformat(),
                "progress": process_info.progress
            }
            for process_info in history
        ]
    
    def get_system_resources(self) -> Dict[str, Any]:
        """Get system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "cpu_percent": cpu_percent,
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "percent": memory.percent
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100
                },
                "active_processes": len(self.active_processes),
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
            }
        
        except Exception as e:
            logger.error(f"Error getting system resources: {str(e)}")
            return {"error": str(e)}
    
    def cleanup_all_processes(self) -> int:
        """Cleanup all active processes"""
        cleaned_count = 0
        
        for pid in list(self.active_processes.keys()):
            try:
                if self.terminate_process(pid):
                    cleaned_count += 1
            except Exception as e:
                logger.error(f"Error cleaning up process {pid}: {str(e)}")
        
        logger.info(f"Cleaned up {cleaned_count} processes")
        return cleaned_count
    
    def set_max_concurrent_processes(self, max_processes: int) -> None:
        """Set maximum concurrent processes limit"""
        self.max_concurrent_processes = max(1, max_processes)
        logger.info(f"Set max concurrent processes to {self.max_concurrent_processes}")
    
    def _cleanup_dead_processes(self) -> None:
        """Clean up processes that are no longer running"""
        dead_pids = []
        
        for pid in self.active_processes:
            try:
                process = psutil.Process(pid)
                if not process.is_running():
                    dead_pids.append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                dead_pids.append(pid)
        
        for pid in dead_pids:
            process_info = self.active_processes[pid]
            process_info.status = "completed"
            self._move_to_history(pid)
    
    def _move_to_history(self, pid: int) -> None:
        """Move process from active to history"""
        if pid in self.active_processes:
            process_info = self.active_processes.pop(pid)
            self.process_history.append(process_info)
            
            if len(self.process_history) > 1000:
                self.process_history = self.process_history[-500:]
