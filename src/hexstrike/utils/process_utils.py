"""
Process management utilities.

This module changes when process management requirements change.
"""

import os
import psutil
import signal
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get information about a specific process"""
    try:
        process = psutil.Process(pid)
        return {
            "pid": process.pid,
            "name": process.name(),
            "status": process.status(),
            "cpu_percent": process.cpu_percent(),
            "memory_percent": process.memory_percent(),
            "memory_info": process.memory_info()._asdict(),
            "create_time": process.create_time(),
            "cmdline": process.cmdline(),
            "cwd": process.cwd() if hasattr(process, 'cwd') else None,
            "num_threads": process.num_threads()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def kill_process(pid: int, force: bool = False) -> bool:
    """Kill a process by PID"""
    try:
        process = psutil.Process(pid)
        
        if force:
            process.kill()
        else:
            process.terminate()
        
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def get_running_processes() -> List[Dict[str, Any]]:
    """Get list of running processes"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return processes

def kill_process_by_name(process_name: str) -> int:
    """Kill processes by name, returns count of killed processes"""
    killed_count = 0
    
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                try:
                    proc.terminate()
                    killed_count += 1
                except psutil.NoSuchProcess:
                    pass
                except Exception as e:
                    logger.error(f"Failed to kill process {proc.info['pid']}: {str(e)}")
    except Exception as e:
        logger.error(f"Error killing processes by name {process_name}: {str(e)}")
    
    return killed_count

def get_process_by_name(process_name: str) -> List[Dict[str, Any]]:
    """Get processes by name"""
    matching_processes = []
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            if proc.info['name'] == process_name:
                matching_processes.append(proc.info)
    except Exception as e:
        logger.error(f"Error finding processes by name {process_name}: {str(e)}")
    
    return matching_processes
