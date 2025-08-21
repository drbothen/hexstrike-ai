"""
System utilities and helper functions.

This module changes when system interaction requirements change.
"""

from .file_operations import file_ops
from .network_utils import network_utils
from .process_utils import get_process_info, kill_process, get_running_processes
from .system_info import (
    get_system_info, check_tool_availability, get_tool_version,
    get_available_memory, get_memory_usage, get_cpu_count, get_cpu_usage,
    get_disk_usage, get_network_interfaces, get_environment_variables,
    set_environment_variable
)
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

def get_temp_directory() -> str:
    """Get system temporary directory"""
    return str(Path.home() / "tmp" if Path.home().exists() else Path("/tmp"))

def get_home_directory() -> str:
    """Get user home directory"""
    return str(Path.home())

def get_current_directory() -> str:
    """Get current working directory"""
    return str(Path.cwd())

def change_directory(path: str) -> bool:
    """Change current working directory"""
    try:
        os.chdir(path)
        return True
    except Exception as e:
        logger.error(f"Error changing directory to {path}: {e}")
        return False

def execute_command(command: List[str], timeout: int = 30, cwd: Optional[str] = None) -> Dict[str, Any]:
    """Execute system command and return result"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": " ".join(command)
        }
    
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "command": " ".join(command)
        }
    
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "command": " ".join(command)
        }

class SystemUtils:
    """System operation utilities - compatibility wrapper"""
    
    def __init__(self):
        self.file_ops = file_ops
        self.network_utils = network_utils
    
    def get_system_info(self) -> Dict[str, Any]:
        return get_system_info()
    
    def check_command_exists(self, command: str) -> bool:
        return check_tool_availability(command)
    
    def run_command(self, command: str, timeout: int = 300, cwd: Optional[str] = None):
        result = execute_command(command.split(), timeout, cwd)
        return result["returncode"], result["stdout"], result["stderr"]
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        return get_running_processes()
    
    def get_memory_usage(self) -> Dict[str, Any]:
        return get_memory_usage()
    
    def get_cpu_usage(self, interval: float = 1.0) -> float:
        cpu_info = get_cpu_usage(interval)
        return cpu_info["overall"]

system_utils = SystemUtils()
