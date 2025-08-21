"""
System interaction utilities and resource monitoring.

This module changes when system interaction utilities or resource monitoring requirements change.
"""

import os
import sys
import shutil
import socket
import psutil
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    try:
        return {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture(),
                "python_version": platform.python_version()
            },
            "resources": {
                "cpu_count": psutil.cpu_count(),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "disk_usage": {
                    "total": psutil.disk_usage('/').total,
                    "used": psutil.disk_usage('/').used,
                    "free": psutil.disk_usage('/').free
                }
            },
            "network": {
                "hostname": socket.gethostname(),
                "fqdn": socket.getfqdn(),
                "interfaces": get_network_interfaces()
            }
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return {"error": str(e)}

def check_tool_availability(tool_name: str) -> bool:
    """Check if a tool is available in the system PATH"""
    return shutil.which(tool_name) is not None

def get_tool_version(tool_name: str) -> Optional[str]:
    """Get version of a tool if available"""
    if not check_tool_availability(tool_name):
        return None
    
    version_commands = [
        [tool_name, "--version"],
        [tool_name, "-version"],
        [tool_name, "version"],
        [tool_name, "-V"],
        [tool_name, "-v"]
    ]
    
    for cmd in version_commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip().split('\n')[0]
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            continue
    
    return "unknown"

def get_available_memory() -> int:
    """Get available memory in bytes"""
    return psutil.virtual_memory().available

def get_memory_usage() -> Dict[str, Any]:
    """Get detailed memory usage information"""
    memory = psutil.virtual_memory()
    return {
        "total": memory.total,
        "available": memory.available,
        "used": memory.used,
        "free": memory.free,
        "percent": memory.percent,
        "cached": getattr(memory, 'cached', 0),
        "buffers": getattr(memory, 'buffers', 0)
    }

def get_cpu_count() -> int:
    """Get number of CPU cores"""
    return psutil.cpu_count()

def get_cpu_usage(interval: float = 1.0) -> Dict[str, Any]:
    """Get CPU usage information"""
    cpu_percent = psutil.cpu_percent(interval=interval, percpu=True)
    return {
        "overall": psutil.cpu_percent(interval=0),
        "per_cpu": cpu_percent,
        "count": len(cpu_percent),
        "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None
    }

def get_disk_usage(path: str = "/") -> Dict[str, Any]:
    """Get disk usage for specified path"""
    try:
        usage = psutil.disk_usage(path)
        return {
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": (usage.used / usage.total) * 100
        }
    except Exception as e:
        logger.error(f"Error getting disk usage for {path}: {e}")
        return {"error": str(e)}

def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a port is open on a host"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False

def get_open_ports(host: str, port_range: Tuple[int, int] = (1, 1024), timeout: float = 1.0) -> List[int]:
    """Get list of open ports on a host within specified range"""
    open_ports = []
    start_port, end_port = port_range
    
    for port in range(start_port, end_port + 1):
        if is_port_open(host, port, timeout):
            open_ports.append(port)
    
    return open_ports

def get_network_interfaces() -> List[Dict[str, str]]:
    """Get network interface information"""
    interfaces = []
    
    try:
        for interface_name, addresses in psutil.net_if_addrs().items():
            interface_info = {
                "name": interface_name,
                "addresses": []
            }
            
            for addr in addresses:
                addr_info = {
                    "family": str(addr.family),
                    "address": addr.address
                }
                
                if addr.netmask:
                    addr_info["netmask"] = addr.netmask
                if addr.broadcast:
                    addr_info["broadcast"] = addr.broadcast
                
                interface_info["addresses"].append(addr_info)
            
            interfaces.append(interface_info)
    
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
    
    return interfaces

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

def create_directory(path: str, mode: int = 0o755, exist_ok: bool = True) -> bool:
    """Create directory with specified permissions"""
    try:
        Path(path).mkdir(mode=mode, parents=True, exist_ok=exist_ok)
        return True
    except Exception as e:
        logger.error(f"Error creating directory {path}: {e}")
        return False

def get_file_info(file_path: str) -> Optional[Dict[str, Any]]:
    """Get file information"""
    try:
        path = Path(file_path)
        stat = path.stat()
        
        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": stat.st_size,
            "mode": oct(stat.st_mode),
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "atime": stat.st_atime,
            "mtime": stat.st_mtime,
            "ctime": stat.st_ctime,
            "is_file": path.is_file(),
            "is_dir": path.is_dir(),
            "is_symlink": path.is_symlink(),
            "exists": path.exists()
        }
    except Exception as e:
        logger.error(f"Error getting file info for {file_path}: {e}")
        return None

def get_environment_variables() -> Dict[str, str]:
    """Get environment variables"""
    return dict(os.environ)

def set_environment_variable(name: str, value: str) -> None:
    """Set environment variable"""
    os.environ[name] = value

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
