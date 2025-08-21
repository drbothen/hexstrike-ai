"""
System information utilities.

This module changes when system information requirements change.
"""

import os
import socket
import psutil
import platform
import subprocess
import shutil
from typing import Dict, Any, List, Optional
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

def get_environment_variables() -> Dict[str, str]:
    """Get environment variables"""
    return dict(os.environ)

def set_environment_variable(name: str, value: str) -> None:
    """Set environment variable"""
    os.environ[name] = value
