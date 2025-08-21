"""
Process management endpoint handlers.

This module changes when process management API endpoints change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
import psutil
import os
import signal

logger = logging.getLogger(__name__)

class ProcessEndpoints:
    """Process management endpoint handlers"""
    
    def __init__(self):
        pass
    
    def list_processes(self):
        """List all active processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    proc_info['cpu_percent'] = proc.cpu_percent()
                    proc_info['memory_percent'] = proc.memory_percent()
                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return jsonify({
                "success": True,
                "processes": processes,
                "total_count": len(processes)
            })
        except Exception as e:
            logger.error(f"💥 Error listing processes: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def get_process_status(self, pid):
        """Get status of a specific process"""
        try:
            pid = int(pid)
            
            try:
                proc = psutil.Process(pid)
                process_info = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_percent": proc.memory_percent(),
                    "create_time": proc.create_time(),
                    "cmdline": proc.cmdline(),
                    "cwd": proc.cwd() if hasattr(proc, 'cwd') else None,
                    "num_threads": proc.num_threads(),
                    "connections": len(proc.connections()) if hasattr(proc, 'connections') else 0
                }
                
                return jsonify({
                    "success": True,
                    "process": process_info
                })
                
            except psutil.NoSuchProcess:
                return jsonify({
                    "success": False,
                    "error": f"Process {pid} not found"
                }), 404
                
        except ValueError:
            return jsonify({
                "success": False,
                "error": "Invalid PID format"
            }), 400
        except Exception as e:
            logger.error(f"💥 Error getting process status: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def terminate_process(self, pid):
        """Terminate a specific process"""
        try:
            pid = int(pid)
            
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.terminate()
                
                return jsonify({
                    "success": True,
                    "message": f"Process {proc_name} (PID: {pid}) terminated successfully"
                })
                
            except psutil.NoSuchProcess:
                return jsonify({
                    "success": False,
                    "error": f"Process {pid} not found"
                }), 404
                
        except ValueError:
            return jsonify({
                "success": False,
                "error": "Invalid PID format"
            }), 400
        except Exception as e:
            logger.error(f"💥 Error terminating process {pid}: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def pause_process(self, pid):
        """Pause a specific process"""
        try:
            pid = int(pid)
            
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.suspend()
                
                return jsonify({
                    "success": True,
                    "message": f"Process {proc_name} (PID: {pid}) paused successfully"
                })
                
            except psutil.NoSuchProcess:
                return jsonify({
                    "success": False,
                    "error": f"Process {pid} not found"
                }), 404
                
        except ValueError:
            return jsonify({
                "success": False,
                "error": "Invalid PID format"
            }), 400
        except Exception as e:
            logger.error(f"💥 Error pausing process {pid}: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def resume_process(self, pid):
        """Resume a paused process"""
        try:
            pid = int(pid)
            
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.resume()
                
                return jsonify({
                    "success": True,
                    "message": f"Process {proc_name} (PID: {pid}) resumed successfully"
                })
                
            except psutil.NoSuchProcess:
                return jsonify({
                    "success": False,
                    "error": f"Process {pid} not found"
                }), 404
                
        except ValueError:
            return jsonify({
                "success": False,
                "error": "Invalid PID format"
            }), 400
        except Exception as e:
            logger.error(f"💥 Error resuming process {pid}: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def kill_process(self, pid):
        """Force kill a specific process"""
        try:
            pid = int(pid)
            
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.kill()
                
                return jsonify({
                    "success": True,
                    "message": f"Process {proc_name} (PID: {pid}) killed successfully"
                })
                
            except psutil.NoSuchProcess:
                return jsonify({
                    "success": False,
                    "error": f"Process {pid} not found"
                }), 404
                
        except ValueError:
            return jsonify({
                "success": False,
                "error": "Invalid PID format"
            }), 400
        except Exception as e:
            logger.error(f"💥 Error killing process {pid}: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def get_system_stats(self):
        """Get system resource statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            stats = {
                "cpu": {
                    "percent": cpu_percent,
                    "count": psutil.cpu_count(),
                    "count_logical": psutil.cpu_count(logical=True)
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100
                },
                "processes": {
                    "total": len(psutil.pids()),
                    "running": len([p for p in psutil.process_iter() if p.status() == psutil.STATUS_RUNNING])
                }
            }
            
            return jsonify({
                "success": True,
                "stats": stats
            })
            
        except Exception as e:
            logger.error(f"💥 Error getting system stats: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
