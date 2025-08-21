"""
Command execution endpoint handlers.

This module changes when command execution or telemetry requirements change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
import subprocess
import time

logger = logging.getLogger(__name__)

class CommandEndpoints:
    """Command execution endpoint handlers"""
    
    def __init__(self):
        self.execution_history = []
    
    def generic_command(self) -> Dict[str, Any]:
        """Execute any command provided in the request with enhanced logging"""
        try:
            data = request.get_json()
            command = data.get('command', '')
            
            if not command:
                return jsonify({"error": "No command provided"}), 400
            
            logger.info(f"🔧 Executing command: {command}")
            
            start_time = time.time()
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            execution_time = time.time() - start_time
            
            execution_record = {
                "command": command,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "execution_time": execution_time,
                "timestamp": time.time()
            }
            
            self.execution_history.append(execution_record)
            
            if result.returncode == 0:
                logger.info(f"✅ Command executed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"⚠️ Command failed with return code {result.returncode}")
            
            return jsonify({
                "success": result.returncode == 0,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "execution_time": execution_time
            })
            
        except subprocess.TimeoutExpired:
            logger.error("💥 Command execution timed out")
            return jsonify({"error": "Command execution timed out"}), 408
        except Exception as e:
            logger.error(f"💥 Error executing command: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def get_telemetry(self) -> Dict[str, Any]:
        """Get system telemetry"""
        try:
            telemetry_data = {
                "commands_executed": len(self.execution_history),
                "recent_commands": self.execution_history[-10:] if self.execution_history else [],
                "system_uptime": time.time(),
                "timestamp": time.time()
            }
            
            return jsonify(telemetry_data)
            
        except Exception as e:
            logger.error(f"💥 Error getting telemetry: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
