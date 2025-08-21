"""
Core tool execution logic.

This module changes when tool execution strategies change.
"""

from typing import Dict, Any, Optional
import subprocess
import time
import logging
from dataclasses import dataclass
from ...platform.errors import ErrorHandler, ErrorType

logger = logging.getLogger(__name__)

@dataclass
class ExecutionResult:
    """Result of tool execution"""
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    parsed_output: Dict[str, Any]
    tool_name: str

class ToolExecutor:
    """Core tool execution engine"""
    
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.execution_cache = {}
    
    def execute_command(self, command: str, timeout: int = 300) -> ExecutionResult:
        """Execute shell command with timeout"""
        start_time = time.time()
        
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=process.returncode == 0,
                stdout=stdout,
                stderr=stderr,
                return_code=process.returncode,
                execution_time=execution_time,
                parsed_output={},
                tool_name=""
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                return_code=-1,
                execution_time=execution_time,
                parsed_output={},
                tool_name=""
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                return_code=-1,
                execution_time=execution_time,
                parsed_output={},
                tool_name=""
            )
    
    def build_command(self, tool: str, params: Dict[str, Any]) -> str:
        """Build command string from tool and parameters"""
        if tool == "nmap":
            return self._build_nmap_command(params)
        elif tool == "gobuster":
            return self._build_gobuster_command(params)
        elif tool == "nuclei":
            return self._build_nuclei_command(params)
        elif tool == "sqlmap":
            return self._build_sqlmap_command(params)
        elif tool == "hydra":
            return self._build_hydra_command(params)
        elif tool == "rustscan":
            return self._build_rustscan_command(params)
        elif tool == "amass":
            return self._build_amass_command(params)
        elif tool == "prowler":
            return self._build_prowler_command(params)
        elif tool == "ghidra":
            return self._build_ghidra_command(params)
        else:
            return f"{tool} {params.get('target', '')}"
    
    def _build_nmap_command(self, params: Dict[str, Any]) -> str:
        """Build nmap command"""
        cmd = ["nmap"]
        
        if "scan_type" in params:
            cmd.append(params["scan_type"])
        
        if "ports" in params:
            cmd.extend(["-p", params["ports"]])
        
        if "additional_args" in params:
            cmd.append(params["additional_args"])
        
        cmd.append(params["target"])
        
        return " ".join(cmd)
    
    def _build_gobuster_command(self, params: Dict[str, Any]) -> str:
        """Build gobuster command"""
        cmd = ["gobuster"]
        
        mode = params.get("mode", "dir")
        cmd.append(mode)
        
        cmd.extend(["-u", params["target"]])
        
        if "wordlist" in params:
            cmd.extend(["-w", params["wordlist"]])
        
        if "extensions" in params:
            cmd.extend(["-x", params["extensions"]])
        
        if "threads" in params:
            cmd.extend(["-t", str(params["threads"])])
        
        return " ".join(cmd)
    
    def _build_nuclei_command(self, params: Dict[str, Any]) -> str:
        """Build nuclei command"""
        cmd = ["nuclei"]
        
        cmd.extend(["-u", params["target"]])
        
        if "tags" in params:
            cmd.extend(["-tags", params["tags"]])
        
        if "severity" in params:
            cmd.extend(["-severity", params["severity"]])
        
        if "concurrency" in params:
            cmd.extend(["-c", str(params["concurrency"])])
        
        return " ".join(cmd)
    
    def _build_sqlmap_command(self, params: Dict[str, Any]) -> str:
        """Build sqlmap command"""
        cmd = ["sqlmap"]
        
        cmd.extend(["-u", params["target"]])
        
        if "level" in params:
            cmd.extend(["--level", str(params["level"])])
        
        if "risk" in params:
            cmd.extend(["--risk", str(params["risk"])])
        
        if params.get("batch", False):
            cmd.append("--batch")
        
        return " ".join(cmd)
    
    def _build_hydra_command(self, params: Dict[str, Any]) -> str:
        """Build hydra command"""
        cmd = ["hydra"]
        
        if "threads" in params:
            cmd.extend(["-t", str(params["threads"])])
        
        if "userlist" in params:
            cmd.extend(["-L", params["userlist"]])
        
        if "passlist" in params:
            cmd.extend(["-P", params["passlist"]])
        
        cmd.append(params["target"])
        
        if "service" in params:
            cmd.append(params["service"])
        
        return " ".join(cmd)
    
    def _build_rustscan_command(self, params: Dict[str, Any]) -> str:
        """Build rustscan command"""
        cmd = ["rustscan"]
        
        cmd.extend(["-a", params["target"]])
        
        if "batch_size" in params:
            cmd.extend(["-b", str(params["batch_size"])])
        
        if "timeout" in params:
            cmd.extend(["-t", str(params["timeout"])])
        
        return " ".join(cmd)
    
    def _build_amass_command(self, params: Dict[str, Any]) -> str:
        """Build amass command"""
        cmd = ["amass", "enum"]
        
        cmd.extend(["-d", params["target"]])
        
        if params.get("active", False):
            cmd.append("-active")
        
        if params.get("brute", False):
            cmd.append("-brute")
        
        return " ".join(cmd)
    
    def _build_prowler_command(self, params: Dict[str, Any]) -> str:
        """Build prowler command"""
        cmd = ["prowler"]
        
        if "services" in params:
            cmd.extend(["-s", ",".join(params["services"])])
        
        if "severity" in params:
            cmd.extend(["--severity", params["severity"]])
        
        return " ".join(cmd)
    
    def _build_ghidra_command(self, params: Dict[str, Any]) -> str:
        """Build ghidra command"""
        cmd = ["ghidra"]
        
        cmd.append(params["target"])
        
        if params.get("analyze", False):
            cmd.append("-analyze")
        
        return " ".join(cmd)
