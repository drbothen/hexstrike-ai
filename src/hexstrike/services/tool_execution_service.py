"""
Tool execution orchestration and result processing.

This module changes when tool execution logic or result processing changes.
"""

import subprocess
import time
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
import logging
from ..platform.errors import ErrorHandler
from ..platform.validation import validator

logger = logging.getLogger(__name__)

@dataclass
class ExecutionResult:
    """Execution outcome data"""
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    parsed_output: Dict[str, Any]
    recovery_info: Optional[Dict[str, Any]] = None
    tool_name: str = ""
    target: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class ToolExecutionService:
    """Main tool execution orchestrator"""
    
    def __init__(self):
        self.error_handler = ErrorHandler()
        self.execution_history: List[ExecutionResult] = []
        self.cache: Dict[str, ExecutionResult] = {}
        self.cache_ttl = 3600
    
    def execute_tool(self, tool_name: str, params: Dict[str, Any], use_cache: bool = True) -> ExecutionResult:
        """Execute tool with specified parameters"""
        start_time = time.time()
        
        validation_errors = validator.validate_tool_parameters(tool_name, params)
        if validation_errors:
            error_msg = "; ".join([f"{err.field}: {err.message}" for err in validation_errors])
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Parameter validation failed: {error_msg}",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name=tool_name,
                target=params.get("target", "")
            )
        
        cache_key = self._generate_cache_key(tool_name, params)
        if use_cache and cache_key in self.cache:
            cached_result = self.cache[cache_key]
            if time.time() - cached_result.execution_time < self.cache_ttl:
                logger.info(f"Using cached result for {tool_name}")
                return cached_result
        
        command = self._build_command(tool_name, params)
        if not command:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Failed to build command for tool: {tool_name}",
                return_code=-1,
                execution_time=0.0,
                parsed_output={},
                tool_name=tool_name,
                target=params.get("target", "")
            )
        
        try:
            timeout = params.get("timeout", 300)
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            parsed_output = self._parse_tool_output(tool_name, result.stdout)
            
            execution_result = ExecutionResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                execution_time=execution_time,
                parsed_output=parsed_output,
                tool_name=tool_name,
                target=params.get("target", "")
            )
            
            if use_cache and execution_result.success:
                self.cache[cache_key] = execution_result
            
            self.execution_history.append(execution_result)
            
            logger.info(f"Tool {tool_name} executed in {execution_time:.2f}s with return code {result.returncode}")
            return execution_result
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Tool execution timed out after {timeout} seconds",
                return_code=-1,
                execution_time=execution_time,
                parsed_output={},
                tool_name=tool_name,
                target=params.get("target", "")
            )
        
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Error executing {tool_name}: {str(e)}")
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                return_code=-1,
                execution_time=execution_time,
                parsed_output={},
                tool_name=tool_name,
                target=params.get("target", "")
            )
    
    def execute_with_recovery(self, tool_name: str, params: Dict[str, Any], max_attempts: int = 3) -> ExecutionResult:
        """Execute tool with intelligent error handling and recovery"""
        attempt_count = 0
        last_result = None
        recovery_history = []
        
        while attempt_count < max_attempts:
            attempt_count += 1
            logger.info(f"Executing {tool_name} (attempt {attempt_count}/{max_attempts})")
            
            result = self.execute_tool(tool_name, params, use_cache=attempt_count == 1)
            
            if result.success:
                result.recovery_info = {
                    "attempts_made": attempt_count,
                    "recovery_applied": attempt_count > 1,
                    "recovery_history": recovery_history
                }
                return result
            
            last_result = result
            
            if attempt_count < max_attempts:
                try:
                    exception = Exception(result.stderr)
                    context = {
                        "target": params.get("target", ""),
                        "parameters": params,
                        "attempt_count": attempt_count,
                        "used_tools": set()
                    }
                    
                    strategy = self.error_handler.handle_tool_failure(tool_name, exception, context)
                    recovery_action = strategy.action.value
                    recovery_history.append({
                        "attempt": attempt_count,
                        "error": result.stderr,
                        "recovery_action": recovery_action
                    })
                    
                    if strategy.action.value == "retry_with_backoff":
                        delay = strategy.parameters.get("initial_delay", 5) * (strategy.backoff_multiplier ** (attempt_count - 1))
                        logger.info(f"Retrying {tool_name} after {delay}s delay")
                        time.sleep(min(delay, 60))
                        
                        if "timeout" in params:
                            params["timeout"] = int(params["timeout"] * strategy.timeout_adjustment)
                    
                except Exception as recovery_error:
                    logger.error(f"Recovery failed: {str(recovery_error)}")
                    break
        
        if last_result:
            last_result.recovery_info = {
                "attempts_made": attempt_count,
                "recovery_applied": True,
                "recovery_history": recovery_history,
                "final_action": "all_attempts_exhausted"
            }
        
        return last_result or ExecutionResult(
            success=False,
            stdout="",
            stderr="All recovery attempts exhausted",
            return_code=-1,
            execution_time=0.0,
            parsed_output={},
            tool_name=tool_name,
            target=params.get("target", "")
        )
    
    def _build_command(self, tool_name: str, params: Dict[str, Any]) -> Optional[str]:
        """Build command string for tool execution"""
        target = params.get("target", "")
        
        if tool_name == "nmap":
            scan_type = params.get("scan_type", "-sV")
            ports = params.get("ports", "")
            additional_args = params.get("additional_args", "-T4 -Pn")
            
            command = f"nmap {scan_type}"
            if ports:
                command += f" -p {ports}"
            if additional_args:
                command += f" {additional_args}"
            command += f" {target}"
            return command
        
        elif tool_name == "gobuster":
            mode = params.get("mode", "dir")
            wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            threads = params.get("threads", 10)
            extensions = params.get("extensions", "")
            
            command = f"gobuster {mode} -u {target} -w {wordlist} -t {threads}"
            if extensions:
                command += f" -x {extensions}"
            return command
        
        elif tool_name == "nuclei":
            severity = params.get("severity", "")
            tags = params.get("tags", "")
            template = params.get("template", "")
            concurrency = params.get("concurrency", 25)
            
            command = f"nuclei -u {target} -c {concurrency}"
            if severity:
                command += f" -severity {severity}"
            if tags:
                command += f" -tags {tags}"
            if template:
                command += f" -t {template}"
            return command
        
        else:
            logger.warning(f"No command builder for tool: {tool_name}")
            return None
    
    def _parse_tool_output(self, tool_name: str, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        parsed = {"raw_output": output}
        
        if tool_name == "nmap":
            parsed.update(self._parse_nmap_output(output))
        elif tool_name == "nuclei":
            parsed.update(self._parse_nuclei_output(output))
        elif tool_name == "gobuster":
            parsed.update(self._parse_gobuster_output(output))
        
        return parsed
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        parsed = {
            "open_ports": [],
            "services": {},
            "os_detection": "",
            "script_results": []
        }
        
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    parsed["open_ports"].append(int(port))
                    parsed["services"][int(port)] = service
        
        return parsed
    
    def _parse_nuclei_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei output"""
        parsed = {
            "vulnerabilities": [],
            "total_requests": 0,
            "templates_loaded": 0
        }
        
        lines = output.split('\n')
        for line in lines:
            if '[' in line and ']' in line:
                if any(sev in line.lower() for sev in ['info', 'low', 'medium', 'high', 'critical']):
                    parsed["vulnerabilities"].append({
                        "raw_line": line,
                        "severity": "unknown"
                    })
        
        return parsed
    
    def _parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output"""
        parsed = {
            "found_paths": [],
            "status_codes": {}
        }
        
        lines = output.split('\n')
        for line in lines:
            if 'Status:' in line:
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0]
                    status = parts[1].replace('Status:', '').strip()
                    parsed["found_paths"].append(path)
                    parsed["status_codes"][path] = status
        
        return parsed
    
    def _generate_cache_key(self, tool_name: str, params: Dict[str, Any]) -> str:
        """Generate cache key for tool execution"""
        key_parts = [tool_name]
        for key in sorted(params.keys()):
            if key != "timeout":
                key_parts.append(f"{key}={params[key]}")
        return "|".join(key_parts)
    
    def get_execution_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get execution history"""
        history = self.execution_history[-limit:] if limit > 0 else self.execution_history
        return [
            {
                "tool_name": result.tool_name,
                "target": result.target,
                "success": result.success,
                "execution_time": result.execution_time,
                "timestamp": result.timestamp,
                "return_code": result.return_code
            }
            for result in history
        ]
    
    def clear_cache(self) -> None:
        """Clear execution cache"""
        self.cache.clear()
        logger.info("Execution cache cleared")
