"""
Tool command building logic.

This module changes when tool command construction logic changes.
"""

from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class CommandBuilder:
    """Tool command construction logic"""
    
    def build_command(self, tool_name: str, params: Dict[str, Any]) -> Optional[str]:
        """Build command string for tool execution"""
        target = params.get("target", "")
        
        if tool_name == "nmap":
            return self._build_nmap_command(target, params)
        elif tool_name == "gobuster":
            return self._build_gobuster_command(target, params)
        elif tool_name == "nuclei":
            return self._build_nuclei_command(target, params)
        elif tool_name == "sqlmap":
            return self._build_sqlmap_command(target, params)
        elif tool_name == "rustscan":
            return self._build_rustscan_command(target, params)
        elif tool_name == "subfinder":
            return self._build_subfinder_command(target, params)
        elif tool_name == "amass":
            return self._build_amass_command(target, params)
        elif tool_name == "hydra":
            return self._build_hydra_command(target, params)
        elif tool_name == "prowler":
            return self._build_prowler_command(target, params)
        elif tool_name == "ghidra":
            return self._build_ghidra_command(target, params)
        else:
            logger.warning(f"No command builder for tool: {tool_name}")
            return None
    
    def _build_nmap_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build nmap command"""
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
    
    def _build_gobuster_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build gobuster command"""
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", 10)
        extensions = params.get("extensions", "")
        
        command = f"gobuster {mode} -u {target} -w {wordlist} -t {threads}"
        if extensions:
            command += f" -x {extensions}"
        return command
    
    def _build_nuclei_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build nuclei command"""
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
    
    def _build_sqlmap_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build sqlmap command"""
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        level = params.get("level", 1)
        risk = params.get("risk", 1)
        
        command = f"sqlmap -u {target} --level {level} --risk {risk}"
        if data:
            command += f" --data '{data}'"
        if cookie:
            command += f" --cookie '{cookie}'"
        return command
    
    def _build_rustscan_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build rustscan command"""
        ports = params.get("ports", "")
        batch_size = params.get("batch_size", 5000)
        timeout = params.get("timeout", 3000)
        
        command = f"rustscan -a {target} -b {batch_size} -t {timeout}"
        if ports:
            command += f" -p {ports}"
        return command
    
    def _build_subfinder_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build subfinder command"""
        silent = params.get("silent", True)
        output = params.get("output", "")
        
        command = f"subfinder -d {target}"
        if silent:
            command += " -silent"
        if output:
            command += f" -o {output}"
        return command
    
    def _build_amass_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build amass command"""
        mode = params.get("mode", "enum")
        passive = params.get("passive", False)
        
        command = f"amass {mode} -d {target}"
        if passive:
            command += " -passive"
        return command
    
    def _build_hydra_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build hydra command"""
        service = params.get("service", "ssh")
        username = params.get("username", "")
        password_list = params.get("password_list", "")
        threads = params.get("threads", 16)
        
        command = f"hydra -t {threads}"
        if username:
            command += f" -l {username}"
        if password_list:
            command += f" -P {password_list}"
        command += f" {target} {service}"
        return command
    
    def _build_prowler_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build prowler command"""
        provider = params.get("provider", "aws")
        service = params.get("service", "")
        region = params.get("region", "")
        
        command = f"prowler {provider}"
        if service:
            command += f" --service {service}"
        if region:
            command += f" --region {region}"
        return command
    
    def _build_ghidra_command(self, target: str, params: Dict[str, Any]) -> str:
        """Build ghidra command"""
        project_name = params.get("project_name", "analysis")
        script = params.get("script", "")
        
        command = f"ghidra -import {target} -project {project_name}"
        if script:
            command += f" -script {script}"
        return command
