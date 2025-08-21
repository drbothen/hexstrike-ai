"""
Basic Tool Endpoints for HexStrike AI
Split from tool_endpoints.py to meet 300-line limit
"""

import logging
from typing import Dict, Any
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)


class BasicToolEndpoints:
    """Basic tool endpoint handlers"""
    
    def __init__(self):
        self.execution_service = ToolExecutionService()

    def nmap(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nmap network scanning"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            ports = request_data.get('ports', '1-1000')
            scan_type = request_data.get('scan_type', 'syn')
            timing = request_data.get('timing', 'T4')
            
            command = f"nmap -{scan_type[0].upper()} -p {ports} -{timing} {target}"
            
            result = self.execution_service.execute_tool('nmap', command, request_data)
            
            return {
                "message": "Nmap scan executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing Nmap: {str(e)}")
            return {"error": f"Nmap execution failed: {str(e)}", "status": "error"}

    def nuclei(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nuclei vulnerability scanner"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            templates = request_data.get('templates', 'technologies,vulnerabilities')
            rate_limit = request_data.get('rate_limit', 150)
            
            command = f"nuclei -u {target} -t {templates} -rl {rate_limit}"
            
            result = self.execution_service.execute_tool('nuclei', command, request_data)
            
            return {
                "message": "Nuclei scan executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing Nuclei: {str(e)}")
            return {"error": f"Nuclei execution failed: {str(e)}", "status": "error"}

    def gobuster(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Gobuster directory/file brute-forcing"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            wordlist = request_data.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            threads = request_data.get('threads', 50)
            extensions = request_data.get('extensions', '')
            
            command = f"gobuster dir -u {target} -w {wordlist} -t {threads}"
            if extensions:
                command += f" -x {extensions}"
            
            result = self.execution_service.execute_tool('gobuster', command, request_data)
            
            return {
                "message": "Gobuster scan executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing Gobuster: {str(e)}")
            return {"error": f"Gobuster execution failed: {str(e)}", "status": "error"}

    def sqlmap(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SQLMap for SQL injection testing"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            level = request_data.get('level', 1)
            risk = request_data.get('risk', 1)
            threads = request_data.get('threads', 1)
            
            command = f"sqlmap -u {target} --level={level} --risk={risk} --threads={threads} --batch"
            
            result = self.execution_service.execute_tool('sqlmap', command, request_data)
            
            return {
                "message": "SQLMap scan executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing SQLMap: {str(e)}")
            return {"error": f"SQLMap execution failed: {str(e)}", "status": "error"}

    def nikto(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nikto web server scanner"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            port = request_data.get('port', 80)
            ssl = request_data.get('ssl', False)
            
            command = f"nikto -h {target} -p {port}"
            if ssl:
                command += " -ssl"
            
            result = self.execution_service.execute_tool('nikto', command, request_data)
            
            return {
                "message": "Nikto scan executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing Nikto: {str(e)}")
            return {"error": f"Nikto execution failed: {str(e)}", "status": "error"}

    def ffuf(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute FFUF web fuzzer"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            wordlist = request_data.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            threads = request_data.get('threads', 40)
            
            command = f"ffuf -u {target}/FUZZ -w {wordlist} -t {threads}"
            
            result = self.execution_service.execute_tool('ffuf', command, request_data)
            
            return {
                "message": "FFUF scan executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing FFUF: {str(e)}")
            return {"error": f"FFUF execution failed: {str(e)}", "status": "error"}

    def hydra(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Hydra password brute-forcing"""
        try:
            target = request_data.get('target')
            if not target:
                return {"error": "Target is required", "status": "error"}
            
            service = request_data.get('service', 'ssh')
            username = request_data.get('username', 'admin')
            password_list = request_data.get('password_list', '/usr/share/wordlists/rockyou.txt')
            
            command = f"hydra -l {username} -P {password_list} {target} {service}"
            
            result = self.execution_service.execute_tool('hydra', command, request_data)
            
            return {
                "message": "Hydra attack executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing Hydra: {str(e)}")
            return {"error": f"Hydra execution failed: {str(e)}", "status": "error"}

    def prowler(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Prowler cloud security assessment"""
        try:
            provider = request_data.get('provider', 'aws')
            services = request_data.get('services', 'ec2,s3,iam')
            severity = request_data.get('severity', 'high,critical')
            
            command = f"prowler {provider} --services {services} --severity {severity}"
            
            result = self.execution_service.execute_tool('prowler', command, request_data)
            
            return {
                "message": "Prowler assessment executed successfully",
                "result": result,
                "status": "success"
            }
            
        except Exception as e:
            logger.error(f"Error executing Prowler: {str(e)}")
            return {"error": f"Prowler execution failed: {str(e)}", "status": "error"}
