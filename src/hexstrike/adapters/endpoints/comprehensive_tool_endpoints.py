"""
Comprehensive tool endpoint handlers for all security tools.

This module changes when new security tools are added or tool APIs change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class ComprehensiveToolEndpoints:
    """Comprehensive endpoint handlers for all security tools"""
    
    def __init__(self):
        self.execution_service = ToolExecutionService()
    
    def _execute_tool_endpoint(self, tool_name: str) -> Dict[str, Any]:
        """Generic tool execution endpoint handler"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Request body must contain valid JSON"}), 400
            
            result = self.execution_service.execute_tool(tool_name, data)
            
            if result.get("success"):
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "output": result.get("output", ""),
                    "execution_time": result.get("execution_time", 0),
                    "command": result.get("command", "")
                })
            else:
                return jsonify({
                    "success": False,
                    "error": result.get("error", "Tool execution failed"),
                    "tool": tool_name
                }), 500
                
        except Exception as e:
            logger.error(f"💥 Error in {tool_name} endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def nmap(self):
        """Execute nmap scan"""
        return self._execute_tool_endpoint("nmap")
    
    def rustscan(self):
        """Execute rustscan"""
        return self._execute_tool_endpoint("rustscan")
    
    def masscan(self):
        """Execute masscan"""
        return self._execute_tool_endpoint("masscan")
    
    def naabu(self):
        """Execute naabu port scanner"""
        return self._execute_tool_endpoint("naabu")
    
    def gobuster(self):
        """Execute gobuster directory brute force"""
        return self._execute_tool_endpoint("gobuster")
    
    def dirsearch(self):
        """Execute dirsearch"""
        return self._execute_tool_endpoint("dirsearch")
    
    def feroxbuster(self):
        """Execute feroxbuster"""
        return self._execute_tool_endpoint("feroxbuster")
    
    def ffuf(self):
        """Execute ffuf fuzzer"""
        return self._execute_tool_endpoint("ffuf")
    
    def nuclei(self):
        """Execute nuclei vulnerability scanner"""
        return self._execute_tool_endpoint("nuclei")
    
    def nikto(self):
        """Execute nikto web scanner"""
        return self._execute_tool_endpoint("nikto")
    
    def sqlmap(self):
        """Execute sqlmap SQL injection tool"""
        return self._execute_tool_endpoint("sqlmap")
    
    def dalfox(self):
        """Execute dalfox XSS scanner"""
        return self._execute_tool_endpoint("dalfox")
    
    def httpx(self):
        """Execute httpx HTTP toolkit"""
        return self._execute_tool_endpoint("httpx")
    
    def katana(self):
        """Execute katana web crawler"""
        return self._execute_tool_endpoint("katana")
    
    def gau(self):
        """Execute gau URL fetcher"""
        return self._execute_tool_endpoint("gau")
    
    def waybackurls(self):
        """Execute waybackurls"""
        return self._execute_tool_endpoint("waybackurls")
    
    def arjun(self):
        """Execute arjun parameter discovery"""
        return self._execute_tool_endpoint("arjun")
    
    def paramspider(self):
        """Execute paramspider"""
        return self._execute_tool_endpoint("paramspider")
    
    def prowler(self):
        """Execute prowler AWS security assessment"""
        return self._execute_tool_endpoint("prowler")
    
    def scout_suite(self):
        """Execute scout-suite multi-cloud assessment"""
        return self._execute_tool_endpoint("scout-suite")
    
    def trivy(self):
        """Execute trivy container scanner"""
        return self._execute_tool_endpoint("trivy")
    
    def checkov(self):
        """Execute checkov IaC scanner"""
        return self._execute_tool_endpoint("checkov")
    
    def terrascan(self):
        """Execute terrascan"""
        return self._execute_tool_endpoint("terrascan")
    
    def kube_hunter(self):
        """Execute kube-hunter"""
        return self._execute_tool_endpoint("kube-hunter")
    
    def kube_bench(self):
        """Execute kube-bench"""
        return self._execute_tool_endpoint("kube-bench")
    
    def docker_bench_security(self):
        """Execute docker-bench-security"""
        return self._execute_tool_endpoint("docker-bench-security")
    
    def clair(self):
        """Execute clair container scanner"""
        return self._execute_tool_endpoint("clair")
    
    def falco(self):
        """Execute falco runtime security"""
        return self._execute_tool_endpoint("falco")
    
    def hashcat(self):
        """Execute hashcat password cracker"""
        return self._execute_tool_endpoint("hashcat")
    
    def john(self):
        """Execute john the ripper"""
        return self._execute_tool_endpoint("john")
    
    def hydra(self):
        """Execute hydra brute force tool"""
        return self._execute_tool_endpoint("hydra")
    
    def medusa(self):
        """Execute medusa brute force tool"""
        return self._execute_tool_endpoint("medusa")
    
    def amass(self):
        """Execute amass subdomain enumeration"""
        return self._execute_tool_endpoint("amass")
    
    def subfinder(self):
        """Execute subfinder"""
        return self._execute_tool_endpoint("subfinder")
    
    def assetfinder(self):
        """Execute assetfinder"""
        return self._execute_tool_endpoint("assetfinder")
    
    def findomain(self):
        """Execute findomain"""
        return self._execute_tool_endpoint("findomain")
    
    def shodan(self):
        """Execute shodan search"""
        return self._execute_tool_endpoint("shodan")
    
    def censys(self):
        """Execute censys search"""
        return self._execute_tool_endpoint("censys")
    
    def ghidra(self):
        """Execute ghidra analysis"""
        return self._execute_tool_endpoint("ghidra")
    
    def radare2(self):
        """Execute radare2"""
        return self._execute_tool_endpoint("radare2")
    
    def binwalk(self):
        """Execute binwalk"""
        return self._execute_tool_endpoint("binwalk")
    
    def strings(self):
        """Execute strings utility"""
        return self._execute_tool_endpoint("strings")
    
    def objdump(self):
        """Execute objdump"""
        return self._execute_tool_endpoint("objdump")
    
    def gdb(self):
        """Execute gdb debugger"""
        return self._execute_tool_endpoint("gdb")
    
    def metasploit(self):
        """Execute metasploit"""
        return self._execute_tool_endpoint("metasploit")
    
    def searchsploit(self):
        """Execute searchsploit"""
        return self._execute_tool_endpoint("searchsploit")
    
    def exploit_db(self):
        """Execute exploit-db search"""
        return self._execute_tool_endpoint("exploit-db")
    
    def wireshark(self):
        """Execute wireshark/tshark"""
        return self._execute_tool_endpoint("wireshark")
    
    def tcpdump(self):
        """Execute tcpdump"""
        return self._execute_tool_endpoint("tcpdump")
    
    def ngrep(self):
        """Execute ngrep"""
        return self._execute_tool_endpoint("ngrep")
    
    def aircrack_ng(self):
        """Execute aircrack-ng"""
        return self._execute_tool_endpoint("aircrack-ng")
    
    def reaver(self):
        """Execute reaver WPS attack"""
        return self._execute_tool_endpoint("reaver")
    
    def kismet(self):
        """Execute kismet wireless detector"""
        return self._execute_tool_endpoint("kismet")
    
    def setoolkit(self):
        """Execute social engineering toolkit"""
        return self._execute_tool_endpoint("setoolkit")
    
    def gophish(self):
        """Execute gophish phishing framework"""
        return self._execute_tool_endpoint("gophish")
    
    def mobsf(self):
        """Execute mobile security framework"""
        return self._execute_tool_endpoint("mobsf")
    
    def frida(self):
        """Execute frida dynamic analysis"""
        return self._execute_tool_endpoint("frida")
    
    def objection(self):
        """Execute objection mobile testing"""
        return self._execute_tool_endpoint("objection")
    
    def enum4linux_ng(self):
        """Execute enum4linux-ng"""
        return self._execute_tool_endpoint("enum4linux-ng")
    
    def smbmap(self):
        """Execute smbmap"""
        return self._execute_tool_endpoint("smbmap")
    
    def rpcclient(self):
        """Execute rpcclient"""
        return self._execute_tool_endpoint("rpcclient")
    
    def ldapsearch(self):
        """Execute ldapsearch"""
        return self._execute_tool_endpoint("ldapsearch")
    
    def snmpwalk(self):
        """Execute snmpwalk"""
        return self._execute_tool_endpoint("snmpwalk")
    
    def responder(self):
        """Execute responder"""
        return self._execute_tool_endpoint("responder")
    
    def impacket(self):
        """Execute impacket tools"""
        return self._execute_tool_endpoint("impacket")
    
    def bloodhound(self):
        """Execute bloodhound"""
        return self._execute_tool_endpoint("bloodhound")
    
    def crackmapexec(self):
        """Execute crackmapexec"""
        return self._execute_tool_endpoint("crackmapexec")
    
    def evil_winrm(self):
        """Execute evil-winrm"""
        return self._execute_tool_endpoint("evil-winrm")
    
    def powershell_empire(self):
        """Execute powershell empire"""
        return self._execute_tool_endpoint("powershell-empire")
    
    def covenant(self):
        """Execute covenant C2"""
        return self._execute_tool_endpoint("covenant")
    
    def cobalt_strike(self):
        """Execute cobalt strike"""
        return self._execute_tool_endpoint("cobalt-strike")
