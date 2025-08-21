"""
Tool-specific endpoint handlers for all security tools.

This module changes when new tools are added or tool APIs change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService
from ...interfaces.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

class ToolEndpoints:
    """Centralized tool endpoint handlers"""
    
    def __init__(self):
        self.tool_executor = ToolExecutionService()
    
    def _execute_tool_endpoint(self, tool_name: str) -> Dict[str, Any]:
        """Generic tool execution endpoint"""
        try:
            data = request.get_json() or {}
            
            result = self.tool_executor.execute_tool(tool_name, data)
            
            if result.success:
                logger.info(f"✅ {tool_name} executed successfully")
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "result": result.output,
                    "execution_time": result.execution_time,
                    "message": f"{tool_name} execution completed"
                })
            else:
                logger.error(f"❌ {tool_name} execution failed: {result.error}")
                return jsonify({
                    "success": False,
                    "tool": tool_name,
                    "error": result.error,
                    "message": f"{tool_name} execution failed"
                }), 500
                
        except Exception as e:
            logger.error(f"💥 Error in {tool_name} endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def nmap(self):
        """Execute Nmap network scanner"""
        return self._execute_tool_endpoint("nmap")
    
    def nuclei(self):
        """Execute Nuclei vulnerability scanner"""
        return self._execute_tool_endpoint("nuclei")
    
    def gobuster(self):
        """Execute Gobuster directory/file brute-forcer"""
        return self._execute_tool_endpoint("gobuster")
    
    def sqlmap(self):
        """Execute SQLMap SQL injection tool"""
        return self._execute_tool_endpoint("sqlmap")
    
    def nikto(self):
        """Execute Nikto web server scanner"""
        return self._execute_tool_endpoint("nikto")
    
    def ffuf(self):
        """Execute FFuf web fuzzer"""
        return self._execute_tool_endpoint("ffuf")
    
    def hydra(self):
        """Execute Hydra password cracker"""
        return self._execute_tool_endpoint("hydra")
    
    def john(self):
        """Execute John the Ripper password cracker"""
        return self._execute_tool_endpoint("john")
    
    def wpscan(self):
        """Execute WPScan WordPress scanner"""
        return self._execute_tool_endpoint("wpscan")
    
    def enum4linux(self):
        """Execute enum4linux SMB enumeration tool"""
        return self._execute_tool_endpoint("enum4linux")
    
    def netexec(self):
        """Execute NetExec (formerly CrackMapExec)"""
        return self._execute_tool_endpoint("netexec")
    
    def amass(self):
        """Execute Amass subdomain enumeration"""
        return self._execute_tool_endpoint("amass")
    
    def hashcat(self):
        """Execute Hashcat password recovery"""
        return self._execute_tool_endpoint("hashcat")
    
    def subfinder(self):
        """Execute Subfinder subdomain discovery"""
        return self._execute_tool_endpoint("subfinder")
    
    def smbmap(self):
        """Execute SMBMap SMB share enumeration"""
        return self._execute_tool_endpoint("smbmap")
    
    def rustscan(self):
        """Execute Rustscan ultra-fast port scanner"""
        return self._execute_tool_endpoint("rustscan")
    
    def masscan(self):
        """Execute Masscan high-speed port scanner"""
        return self._execute_tool_endpoint("masscan")
    
    def nmap_advanced(self):
        """Execute advanced Nmap with NSE scripts"""
        return self._execute_tool_endpoint("nmap-advanced")
    
    def autorecon(self):
        """Execute AutoRecon automated reconnaissance"""
        return self._execute_tool_endpoint("autorecon")
    
    def enum4linux_ng(self):
        """Execute Enum4linux-ng advanced SMB enumeration"""
        return self._execute_tool_endpoint("enum4linux-ng")
    
    def rpcclient(self):
        """Execute rpcclient RPC enumeration"""
        return self._execute_tool_endpoint("rpcclient")
    
    def nbtscan(self):
        """Execute nbtscan NetBIOS scanner"""
        return self._execute_tool_endpoint("nbtscan")
    
    def arp_scan(self):
        """Execute arp-scan network discovery"""
        return self._execute_tool_endpoint("arp-scan")
    
    def responder(self):
        """Execute Responder credential harvesting"""
        return self._execute_tool_endpoint("responder")
    
    def volatility(self):
        """Execute Volatility memory forensics"""
        return self._execute_tool_endpoint("volatility")
    
    def msfvenom(self):
        """Execute MSFVenom payload generator"""
        return self._execute_tool_endpoint("msfvenom")
    
    def gdb(self):
        """Execute GDB debugger"""
        return self._execute_tool_endpoint("gdb")
    
    def radare2(self):
        """Execute Radare2 reverse engineering"""
        return self._execute_tool_endpoint("radare2")
    
    def binwalk(self):
        """Execute Binwalk firmware analysis"""
        return self._execute_tool_endpoint("binwalk")
    
    def ropgadget(self):
        """Execute ROPgadget ROP chain builder"""
        return self._execute_tool_endpoint("ropgadget")
    
    def checksec(self):
        """Execute checksec binary security checker"""
        return self._execute_tool_endpoint("checksec")
    
    def xxd(self):
        """Execute xxd hex dump utility"""
        return self._execute_tool_endpoint("xxd")
    
    def strings(self):
        """Execute strings binary analysis"""
        return self._execute_tool_endpoint("strings")
    
    def objdump(self):
        """Execute objdump binary analysis"""
        return self._execute_tool_endpoint("objdump")
    
    def ghidra(self):
        """Execute Ghidra reverse engineering"""
        return self._execute_tool_endpoint("ghidra")
    
    def pwntools(self):
        """Execute Pwntools exploit development"""
        return self._execute_tool_endpoint("pwntools")
    
    def one_gadget(self):
        """Execute one_gadget RCE finder"""
        return self._execute_tool_endpoint("one-gadget")
    
    def libc_database(self):
        """Execute libc-database lookup"""
        return self._execute_tool_endpoint("libc-database")
    
    def gdb_peda(self):
        """Execute GDB with PEDA"""
        return self._execute_tool_endpoint("gdb-peda")
    
    def angr(self):
        """Execute angr symbolic execution"""
        return self._execute_tool_endpoint("angr")
    
    def ropper(self):
        """Execute ropper ROP gadget finder"""
        return self._execute_tool_endpoint("ropper")
    
    def pwninit(self):
        """Execute pwninit CTF setup"""
        return self._execute_tool_endpoint("pwninit")
    
    def feroxbuster(self):
        """Execute Feroxbuster content discovery"""
        return self._execute_tool_endpoint("feroxbuster")
    
    def dotdotpwn(self):
        """Execute DotDotPwn directory traversal"""
        return self._execute_tool_endpoint("dotdotpwn")
    
    def xsser(self):
        """Execute XSSer XSS scanner"""
        return self._execute_tool_endpoint("xsser")
    
    def wfuzz(self):
        """Execute Wfuzz web fuzzer"""
        return self._execute_tool_endpoint("wfuzz")
    
    def dirsearch(self):
        """Execute Dirsearch directory scanner"""
        return self._execute_tool_endpoint("dirsearch")
    
    def katana(self):
        """Execute Katana web crawler"""
        return self._execute_tool_endpoint("katana")
    
    def gau(self):
        """Execute Gau URL discovery"""
        return self._execute_tool_endpoint("gau")
    
    def waybackurls(self):
        """Execute Waybackurls historical URL discovery"""
        return self._execute_tool_endpoint("waybackurls")
    
    def arjun(self):
        """Execute Arjun parameter discovery"""
        return self._execute_tool_endpoint("arjun")
    
    def paramspider(self):
        """Execute ParamSpider parameter mining"""
        return self._execute_tool_endpoint("paramspider")
    
    def x8(self):
        """Execute x8 hidden parameter discovery"""
        return self._execute_tool_endpoint("x8")
    
    def jaeles(self):
        """Execute Jaeles vulnerability scanner"""
        return self._execute_tool_endpoint("jaeles")
    
    def dalfox(self):
        """Execute Dalfox XSS scanner"""
        return self._execute_tool_endpoint("dalfox")
    
    def httpx(self):
        """Execute httpx HTTP toolkit"""
        return self._execute_tool_endpoint("httpx")
    
    def anew(self):
        """Execute anew data processing"""
        return self._execute_tool_endpoint("anew")
    
    def qsreplace(self):
        """Execute qsreplace query parameter replacement"""
        return self._execute_tool_endpoint("qsreplace")
    
    def uro(self):
        """Execute uro URL filtering"""
        return self._execute_tool_endpoint("uro")
    
    def zap(self):
        """Execute OWASP ZAP"""
        return self._execute_tool_endpoint("zap")
    
    def wafw00f(self):
        """Execute wafw00f WAF detection"""
        return self._execute_tool_endpoint("wafw00f")
    
    def fierce(self):
        """Execute fierce DNS reconnaissance"""
        return self._execute_tool_endpoint("fierce")
    
    def dnsenum(self):
        """Execute dnsenum DNS enumeration"""
        return self._execute_tool_endpoint("dnsenum")
    
    def volatility3(self):
        """Execute Volatility3 memory forensics"""
        return self._execute_tool_endpoint("volatility3")
    
    def foremost(self):
        """Execute Foremost file carving"""
        return self._execute_tool_endpoint("foremost")
    
    def steghide(self):
        """Execute Steghide steganography"""
        return self._execute_tool_endpoint("steghide")
    
    def exiftool(self):
        """Execute ExifTool metadata extraction"""
        return self._execute_tool_endpoint("exiftool")
    
    def hashpump(self):
        """Execute HashPump length extension attacks"""
        return self._execute_tool_endpoint("hashpump")
    
    def hakrawler(self):
        """Execute Hakrawler web endpoint discovery"""
        return self._execute_tool_endpoint("hakrawler")
    
    def trivy(self):
        """Execute Trivy container scanner"""
        return self._execute_tool_endpoint("trivy")
    
    def prowler(self):
        """Execute Prowler cloud security scanner"""
        return self._execute_tool_endpoint("prowler")
    
    def scout_suite(self):
        """Execute Scout Suite cloud security"""
        return self._execute_tool_endpoint("scout-suite")
    
    def kube_hunter(self):
        """Execute kube-hunter Kubernetes scanner"""
        return self._execute_tool_endpoint("kube-hunter")
    
    def kube_bench(self):
        """Execute kube-bench CIS benchmarks"""
        return self._execute_tool_endpoint("kube-bench")
    
    def checkov(self):
        """Execute Checkov IaC scanner"""
        return self._execute_tool_endpoint("checkov")
    
    def terrascan(self):
        """Execute Terrascan IaC security"""
        return self._execute_tool_endpoint("terrascan")
