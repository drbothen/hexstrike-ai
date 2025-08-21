"""
Comprehensive tool endpoint handlers for all security tools.

This module changes when new security tools are added or tool APIs change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from .comprehensive_tool_endpoints_web import ComprehensiveWebToolEndpoints
from .comprehensive_tool_endpoints_network import ComprehensiveNetworkToolEndpoints
from .comprehensive_tool_endpoints_exploit import ComprehensiveExploitToolEndpoints
from .comprehensive_tool_endpoints_cloud import ComprehensiveCloudToolEndpoints

logger = logging.getLogger(__name__)

class ComprehensiveToolEndpoints:
    """Comprehensive endpoint handlers that delegates to specialized handlers"""
    
    def __init__(self):
        self.web_tools = ComprehensiveWebToolEndpoints()
        self.network_tools = ComprehensiveNetworkToolEndpoints()
        self.exploit_tools = ComprehensiveExploitToolEndpoints()
        self.cloud_tools = ComprehensiveCloudToolEndpoints()
    
    def nmap(self):
        return self.network_tools.nmap()
    
    def rustscan(self):
        return self.network_tools.rustscan()
    
    def masscan(self):
        return self.network_tools.masscan()
    
    def naabu(self):
        return self.network_tools.naabu()
    
    def gobuster(self):
        return self.web_tools.gobuster()
    
    def dirsearch(self):
        return self.web_tools.dirsearch()
    
    def feroxbuster(self):
        return self.web_tools.feroxbuster()
    
    def ffuf(self):
        return self.web_tools.ffuf()
    
    def nuclei(self):
        return self.web_tools.nuclei()
    
    def nikto(self):
        return self.web_tools.nikto()
    
    def sqlmap(self):
        return self.web_tools.sqlmap()
    
    def dalfox(self):
        return self.web_tools.dalfox()
    
    def httpx(self):
        return self.web_tools.httpx()
    
    def katana(self):
        return self.web_tools.katana()
    
    def gau(self):
        return self.web_tools.gau()
    
    def waybackurls(self):
        return self.web_tools.waybackurls()
    
    def arjun(self):
        return self.web_tools.arjun()
    
    def paramspider(self):
        return self.web_tools.paramspider()
    
    def prowler(self):
        return self.cloud_tools.prowler()
    
    def scout_suite(self):
        return self.cloud_tools.scout_suite()
    
    def trivy(self):
        return self.cloud_tools.trivy()
    
    def checkov(self):
        return self.cloud_tools.checkov()
    
    def terrascan(self):
        return self.cloud_tools.terrascan()
    
    def kube_hunter(self):
        return self.cloud_tools.kube_hunter()
    
    def kube_bench(self):
        return self.cloud_tools.kube_bench()
    
    def docker_bench_security(self):
        return self.cloud_tools.docker_bench_security()
    
    def clair(self):
        return self.cloud_tools.clair()
    
    def falco(self):
        return self.cloud_tools.falco()
    
    def hashcat(self):
        return self.exploit_tools.hashcat()
    
    def john(self):
        return self.exploit_tools.john()
    
    def hydra(self):
        return self.exploit_tools.hydra()
    
    def medusa(self):
        return self.exploit_tools.medusa()
    
    def amass(self):
        return self.network_tools.amass()
    
    def subfinder(self):
        return self.network_tools.subfinder()
    
    def assetfinder(self):
        return self.network_tools.assetfinder()
    
    def findomain(self):
        return self.network_tools.findomain()
    
    def shodan(self):
        return self.network_tools.shodan()
    
    def censys(self):
        return self.network_tools.censys()
    
    def ghidra(self):
        return self.exploit_tools.ghidra()
    
    def radare2(self):
        return self.exploit_tools.radare2()
    
    def binwalk(self):
        return self.exploit_tools.binwalk()
    
    def strings(self):
        return self.exploit_tools.strings()
    
    def objdump(self):
        return self.exploit_tools.objdump()
    
    def gdb(self):
        return self.exploit_tools.gdb()
    
    def metasploit(self):
        return self.exploit_tools.metasploit()
    
    def searchsploit(self):
        return self.exploit_tools.searchsploit()
    
    def exploit_db(self):
        return self.exploit_tools.exploit_db()
    
    def wireshark(self):
        return self.network_tools.wireshark()
    
    def tcpdump(self):
        return self.network_tools.tcpdump()
    
    def ngrep(self):
        return self.network_tools.ngrep()
    
    def aircrack_ng(self):
        return self.network_tools.aircrack_ng()
    
    def reaver(self):
        return self.network_tools.reaver()
    
    def kismet(self):
        return self.network_tools.kismet()
    
    def setoolkit(self):
        return self.exploit_tools.setoolkit()
    
    def gophish(self):
        return self.exploit_tools.gophish()
    
    def mobsf(self):
        return self.exploit_tools.mobsf()
    
    def frida(self):
        return self.exploit_tools.frida()
    
    def objection(self):
        return self.exploit_tools.objection()
    
    def enum4linux_ng(self):
        return self.network_tools.enum4linux_ng()
    
    def smbmap(self):
        return self.network_tools.smbmap()
    
    def rpcclient(self):
        return self.network_tools.rpcclient()
    
    def ldapsearch(self):
        return self.network_tools.ldapsearch()
    
    def snmpwalk(self):
        return self.network_tools.snmpwalk()
    
    def responder(self):
        return self.network_tools.responder()
    
    def impacket(self):
        return self.network_tools.impacket()
    
    def bloodhound(self):
        return self.network_tools.bloodhound()
    
    def crackmapexec(self):
        return self.network_tools.crackmapexec()
    
    def evil_winrm(self):
        return self.network_tools.evil_winrm()
    
    def powershell_empire(self):
        return self.exploit_tools.powershell_empire()
    
    def covenant(self):
        return self.exploit_tools.covenant()
    
    def cobalt_strike(self):
        return self.exploit_tools.cobalt_strike()
