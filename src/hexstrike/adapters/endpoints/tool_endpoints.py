"""
Tool-specific endpoint handlers for all security tools.

This module changes when new tools are added or tool APIs change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from .tool_endpoints_web import WebToolEndpoints
from .tool_endpoints_network import NetworkToolEndpoints
from .tool_endpoints_binary import BinaryToolEndpoints
from .tool_endpoints_crypto import CryptoToolEndpoints
from .tool_endpoints_cloud import CloudToolEndpoints
from .tool_endpoints_utility import UtilityToolEndpoints

logger = logging.getLogger(__name__)

class ToolEndpoints:
    """Centralized tool endpoint handlers that delegates to specialized handlers"""
    
    def __init__(self):
        self.web_tools = WebToolEndpoints()
        self.network_tools = NetworkToolEndpoints()
        self.binary_tools = BinaryToolEndpoints()
        self.crypto_tools = CryptoToolEndpoints()
        self.cloud_tools = CloudToolEndpoints()
        self.utility_tools = UtilityToolEndpoints()
    
    def nmap(self):
        return self.network_tools.nmap()
    
    def nuclei(self):
        return self.web_tools.nuclei()
    
    def gobuster(self):
        return self.web_tools.gobuster()
    
    def sqlmap(self):
        return self.web_tools.sqlmap()
    
    def nikto(self):
        return self.web_tools.nikto()
    
    def ffuf(self):
        return self.web_tools.ffuf()
    
    def hydra(self):
        return self.crypto_tools.hydra()
    
    def john(self):
        return self.crypto_tools.john()
    
    def wpscan(self):
        return self.web_tools.wpscan()
    
    def enum4linux(self):
        return self.network_tools.enum4linux()
    
    def netexec(self):
        return self.network_tools.netexec()
    
    def amass(self):
        return self.network_tools.amass()
    
    def hashcat(self):
        return self.crypto_tools.hashcat()
    
    def subfinder(self):
        return self.network_tools.subfinder()
    
    def smbmap(self):
        return self.network_tools.smbmap()
    
    def rustscan(self):
        return self.network_tools.rustscan()
    
    def masscan(self):
        return self.network_tools.masscan()
    
    def nmap_advanced(self):
        return self.network_tools.nmap_advanced()
    
    def autorecon(self):
        return self.network_tools.autorecon()
    
    def enum4linux_ng(self):
        return self.network_tools.enum4linux_ng()
    
    def rpcclient(self):
        return self.network_tools.rpcclient()
    
    def nbtscan(self):
        return self.network_tools.nbtscan()
    
    def arp_scan(self):
        return self.network_tools.arp_scan()
    
    def responder(self):
        return self.network_tools.responder()
    
    def volatility(self):
        return self.binary_tools.volatility()
    
    def msfvenom(self):
        return self.binary_tools.msfvenom()
    
    def gdb(self):
        return self.binary_tools.gdb()
    
    def radare2(self):
        return self.binary_tools.radare2()
    
    def binwalk(self):
        return self.binary_tools.binwalk()
    
    def ropgadget(self):
        return self.binary_tools.ropgadget()
    
    def checksec(self):
        return self.binary_tools.checksec()
    
    def xxd(self):
        return self.binary_tools.xxd()
    
    def strings(self):
        return self.binary_tools.strings()
    
    def objdump(self):
        return self.binary_tools.objdump()
    
    def ghidra(self):
        return self.binary_tools.ghidra()
    
    def pwntools(self):
        return self.binary_tools.pwntools()
    
    def one_gadget(self):
        return self.binary_tools.one_gadget()
    
    def libc_database(self):
        return self.binary_tools.libc_database()
    
    def gdb_peda(self):
        return self.binary_tools.gdb_peda()
    
    def angr(self):
        return self.binary_tools.angr()
    
    def ropper(self):
        return self.binary_tools.ropper()
    
    def pwninit(self):
        return self.binary_tools.pwninit()
    
    def feroxbuster(self):
        return self.web_tools.feroxbuster()
    
    def dotdotpwn(self):
        return self.web_tools.dotdotpwn()
    
    def xsser(self):
        return self.web_tools.xsser()
    
    def wfuzz(self):
        return self.web_tools.wfuzz()
    
    def dirsearch(self):
        return self.web_tools.dirsearch()
    
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
    
    def x8(self):
        return self.web_tools.x8()
    
    def jaeles(self):
        return self.web_tools.jaeles()
    
    def dalfox(self):
        return self.web_tools.dalfox()
    
    def httpx(self):
        return self.web_tools.httpx()
    
    def anew(self):
        return self.utility_tools.anew()
    
    def qsreplace(self):
        return self.utility_tools.qsreplace()
    
    def uro(self):
        return self.utility_tools.uro()
    
    def zap(self):
        return self.web_tools.zap()
    
    def wafw00f(self):
        return self.web_tools.wafw00f()
    
    def fierce(self):
        return self.network_tools.fierce()
    
    def dnsenum(self):
        return self.network_tools.dnsenum()
    
    def volatility3(self):
        return self.binary_tools.volatility3()
    
    def foremost(self):
        return self.binary_tools.foremost()
    
    def steghide(self):
        return self.binary_tools.steghide()
    
    def exiftool(self):
        return self.binary_tools.exiftool()
    
    def hashpump(self):
        return self.crypto_tools.hashpump()
    
    def hakrawler(self):
        return self.web_tools.hakrawler()
    
    def trivy(self):
        return self.cloud_tools.trivy()
    
    def prowler(self):
        return self.cloud_tools.prowler()
    
    def scout_suite(self):
        return self.cloud_tools.scout_suite()
    
    def kube_hunter(self):
        return self.cloud_tools.kube_hunter()
    
    def kube_bench(self):
        return self.cloud_tools.kube_bench()
    
    def checkov(self):
        return self.cloud_tools.checkov()
    
    def terrascan(self):
        return self.cloud_tools.terrascan()
