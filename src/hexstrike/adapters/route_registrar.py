"""
Route registration for Flask adapter.

This module handles the registration of routes for the Flask adapter.
"""

from flask import Flask, jsonify
from typing import Dict, Any
import logging
from .endpoints.ctf_endpoints import CTFEndpoints
from .endpoints.bugbounty_endpoints import BugBountyEndpoints
from .endpoints.intelligence_endpoints import IntelligenceEndpoints
from .endpoints.visual_endpoints import VisualEndpoints
from .endpoints.process_endpoints import ProcessEndpoints
from .endpoints.file_endpoints import FileEndpoints
from .endpoints.health_endpoints import HealthEndpoints
from .endpoints.command_endpoints import CommandEndpoints
from .endpoints.cache_endpoints import CacheEndpoints
from .endpoints.payload_endpoints import PayloadEndpoints
from .endpoints.python_endpoints import PythonEndpoints
from .endpoints.ai_endpoints import AIEndpoints
from .endpoints.vuln_intel_endpoints import VulnIntelEndpoints
from .endpoints.advanced_process_endpoints import AdvancedProcessEndpoints
from .endpoints.tool_endpoints import ToolEndpoints

logger = logging.getLogger(__name__)

class RouteRegistrar:
    """Handles registration of routes for Flask adapter"""
    
    def __init__(self, app: Flask, get_timestamp_func):
        self.app = app
        self.get_timestamp = get_timestamp_func
        
        self.ctf_endpoints = CTFEndpoints()
        self.bugbounty_endpoints = BugBountyEndpoints()
        self.intelligence_endpoints = IntelligenceEndpoints()
        self.visual_endpoints = VisualEndpoints()
        self.process_endpoints = ProcessEndpoints()
        self.file_endpoints = FileEndpoints()
        self.health_endpoints = HealthEndpoints()
        self.command_endpoints = CommandEndpoints()
        self.cache_endpoints = CacheEndpoints()
        self.payload_endpoints = PayloadEndpoints()
        self.python_endpoints = PythonEndpoints()
        self.ai_endpoints = AIEndpoints()
        self.vuln_intel_endpoints = VulnIntelEndpoints()
        self.advanced_process_endpoints = AdvancedProcessEndpoints()
        self.tool_endpoints = ToolEndpoints()
    
    def register_health_endpoint(self):
        """Register health check endpoint"""
        
        @self.app.route("/health", methods=["GET"])
        def health_check():
            """Health check endpoint with comprehensive tool detection"""
            return jsonify({
                "status": "healthy",
                "version": "6.0.0",
                "timestamp": self.get_timestamp(),
                "endpoints_available": 156,
                "modular_architecture": True,
                "services": {
                    "decision_service": "active",
                    "execution_service": "active",
                    "process_service": "active",
                    "ctf_service": "active",
                    "bugbounty_service": "active",
                    "intelligence_service": "active",
                    "visual_service": "active"
                }
            })
    
    def register_ctf_endpoints(self):
        """Register CTF endpoints"""
        self.app.route("/api/ctf/create-challenge-workflow", methods=["POST"])(self.ctf_endpoints.create_challenge_workflow)
        self.app.route("/api/ctf/auto-solve-challenge", methods=["POST"])(self.ctf_endpoints.auto_solve_challenge)
        self.app.route("/api/ctf/team-strategy", methods=["POST"])(self.ctf_endpoints.create_team_strategy)
        self.app.route("/api/ctf/suggest-tools", methods=["POST"])(self.ctf_endpoints.suggest_tools)
        self.app.route("/api/ctf/cryptography-solver", methods=["POST"])(self.ctf_endpoints.cryptography_solver)
        self.app.route("/api/ctf/forensics-analyzer", methods=["POST"])(self.ctf_endpoints.forensics_analyzer)
        self.app.route("/api/ctf/binary-analyzer", methods=["POST"])(self.ctf_endpoints.binary_analyzer)
    
    def register_bugbounty_endpoints(self):
        """Register bug bounty endpoints"""
        self.app.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])(self.bugbounty_endpoints.reconnaissance_workflow)
        self.app.route("/api/bugbounty/vulnerability-hunting-workflow", methods=["POST"])(self.bugbounty_endpoints.vulnerability_hunting_workflow)
        self.app.route("/api/bugbounty/business-logic-workflow", methods=["POST"])(self.bugbounty_endpoints.business_logic_workflow)
        self.app.route("/api/bugbounty/osint-workflow", methods=["POST"])(self.bugbounty_endpoints.osint_workflow)
        self.app.route("/api/bugbounty/prioritize-vulnerabilities", methods=["POST"])(self.bugbounty_endpoints.prioritize_vulnerabilities)
        self.app.route("/api/bugbounty/suggest-next-steps", methods=["POST"])(self.bugbounty_endpoints.suggest_next_steps)
        self.app.route("/api/bugbounty/estimate-bounty-potential", methods=["POST"])(self.bugbounty_endpoints.estimate_bounty_potential)
    
    def register_intelligence_endpoints(self):
        """Register intelligence endpoints"""
        self.app.route("/api/intelligence/analyze-target", methods=["POST"])(self.intelligence_endpoints.analyze_target)
        self.app.route("/api/intelligence/select-tools", methods=["POST"])(self.intelligence_endpoints.select_tools)
        self.app.route("/api/intelligence/optimize-parameters", methods=["POST"])(self.intelligence_endpoints.optimize_parameters)
        self.app.route("/api/intelligence/create-attack-chain", methods=["POST"])(self.intelligence_endpoints.create_attack_chain)
        self.app.route("/api/intelligence/smart-scan", methods=["POST"])(self.intelligence_endpoints.smart_scan)
        self.app.route("/api/intelligence/technology-detection", methods=["POST"])(self.intelligence_endpoints.technology_detection)
        self.app.route("/api/intelligence/tool-effectiveness-stats", methods=["POST"])(self.intelligence_endpoints.tool_effectiveness_stats)
    
    def register_visual_endpoints(self):
        """Register visual endpoints"""
        self.app.route("/api/visual/vulnerability-card", methods=["POST"])(self.visual_endpoints.vulnerability_card)
        self.app.route("/api/visual/summary-report", methods=["POST"])(self.visual_endpoints.summary_report)
        self.app.route("/api/visual/tool-output", methods=["POST"])(self.visual_endpoints.tool_output)
        self.app.route("/api/visual/progress-dashboard", methods=["POST"])(self.visual_endpoints.progress_dashboard)
        self.app.route("/api/visual/error-card", methods=["POST"])(self.visual_endpoints.error_card)
        self.app.route("/api/visual/banner", methods=["GET"])(self.visual_endpoints.banner)
    
    def register_process_endpoints(self):
        """Register process endpoints"""
        self.app.route("/api/processes/list", methods=["GET"])(self.process_endpoints.list_processes)
        self.app.route("/api/processes/status/<int:pid>", methods=["GET"])(self.process_endpoints.get_process_status)
        self.app.route("/api/processes/terminate/<int:pid>", methods=["POST"])(self.process_endpoints.terminate_process)
        self.app.route("/api/processes/pause/<int:pid>", methods=["POST"])(self.process_endpoints.pause_process)
        self.app.route("/api/processes/resume/<int:pid>", methods=["POST"])(self.process_endpoints.resume_process)
        self.app.route("/api/processes/kill/<int:pid>", methods=["POST"])(self.process_endpoints.kill_process)
        self.app.route("/api/processes/stats", methods=["GET"])(self.process_endpoints.get_system_stats)
        self.app.route("/api/processes/dashboard", methods=["GET"])(self.advanced_process_endpoints.get_process_dashboard)
    
    def register_file_endpoints(self):
        """Register file endpoints"""
        self.app.route("/api/files/create", methods=["POST"])(self.file_endpoints.create_file)
        self.app.route("/api/files/modify", methods=["POST"])(self.file_endpoints.modify_file)
        self.app.route("/api/files/delete", methods=["DELETE"])(self.file_endpoints.delete_file)
        self.app.route("/api/files/list", methods=["GET"])(self.file_endpoints.list_files)
        self.app.route("/api/files/read", methods=["POST"])(self.file_endpoints.read_file)
        self.app.route("/api/files/copy", methods=["POST"])(self.file_endpoints.copy_file)
        self.app.route("/api/files/move", methods=["POST"])(self.file_endpoints.move_file)
        self.app.route("/api/files/info", methods=["POST"])(self.file_endpoints.get_file_info)
    
    def register_command_endpoints(self):
        """Register command endpoints"""
        self.app.route("/api/command", methods=["POST"])(self.command_endpoints.generic_command)
        self.app.route("/api/telemetry", methods=["GET"])(self.command_endpoints.get_telemetry)
    
    def register_cache_endpoints(self):
        """Register cache endpoints"""
        self.app.route("/api/cache/stats", methods=["GET"])(self.cache_endpoints.get_cache_stats)
        self.app.route("/api/cache/clear", methods=["POST"])(self.cache_endpoints.clear_cache)
    
    def register_payload_endpoints(self):
        """Register payload endpoints"""
        self.app.route("/api/payloads/generate", methods=["POST"])(self.payload_endpoints.generate_payload)
    
    def register_python_endpoints(self):
        """Register Python endpoints"""
        self.app.route("/api/python/install", methods=["POST"])(self.python_endpoints.install_package)
        self.app.route("/api/python/list", methods=["GET"])(self.python_endpoints.list_packages)
        self.app.route("/api/python/info", methods=["GET"])(self.python_endpoints.get_python_info)
    
    def register_ai_endpoints(self):
        """Register AI endpoints"""
        self.app.route("/api/ai/generate-payload", methods=["POST"])(self.ai_endpoints.generate_ai_payload)
        self.app.route("/api/ai/analyze-target", methods=["POST"])(self.ai_endpoints.analyze_target_for_ai)
    
    def register_vuln_intel_endpoints(self):
        """Register vulnerability intelligence endpoints"""
        self.app.route("/api/vuln-intel/cve-monitor", methods=["POST"])(self.vuln_intel_endpoints.cve_monitor)
        self.app.route("/api/vuln-intel/exploit-generate", methods=["POST"])(self.vuln_intel_endpoints.exploit_generate)
        self.app.route("/api/vuln-intel/attack-chains", methods=["POST"])(self.vuln_intel_endpoints.attack_chains)
        self.app.route("/api/vuln-intel/threat-feeds", methods=["POST"])(self.vuln_intel_endpoints.threat_feeds)
        self.app.route("/api/vuln-intel/zero-day-research", methods=["POST"])(self.vuln_intel_endpoints.zero_day_research)
    
    def register_advanced_process_endpoints(self):
        """Register advanced process endpoints"""
        self.app.route("/api/process/execute-async", methods=["POST"])(self.advanced_process_endpoints.execute_async)
        self.app.route("/api/process/get-task-result/<task_id>", methods=["GET"])(self.advanced_process_endpoints.get_task_result)
        self.app.route("/api/process/pool-stats", methods=["GET"])(self.advanced_process_endpoints.get_pool_stats)
        self.app.route("/api/process/resource-usage", methods=["GET"])(self.advanced_process_endpoints.get_resource_usage)
    
    def register_all_routes(self):
        """Register all routes"""
        self.register_health_endpoint()
        self.register_ctf_endpoints()
        self.register_bugbounty_endpoints()
        self.register_intelligence_endpoints()
        self.register_visual_endpoints()
        self.register_process_endpoints()
        self.register_file_endpoints()
        self.register_command_endpoints()
        self.register_cache_endpoints()
        self.register_payload_endpoints()
        self.register_python_endpoints()
        self.register_ai_endpoints()
        self.register_vuln_intel_endpoints()
        self.register_advanced_process_endpoints()
        self.register_tool_endpoints()
    
    def register_tool_endpoints(self):
        """Register all tool-specific endpoints"""
        self.app.route("/api/tools/nmap", methods=["POST"])(self.tool_endpoints.nmap)
        self.app.route("/api/tools/rustscan", methods=["POST"])(self.tool_endpoints.rustscan)
        self.app.route("/api/tools/masscan", methods=["POST"])(self.tool_endpoints.masscan)
        self.app.route("/api/tools/nmap-advanced", methods=["POST"])(self.tool_endpoints.nmap_advanced)
        
        self.app.route("/api/tools/gobuster", methods=["POST"])(self.tool_endpoints.gobuster)
        self.app.route("/api/tools/dirsearch", methods=["POST"])(self.tool_endpoints.dirsearch)
        self.app.route("/api/tools/feroxbuster", methods=["POST"])(self.tool_endpoints.feroxbuster)
        self.app.route("/api/tools/ffuf", methods=["POST"])(self.tool_endpoints.ffuf)
        self.app.route("/api/tools/nuclei", methods=["POST"])(self.tool_endpoints.nuclei)
        self.app.route("/api/tools/nikto", methods=["POST"])(self.tool_endpoints.nikto)
        self.app.route("/api/tools/sqlmap", methods=["POST"])(self.tool_endpoints.sqlmap)
        self.app.route("/api/tools/dalfox", methods=["POST"])(self.tool_endpoints.dalfox)
        self.app.route("/api/tools/httpx", methods=["POST"])(self.tool_endpoints.httpx)
        self.app.route("/api/tools/katana", methods=["POST"])(self.tool_endpoints.katana)
        self.app.route("/api/tools/gau", methods=["POST"])(self.tool_endpoints.gau)
        self.app.route("/api/tools/waybackurls", methods=["POST"])(self.tool_endpoints.waybackurls)
        self.app.route("/api/tools/arjun", methods=["POST"])(self.tool_endpoints.arjun)
        self.app.route("/api/tools/paramspider", methods=["POST"])(self.tool_endpoints.paramspider)
        self.app.route("/api/tools/wpscan", methods=["POST"])(self.tool_endpoints.wpscan)
        self.app.route("/api/tools/wafw00f", methods=["POST"])(self.tool_endpoints.wafw00f)
        self.app.route("/api/tools/zap", methods=["POST"])(self.tool_endpoints.zap)
        
        self.app.route("/api/tools/prowler", methods=["POST"])(self.tool_endpoints.prowler)
        self.app.route("/api/tools/scout-suite", methods=["POST"])(self.tool_endpoints.scout_suite)
        self.app.route("/api/tools/trivy", methods=["POST"])(self.tool_endpoints.trivy)
        self.app.route("/api/tools/checkov", methods=["POST"])(self.tool_endpoints.checkov)
        self.app.route("/api/tools/terrascan", methods=["POST"])(self.tool_endpoints.terrascan)
        self.app.route("/api/tools/kube-hunter", methods=["POST"])(self.tool_endpoints.kube_hunter)
        self.app.route("/api/tools/kube-bench", methods=["POST"])(self.tool_endpoints.kube_bench)
        
        self.app.route("/api/tools/hashcat", methods=["POST"])(self.tool_endpoints.hashcat)
        self.app.route("/api/tools/john", methods=["POST"])(self.tool_endpoints.john)
        self.app.route("/api/tools/hydra", methods=["POST"])(self.tool_endpoints.hydra)
        self.app.route("/api/tools/hashpump", methods=["POST"])(self.tool_endpoints.hashpump)
        
        self.app.route("/api/tools/amass", methods=["POST"])(self.tool_endpoints.amass)
        self.app.route("/api/tools/subfinder", methods=["POST"])(self.tool_endpoints.subfinder)
        self.app.route("/api/tools/fierce", methods=["POST"])(self.tool_endpoints.fierce)
        self.app.route("/api/tools/dnsenum", methods=["POST"])(self.tool_endpoints.dnsenum)
        self.app.route("/api/tools/hakrawler", methods=["POST"])(self.tool_endpoints.hakrawler)
        
        self.app.route("/api/tools/ghidra", methods=["POST"])(self.tool_endpoints.ghidra)
        self.app.route("/api/tools/radare2", methods=["POST"])(self.tool_endpoints.radare2)
        self.app.route("/api/tools/binwalk", methods=["POST"])(self.tool_endpoints.binwalk)
        self.app.route("/api/tools/strings", methods=["POST"])(self.tool_endpoints.strings)
        self.app.route("/api/tools/objdump", methods=["POST"])(self.tool_endpoints.objdump)
        self.app.route("/api/tools/gdb", methods=["POST"])(self.tool_endpoints.gdb)
        self.app.route("/api/tools/gdb-peda", methods=["POST"])(self.tool_endpoints.gdb_peda)
        self.app.route("/api/tools/angr", methods=["POST"])(self.tool_endpoints.angr)
        self.app.route("/api/tools/pwntools", methods=["POST"])(self.tool_endpoints.pwntools)
        self.app.route("/api/tools/ropgadget", methods=["POST"])(self.tool_endpoints.ropgadget)
        self.app.route("/api/tools/ropper", methods=["POST"])(self.tool_endpoints.ropper)
        self.app.route("/api/tools/checksec", methods=["POST"])(self.tool_endpoints.checksec)
        self.app.route("/api/tools/one-gadget", methods=["POST"])(self.tool_endpoints.one_gadget)
        self.app.route("/api/tools/libc-database", methods=["POST"])(self.tool_endpoints.libc_database)
        self.app.route("/api/tools/pwninit", methods=["POST"])(self.tool_endpoints.pwninit)
        self.app.route("/api/tools/xxd", methods=["POST"])(self.tool_endpoints.xxd)
        
        self.app.route("/api/tools/msfvenom", methods=["POST"])(self.tool_endpoints.msfvenom)
        self.app.route("/api/tools/volatility", methods=["POST"])(self.tool_endpoints.volatility)
        self.app.route("/api/tools/volatility3", methods=["POST"])(self.tool_endpoints.volatility3)
        
        self.app.route("/api/tools/foremost", methods=["POST"])(self.tool_endpoints.foremost)
        self.app.route("/api/tools/steghide", methods=["POST"])(self.tool_endpoints.steghide)
        self.app.route("/api/tools/exiftool", methods=["POST"])(self.tool_endpoints.exiftool)
        
        self.app.route("/api/tools/dotdotpwn", methods=["POST"])(self.tool_endpoints.dotdotpwn)
        self.app.route("/api/tools/xsser", methods=["POST"])(self.tool_endpoints.xsser)
        self.app.route("/api/tools/wfuzz", methods=["POST"])(self.tool_endpoints.wfuzz)
        
        self.app.route("/api/tools/x8", methods=["POST"])(self.tool_endpoints.x8)
        self.app.route("/api/tools/jaeles", methods=["POST"])(self.tool_endpoints.jaeles)
        
        self.app.route("/api/tools/anew", methods=["POST"])(self.tool_endpoints.anew)
        self.app.route("/api/tools/qsreplace", methods=["POST"])(self.tool_endpoints.qsreplace)
        self.app.route("/api/tools/uro", methods=["POST"])(self.tool_endpoints.uro)
        
        self.app.route("/api/tools/enum4linux-ng", methods=["POST"])(self.tool_endpoints.enum4linux_ng)
        self.app.route("/api/tools/smbmap", methods=["POST"])(self.tool_endpoints.smbmap)
        self.app.route("/api/tools/rpcclient", methods=["POST"])(self.tool_endpoints.rpcclient)
        self.app.route("/api/tools/responder", methods=["POST"])(self.tool_endpoints.responder)
        self.app.route("/api/tools/netexec", methods=["POST"])(self.tool_endpoints.netexec)
        self.app.route("/api/tools/enum4linux", methods=["POST"])(self.tool_endpoints.enum4linux)
        self.app.route("/api/tools/nbtscan", methods=["POST"])(self.tool_endpoints.nbtscan)
        self.app.route("/api/tools/arp-scan", methods=["POST"])(self.tool_endpoints.arp_scan)
        self.app.route("/api/tools/autorecon", methods=["POST"])(self.tool_endpoints.autorecon)
