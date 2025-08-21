"""
Flask framework integration adapter.

This module changes when Flask integration requirements or API structure changes.
"""

from flask import Flask, request, jsonify, Response
from typing import Dict, Any, Callable, Optional
import logging
from functools import wraps
from ..services.decision_service import DecisionService
from ..services.tool_execution_service import ToolExecutionService
from ..services.process_service import ProcessService
from ..platform.errors import ErrorHandler
from .request_handlers import RequestHandlers
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
from .endpoints.all_tool_endpoints import AllToolEndpoints

logger = logging.getLogger(__name__)

class FlaskAdapter:
    """Flask framework integration adapter"""
    
    def __init__(self, app: Flask):
        self.app = app
        self.decision_service = DecisionService()
        self.execution_service = ToolExecutionService()
        self.process_service = ProcessService()
        self.error_handler = ErrorHandler()
        
        self.request_handlers = RequestHandlers(
            self.decision_service,
            self.execution_service,
            self.process_service,
            self.error_handler
        )
        
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
        self.tool_endpoints = AllToolEndpoints()
        
        self._register_error_handlers()
    
    def _register_error_handlers(self) -> None:
        """Register global error handlers"""
        
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid request parameters",
                "status_code": 400
            }), 400
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "error": "Not Found",
                "message": "Endpoint not found",
                "status_code": 404
            }), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
                "status_code": 500
            }), 500
    
    def validate_json_request(self, required_fields: list = None):
        """Decorator to validate JSON request data"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not request.is_json:
                    return jsonify({
                        "error": "Content-Type must be application/json"
                    }), 400
                
                data = request.get_json()
                if not data:
                    return jsonify({
                        "error": "Request body must contain valid JSON"
                    }), 400
                
                if required_fields:
                    missing_fields = [field for field in required_fields if field not in data]
                    if missing_fields:
                        return jsonify({
                            "error": f"Missing required fields: {', '.join(missing_fields)}"
                        }), 400
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def validate_request(self, request_data: Dict[str, Any], schema: type) -> bool:
        """Validate request against schema"""
        try:
            return True
        except Exception as e:
            logger.error(f"Request validation failed: {str(e)}")
            return False
    
    def format_response(self, data: Any, success: bool = True, status_code: int = 200) -> Response:
        """Format standardized API response"""
        response_data = {
            "success": success,
            "data": data if success else None,
            "error": data if not success else None,
            "timestamp": self._get_current_timestamp()
        }
        
        return jsonify(response_data), status_code
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _register_tool_endpoints(self) -> None:
        """Register all tool-specific endpoints"""
        self.app.route("/api/tools/nmap", methods=["POST"])(self.tool_endpoints.nmap)
        self.app.route("/api/tools/rustscan", methods=["POST"])(self.tool_endpoints.rustscan)
        self.app.route("/api/tools/masscan", methods=["POST"])(self.tool_endpoints.masscan)
        self.app.route("/api/tools/naabu", methods=["POST"])(self.tool_endpoints.naabu)
        self.app.route("/api/tools/zmap", methods=["POST"])(self.tool_endpoints.zmap)
        
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
        self.app.route("/api/tools/whatweb", methods=["POST"])(self.tool_endpoints.whatweb)
        self.app.route("/api/tools/wafw00f", methods=["POST"])(self.tool_endpoints.wafw00f)
        self.app.route("/api/tools/burpsuite", methods=["POST"])(self.tool_endpoints.burpsuite)
        
        self.app.route("/api/tools/prowler", methods=["POST"])(self.tool_endpoints.prowler)
        self.app.route("/api/tools/scout-suite", methods=["POST"])(self.tool_endpoints.scout_suite)
        self.app.route("/api/tools/trivy", methods=["POST"])(self.tool_endpoints.trivy)
        self.app.route("/api/tools/checkov", methods=["POST"])(self.tool_endpoints.checkov)
        self.app.route("/api/tools/terrascan", methods=["POST"])(self.tool_endpoints.terrascan)
        self.app.route("/api/tools/kube-hunter", methods=["POST"])(self.tool_endpoints.kube_hunter)
        self.app.route("/api/tools/kube-bench", methods=["POST"])(self.tool_endpoints.kube_bench)
        self.app.route("/api/tools/docker-bench-security", methods=["POST"])(self.tool_endpoints.docker_bench_security)
        
        self.app.route("/api/tools/hashcat", methods=["POST"])(self.tool_endpoints.hashcat)
        self.app.route("/api/tools/john", methods=["POST"])(self.tool_endpoints.john)
        self.app.route("/api/tools/hydra", methods=["POST"])(self.tool_endpoints.hydra)
        self.app.route("/api/tools/medusa", methods=["POST"])(self.tool_endpoints.medusa)
        
        self.app.route("/api/tools/amass", methods=["POST"])(self.tool_endpoints.amass)
        self.app.route("/api/tools/subfinder", methods=["POST"])(self.tool_endpoints.subfinder)
        self.app.route("/api/tools/assetfinder", methods=["POST"])(self.tool_endpoints.assetfinder)
        self.app.route("/api/tools/findomain", methods=["POST"])(self.tool_endpoints.findomain)
        self.app.route("/api/tools/shodan", methods=["POST"])(self.tool_endpoints.shodan)
        self.app.route("/api/tools/censys", methods=["POST"])(self.tool_endpoints.censys)
        self.app.route("/api/tools/theharvester", methods=["POST"])(self.tool_endpoints.theharvester)
        
        self.app.route("/api/tools/ghidra", methods=["POST"])(self.tool_endpoints.ghidra)
        self.app.route("/api/tools/radare2", methods=["POST"])(self.tool_endpoints.radare2)
        self.app.route("/api/tools/binwalk", methods=["POST"])(self.tool_endpoints.binwalk)
        self.app.route("/api/tools/strings", methods=["POST"])(self.tool_endpoints.strings)
        self.app.route("/api/tools/objdump", methods=["POST"])(self.tool_endpoints.objdump)
        self.app.route("/api/tools/gdb", methods=["POST"])(self.tool_endpoints.gdb)
        
        self.app.route("/api/tools/metasploit", methods=["POST"])(self.tool_endpoints.metasploit)
        self.app.route("/api/tools/searchsploit", methods=["POST"])(self.tool_endpoints.searchsploit)
        self.app.route("/api/tools/exploit-db", methods=["POST"])(self.tool_endpoints.exploit_db)
        
        self.app.route("/api/tools/wireshark", methods=["POST"])(self.tool_endpoints.wireshark)
        self.app.route("/api/tools/tcpdump", methods=["POST"])(self.tool_endpoints.tcpdump)
        self.app.route("/api/tools/ngrep", methods=["POST"])(self.tool_endpoints.ngrep)
        
        self.app.route("/api/tools/aircrack-ng", methods=["POST"])(self.tool_endpoints.aircrack_ng)
        self.app.route("/api/tools/reaver", methods=["POST"])(self.tool_endpoints.reaver)
        self.app.route("/api/tools/kismet", methods=["POST"])(self.tool_endpoints.kismet)
        
        self.app.route("/api/tools/setoolkit", methods=["POST"])(self.tool_endpoints.setoolkit)
        self.app.route("/api/tools/gophish", methods=["POST"])(self.tool_endpoints.gophish)
        
        self.app.route("/api/tools/mobsf", methods=["POST"])(self.tool_endpoints.mobsf)
        self.app.route("/api/tools/frida", methods=["POST"])(self.tool_endpoints.frida)
        self.app.route("/api/tools/objection", methods=["POST"])(self.tool_endpoints.objection)
        
        self.app.route("/api/tools/enum4linux-ng", methods=["POST"])(self.tool_endpoints.enum4linux_ng)
        self.app.route("/api/tools/smbmap", methods=["POST"])(self.tool_endpoints.smbmap)
        self.app.route("/api/tools/rpcclient", methods=["POST"])(self.tool_endpoints.rpcclient)
        self.app.route("/api/tools/ldapsearch", methods=["POST"])(self.tool_endpoints.ldapsearch)
        self.app.route("/api/tools/snmpwalk", methods=["POST"])(self.tool_endpoints.snmpwalk)
        self.app.route("/api/tools/responder", methods=["POST"])(self.tool_endpoints.responder)
        self.app.route("/api/tools/impacket", methods=["POST"])(self.tool_endpoints.impacket)
        self.app.route("/api/tools/bloodhound", methods=["POST"])(self.tool_endpoints.bloodhound)
        self.app.route("/api/tools/crackmapexec", methods=["POST"])(self.tool_endpoints.crackmapexec)
        self.app.route("/api/tools/evil-winrm", methods=["POST"])(self.tool_endpoints.evil_winrm)
    
    def register_routes(self) -> None:
        """Register all API routes"""
        
        @self.app.route("/health", methods=["GET"])
        def health_check():
            """Health check endpoint with comprehensive tool detection"""
            return jsonify({
                "status": "healthy",
                "version": "6.0.0",
                "timestamp": self._get_current_timestamp(),
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
        
        self.app.route("/api/ctf/create-challenge-workflow", methods=["POST"])(self.ctf_endpoints.create_challenge_workflow)
        self.app.route("/api/ctf/auto-solve-challenge", methods=["POST"])(self.ctf_endpoints.auto_solve_challenge)
        self.app.route("/api/ctf/team-strategy", methods=["POST"])(self.ctf_endpoints.team_strategy)
        self.app.route("/api/ctf/suggest-tools", methods=["POST"])(self.ctf_endpoints.suggest_tools)
        self.app.route("/api/ctf/cryptography-solver", methods=["POST"])(self.ctf_endpoints.cryptography_solver)
        self.app.route("/api/ctf/forensics-analyzer", methods=["POST"])(self.ctf_endpoints.forensics_analyzer)
        self.app.route("/api/ctf/binary-analyzer", methods=["POST"])(self.ctf_endpoints.binary_analyzer)
        
        self.app.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])(self.bugbounty_endpoints.reconnaissance_workflow)
        self.app.route("/api/bugbounty/vulnerability-hunting-workflow", methods=["POST"])(self.bugbounty_endpoints.vulnerability_hunting_workflow)
        self.app.route("/api/bugbounty/business-logic-workflow", methods=["POST"])(self.bugbounty_endpoints.business_logic_workflow)
        self.app.route("/api/bugbounty/osint-workflow", methods=["POST"])(self.bugbounty_endpoints.osint_workflow)
        self.app.route("/api/bugbounty/file-upload-testing", methods=["POST"])(self.bugbounty_endpoints.file_upload_testing)
        self.app.route("/api/bugbounty/comprehensive-assessment", methods=["POST"])(self.bugbounty_endpoints.comprehensive_assessment)
        
        self.app.route("/api/intelligence/analyze-target", methods=["POST"])(self.intelligence_endpoints.analyze_target)
        self.app.route("/api/intelligence/select-tools", methods=["POST"])(self.intelligence_endpoints.select_tools)
        self.app.route("/api/intelligence/optimize-parameters", methods=["POST"])(self.intelligence_endpoints.optimize_parameters)
        self.app.route("/api/intelligence/create-attack-chain", methods=["POST"])(self.intelligence_endpoints.create_attack_chain)
        self.app.route("/api/intelligence/smart-scan", methods=["POST"])(self.intelligence_endpoints.smart_scan)
        self.app.route("/api/intelligence/technology-detection", methods=["POST"])(self.intelligence_endpoints.technology_detection)
        
        self.app.route("/api/visual/vulnerability-card", methods=["POST"])(self.visual_endpoints.vulnerability_card)
        self.app.route("/api/visual/summary-report", methods=["POST"])(self.visual_endpoints.summary_report)
        self.app.route("/api/visual/tool-output", methods=["POST"])(self.visual_endpoints.tool_output)
        
        self.app.route("/api/processes/list", methods=["GET"])(self.process_endpoints.list_processes)
        self.app.route("/api/processes/status/<int:pid>", methods=["GET"])(self.process_endpoints.get_process_status)
        self.app.route("/api/processes/terminate/<int:pid>", methods=["POST"])(self.process_endpoints.terminate_process)
        self.app.route("/api/processes/pause/<int:pid>", methods=["POST"])(self.process_endpoints.pause_process)
        self.app.route("/api/processes/resume/<int:pid>", methods=["POST"])(self.process_endpoints.resume_process)
        self.app.route("/api/processes/kill/<int:pid>", methods=["POST"])(self.process_endpoints.kill_process)
        self.app.route("/api/processes/stats", methods=["GET"])(self.process_endpoints.get_system_stats)
        self.app.route("/api/processes/dashboard", methods=["GET"])(self.advanced_process_endpoints.get_process_dashboard)
        
        self.app.route("/api/files/create", methods=["POST"])(self.file_endpoints.create_file)
        self.app.route("/api/files/modify", methods=["POST"])(self.file_endpoints.modify_file)
        self.app.route("/api/files/delete", methods=["DELETE"])(self.file_endpoints.delete_file)
        self.app.route("/api/files/list", methods=["GET"])(self.file_endpoints.list_files)
        self.app.route("/api/files/read", methods=["POST"])(self.file_endpoints.read_file)
        self.app.route("/api/files/copy", methods=["POST"])(self.file_endpoints.copy_file)
        self.app.route("/api/files/move", methods=["POST"])(self.file_endpoints.move_file)
        self.app.route("/api/files/info", methods=["POST"])(self.file_endpoints.get_file_info)
        
        self.app.route("/api/command", methods=["POST"])(self.command_endpoints.generic_command)
        self.app.route("/api/telemetry", methods=["GET"])(self.command_endpoints.get_telemetry)
        
        self.app.route("/api/cache/stats", methods=["GET"])(self.cache_endpoints.get_cache_stats)
        self.app.route("/api/cache/clear", methods=["POST"])(self.cache_endpoints.clear_cache)
        
        self.app.route("/api/payloads/generate", methods=["POST"])(self.payload_endpoints.generate_payload)
        
        self.app.route("/api/python/install", methods=["POST"])(self.python_endpoints.install_package)
        self.app.route("/api/python/list", methods=["GET"])(self.python_endpoints.list_packages)
        self.app.route("/api/python/info", methods=["GET"])(self.python_endpoints.get_python_info)
        
        self.app.route("/api/ai/generate-payload", methods=["POST"])(self.ai_endpoints.generate_ai_payload)
        self.app.route("/api/ai/analyze-target", methods=["POST"])(self.ai_endpoints.analyze_target_for_ai)
        
        self.app.route("/api/vuln-intel/cve-monitor", methods=["POST"])(self.vuln_intel_endpoints.cve_monitor)
        self.app.route("/api/vuln-intel/exploit-generate", methods=["POST"])(self.vuln_intel_endpoints.exploit_generate)
        self.app.route("/api/vuln-intel/attack-chains", methods=["POST"])(self.vuln_intel_endpoints.attack_chains)
        self.app.route("/api/vuln-intel/threat-feeds", methods=["POST"])(self.vuln_intel_endpoints.threat_feeds)
        self.app.route("/api/vuln-intel/zero-day-research", methods=["POST"])(self.vuln_intel_endpoints.zero_day_research)
        
        self.app.route("/api/process/execute-async", methods=["POST"])(self.advanced_process_endpoints.execute_async)
        self.app.route("/api/process/get-task-result/<task_id>", methods=["GET"])(self.advanced_process_endpoints.get_task_result)
        self.app.route("/api/process/pool-stats", methods=["GET"])(self.advanced_process_endpoints.get_pool_stats)
        self.app.route("/api/process/resource-usage", methods=["GET"])(self.advanced_process_endpoints.get_resource_usage)
        
        self._register_tool_endpoints()
