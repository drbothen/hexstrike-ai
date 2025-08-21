"""
Default tool definitions and configurations.

This module changes when tool definitions or configurations change.
"""

from typing import Dict
from .tool_registry import ToolDefinition, ToolCategory, ParameterSpec
from ..platform.constants import DEFAULT_TIMEOUTS

def get_default_tool_definitions() -> Dict[str, ToolDefinition]:
    """Get all default tool definitions"""
    tools = {}
    
    tools["nmap"] = ToolDefinition(
        name="nmap",
        category=ToolCategory.NETWORK_DISCOVERY,
        command_template="nmap {scan_type} {ports} {additional_args} {target}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target host or network"),
            "scan_type": ParameterSpec("scan_type", "str", False, "-sV", description="Scan type"),
            "ports": ParameterSpec("ports", "str", False, "", description="Port specification"),
            "additional_args": ParameterSpec("additional_args", "str", False, "-T4 -Pn", description="Additional arguments")
        },
        effectiveness={
            "network_host": 0.95,
            "web_application": 0.85,
            "api_endpoint": 0.80,
            "cloud_service": 0.75
        },
        alternatives=["rustscan", "masscan"],
        timeout=DEFAULT_TIMEOUTS.get("nmap", 300),
        description="Network exploration tool and security scanner"
    )
    
    tools["rustscan"] = ToolDefinition(
        name="rustscan",
        category=ToolCategory.NETWORK_DISCOVERY,
        command_template="rustscan -a {target} -b {batch_size} -t {timeout} --ulimit {ulimit}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target host"),
            "batch_size": ParameterSpec("batch_size", "int", False, 3000, description="Batch size"),
            "timeout": ParameterSpec("timeout", "int", False, 1500, description="Timeout in ms"),
            "ulimit": ParameterSpec("ulimit", "int", False, 5000, description="Ulimit value")
        },
        effectiveness={
            "network_host": 0.90,
            "web_application": 0.75,
            "api_endpoint": 0.70
        },
        alternatives=["nmap", "masscan"],
        timeout=DEFAULT_TIMEOUTS.get("rustscan", 120),
        description="Fast port scanner"
    )
    
    tools["gobuster"] = ToolDefinition(
        name="gobuster",
        category=ToolCategory.WEB_DISCOVERY,
        command_template="gobuster {mode} -u {target} -w {wordlist} -t {threads} {extensions}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target URL"),
            "mode": ParameterSpec("mode", "str", False, "dir", ["dir", "dns", "fuzz", "vhost"], description="Scan mode"),
            "wordlist": ParameterSpec("wordlist", "str", False, "/usr/share/wordlists/dirb/common.txt", description="Wordlist path"),
            "threads": ParameterSpec("threads", "int", False, 10, description="Number of threads"),
            "extensions": ParameterSpec("extensions", "str", False, "", description="File extensions")
        },
        effectiveness={
            "web_application": 0.90,
            "api_endpoint": 0.85,
            "cloud_service": 0.70
        },
        alternatives=["feroxbuster", "dirsearch", "ffuf"],
        timeout=DEFAULT_TIMEOUTS.get("gobuster", 600),
        description="Directory/file & DNS busting tool"
    )
    
    tools["nuclei"] = ToolDefinition(
        name="nuclei",
        category=ToolCategory.VULNERABILITY_SCANNING,
        command_template="nuclei -u {target} -severity {severity} -tags {tags} -t {template} -c {concurrency}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target URL"),
            "severity": ParameterSpec("severity", "str", False, "", description="Severity filter"),
            "tags": ParameterSpec("tags", "str", False, "", description="Template tags"),
            "template": ParameterSpec("template", "str", False, "", description="Template path"),
            "concurrency": ParameterSpec("concurrency", "int", False, 25, description="Concurrent requests")
        },
        effectiveness={
            "web_application": 0.95,
            "api_endpoint": 0.90,
            "cloud_service": 0.85
        },
        alternatives=["nikto", "jaeles"],
        timeout=DEFAULT_TIMEOUTS.get("nuclei", 180),
        description="Vulnerability scanner based on templates"
    )
    
    tools["subfinder"] = ToolDefinition(
        name="subfinder",
        category=ToolCategory.SUBDOMAIN_ENUMERATION,
        command_template="subfinder -d {target} -silent",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target domain")
        },
        effectiveness={
            "web_application": 0.80,
            "api_endpoint": 0.70,
            "cloud_service": 0.75
        },
        alternatives=["amass", "assetfinder"],
        timeout=DEFAULT_TIMEOUTS.get("subfinder", 300),
        description="Subdomain discovery tool"
    )
    
    tools["amass"] = ToolDefinition(
        name="amass",
        category=ToolCategory.SUBDOMAIN_ENUMERATION,
        command_template="amass {mode} -d {target} {passive}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target domain"),
            "mode": ParameterSpec("mode", "str", False, "enum", description="Amass mode"),
            "passive": ParameterSpec("passive", "bool", False, True, description="Passive mode")
        },
        effectiveness={
            "web_application": 0.85,
            "api_endpoint": 0.75,
            "cloud_service": 0.80
        },
        alternatives=["subfinder", "assetfinder"],
        timeout=DEFAULT_TIMEOUTS.get("amass", 1800),
        description="In-depth attack surface mapping"
    )
    
    tools["hydra"] = ToolDefinition(
        name="hydra",
        category=ToolCategory.PASSWORD_ATTACKS,
        command_template="hydra -L {userlist} -P {passlist} -t {threads} {target} {service}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Target host"),
            "service": ParameterSpec("service", "str", False, "ssh", description="Service to attack"),
            "userlist": ParameterSpec("userlist", "str", False, "/usr/share/wordlists/metasploit/unix_users.txt", description="Username list"),
            "passlist": ParameterSpec("passlist", "str", False, "/usr/share/wordlists/rockyou.txt", description="Password list"),
            "threads": ParameterSpec("threads", "int", False, 16, description="Number of threads")
        },
        effectiveness={
            "network_host": 0.80,
            "web_application": 0.60,
            "cloud_service": 0.65
        },
        alternatives=["medusa", "patator"],
        timeout=DEFAULT_TIMEOUTS.get("hydra", 600),
        description="Network logon cracker"
    )
    
    tools["prowler"] = ToolDefinition(
        name="prowler",
        category=ToolCategory.CLOUD_SECURITY,
        command_template="prowler {provider} {services}",
        parameters={
            "provider": ParameterSpec("provider", "str", False, "aws", description="Cloud provider"),
            "services": ParameterSpec("services", "str", False, "", description="Services to scan")
        },
        effectiveness={
            "cloud_service": 0.95,
            "web_application": 0.30
        },
        alternatives=["scout-suite"],
        timeout=DEFAULT_TIMEOUTS.get("prowler", 1800),
        description="Cloud security assessment tool"
    )
    
    tools["ghidra"] = ToolDefinition(
        name="ghidra",
        category=ToolCategory.BINARY_ANALYSIS,
        command_template="ghidra {headless} {analyze} {import} {target}",
        parameters={
            "target": ParameterSpec("target", "str", True, description="Binary file path"),
            "headless": ParameterSpec("headless", "bool", False, True, description="Headless mode"),
            "analyze": ParameterSpec("analyze", "bool", False, True, description="Auto analyze"),
            "import": ParameterSpec("import", "bool", False, True, description="Import binary")
        },
        effectiveness={
            "binary_file": 0.95,
            "mobile_app": 0.80
        },
        alternatives=["radare2", "ida"],
        timeout=DEFAULT_TIMEOUTS.get("ghidra", 1800),
        description="Software reverse engineering framework"
    )
    
    return tools
