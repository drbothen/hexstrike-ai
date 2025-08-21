"""
Central tool repository and metadata management.

This module changes when tool definitions, capabilities, or metadata change.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging
from ..domain.target_analysis import TargetType
from ..platform.constants import DEFAULT_TIMEOUTS, DEFAULT_THREADS, TOOL_CATEGORIES

logger = logging.getLogger(__name__)

class ToolCategory(Enum):
    """Tool category enumeration"""
    NETWORK_DISCOVERY = "network_discovery"
    WEB_DISCOVERY = "web_discovery"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    PARAMETER_DISCOVERY = "parameter_discovery"
    PASSWORD_ATTACKS = "password_attacks"
    CLOUD_SECURITY = "cloud_security"
    BINARY_ANALYSIS = "binary_analysis"
    FORENSICS = "forensics"
    OSINT = "osint"

@dataclass
class ParameterSpec:
    """Parameter validation specification"""
    name: str
    type: str
    required: bool
    default: Optional[Any] = None
    validation_rules: List[str] = field(default_factory=list)
    description: str = ""

@dataclass
class ToolDefinition:
    """Tool metadata and configuration"""
    name: str
    category: ToolCategory
    command_template: str
    parameters: Dict[str, ParameterSpec]
    effectiveness: Dict[str, float]
    alternatives: List[str] = field(default_factory=list)
    timeout: int = 300
    requires_privileges: bool = False
    supported_platforms: List[str] = field(default_factory=lambda: ["linux"])
    description: str = ""
    version_command: str = "--version"
    installation_notes: str = ""

class ToolRegistry:
    """Central tool repository"""
    
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self.categories: Dict[ToolCategory, List[str]] = {}
        self._initialize_default_tools()
    
    def _initialize_default_tools(self) -> None:
        """Initialize default tool definitions"""
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self.register_tool(ToolDefinition(
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
        ))
        
        self._update_categories()
    
    def register_tool(self, tool_def: ToolDefinition) -> None:
        """Register a new tool definition"""
        self.tools[tool_def.name] = tool_def
        self._update_categories()
        logger.info(f"Registered tool: {tool_def.name}")
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """Get tool definition by name"""
        return self.tools.get(name)
    
    def get_tools_by_category(self, category: ToolCategory) -> List[ToolDefinition]:
        """Get all tools in a category"""
        return [self.tools[name] for name in self.categories.get(category, [])]
    
    def get_tools_by_target_type(self, target_type: TargetType) -> List[ToolDefinition]:
        """Get tools effective for target type"""
        effective_tools = []
        target_type_str = target_type.value
        
        for tool_def in self.tools.values():
            effectiveness = tool_def.effectiveness.get(target_type_str, 0.0)
            if effectiveness > 0.5:  # Only include tools with >50% effectiveness
                effective_tools.append(tool_def)
        
        effective_tools.sort(key=lambda t: t.effectiveness.get(target_type_str, 0.0), reverse=True)
        return effective_tools
    
    def update_tool_effectiveness(self, tool_name: str, effectiveness: Dict[str, float]) -> None:
        """Update tool effectiveness scores"""
        if tool_name in self.tools:
            self.tools[tool_name].effectiveness.update(effectiveness)
            logger.info(f"Updated effectiveness for {tool_name}")
        else:
            logger.warning(f"Tool {tool_name} not found for effectiveness update")
    
    def get_tool_alternatives(self, tool_name: str) -> List[str]:
        """Get alternative tools for a given tool"""
        tool_def = self.get_tool(tool_name)
        if tool_def:
            return tool_def.alternatives
        return []
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if tool is available in registry"""
        return tool_name in self.tools
    
    def get_all_tools(self) -> List[ToolDefinition]:
        """Get all registered tools"""
        return list(self.tools.values())
    
    def get_tool_names(self) -> List[str]:
        """Get all tool names"""
        return list(self.tools.keys())
    
    def get_categories(self) -> List[ToolCategory]:
        """Get all available categories"""
        return list(self.categories.keys())
    
    def search_tools(self, query: str) -> List[ToolDefinition]:
        """Search tools by name or description"""
        query_lower = query.lower()
        matching_tools = []
        
        for tool_def in self.tools.values():
            if (query_lower in tool_def.name.lower() or 
                query_lower in tool_def.description.lower()):
                matching_tools.append(tool_def)
        
        return matching_tools
    
    def validate_tool_parameters(self, tool_name: str, params: Dict[str, Any]) -> List[str]:
        """Validate parameters for a tool"""
        errors = []
        tool_def = self.get_tool(tool_name)
        
        if not tool_def:
            errors.append(f"Tool {tool_name} not found in registry")
            return errors
        
        for param_name, param_spec in tool_def.parameters.items():
            if param_spec.required and param_name not in params:
                errors.append(f"Required parameter '{param_name}' missing")
        
        for param_name, value in params.items():
            if param_name in tool_def.parameters:
                param_spec = tool_def.parameters[param_name]
                
                if param_spec.type == "int" and not isinstance(value, int):
                    try:
                        int(value)
                    except (ValueError, TypeError):
                        errors.append(f"Parameter '{param_name}' must be an integer")
                
                elif param_spec.type == "bool" and not isinstance(value, bool):
                    if str(value).lower() not in ["true", "false", "1", "0"]:
                        errors.append(f"Parameter '{param_name}' must be a boolean")
                
                for rule in param_spec.validation_rules:
                    if isinstance(rule, list) and value not in rule:
                        errors.append(f"Parameter '{param_name}' must be one of: {rule}")
        
        return errors
    
    def get_tool_command_template(self, tool_name: str) -> Optional[str]:
        """Get command template for a tool"""
        tool_def = self.get_tool(tool_name)
        return tool_def.command_template if tool_def else None
    
    def _update_categories(self) -> None:
        """Update categories mapping"""
        self.categories.clear()
        
        for tool_def in self.tools.values():
            if tool_def.category not in self.categories:
                self.categories[tool_def.category] = []
            self.categories[tool_def.category].append(tool_def.name)
