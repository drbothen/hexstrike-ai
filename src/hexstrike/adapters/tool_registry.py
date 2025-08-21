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
        from .tool_definitions import get_default_tool_definitions
        
        default_tools = get_default_tool_definitions()
        for tool_def in default_tools.values():
            self.register_tool(tool_def)
        
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
