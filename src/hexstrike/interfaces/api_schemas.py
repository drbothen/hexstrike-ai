"""
API request and response schema definitions.

This module changes when API schema requirements or validation rules change.
"""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

class ToolCategory(Enum):
    """Tool category enumeration for API"""
    NETWORK_DISCOVERY = "network_discovery"
    WEB_DISCOVERY = "web_discovery"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    PASSWORD_ATTACKS = "password_attacks"
    CLOUD_SECURITY = "cloud_security"
    BINARY_ANALYSIS = "binary_analysis"
    FORENSICS = "forensics"

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ToolExecutionRequest:
    """Tool execution request schema"""
    tool_name: str
    parameters: Dict[str, Any]
    use_recovery: bool = True
    timeout: Optional[int] = None
    use_cache: bool = True

@dataclass
class ToolExecutionResponse:
    """Tool execution response schema"""
    success: bool
    tool_name: str
    target: str
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    parsed_output: Dict[str, Any]
    recovery_info: Optional[Dict[str, Any]]
    timestamp: str

@dataclass
class IntelligenceRequest:
    """Intelligence analysis request schema"""
    target: str
    objective: str = "comprehensive"
    max_tools: int = 10
    include_optimization: bool = True

@dataclass
class TargetProfileResponse:
    """Target profile response schema"""
    target: str
    target_type: str
    ip_addresses: List[str]
    open_ports: List[int]
    services: Dict[int, str]
    technologies: List[str]
    attack_surface_score: float
    risk_level: str
    confidence_score: float

@dataclass
class IntelligenceResponse:
    """Intelligence analysis response schema"""
    success: bool
    target: str
    target_profile: TargetProfileResponse
    selected_tools: List[str]
    optimized_tools: List[Dict[str, Any]]
    total_tools: int

@dataclass
class ProcessManagementRequest:
    """Process management request schema"""
    action: str  # list, status, terminate, pause, resume
    pid: Optional[int] = None

@dataclass
class ProcessInfo:
    """Process information schema"""
    pid: int
    command: str
    tool_name: str
    target: str
    status: str
    start_time: str
    cpu_percent: float
    memory_percent: float
    progress: float
    runtime: float

@dataclass
class ProcessManagementResponse:
    """Process management response schema"""
    success: bool
    processes: Optional[Dict[int, ProcessInfo]] = None
    process: Optional[ProcessInfo] = None
    message: Optional[str] = None
    total_processes: Optional[int] = None

@dataclass
class VulnerabilityInfo:
    """Vulnerability information schema"""
    vulnerability_id: str
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float]
    affected_component: str
    solution: Optional[str]
    references: List[str]

@dataclass
class ScanResult:
    """Scan result schema"""
    tool_name: str
    target: str
    scan_type: str
    vulnerabilities: List[VulnerabilityInfo]
    total_vulnerabilities: int
    severity_counts: Dict[str, int]
    scan_duration: float
    timestamp: str

@dataclass
class HealthCheckResponse:
    """Health check response schema"""
    status: str
    version: str
    timestamp: str
    services: Dict[str, str]
    system_resources: Optional[Dict[str, Any]] = None

@dataclass
class ErrorResponse:
    """Error response schema"""
    error: str
    message: str
    status_code: int
    timestamp: str
    details: Optional[Dict[str, Any]] = None

@dataclass
class ValidationError:
    """Validation error schema"""
    field: str
    message: str
    value: Any

@dataclass
class BugBountyRequest:
    """Bug bounty workflow request schema"""
    domain: str
    scope: List[str]
    priority_vulns: List[str]
    include_osint: bool = True
    include_business_logic: bool = True

@dataclass
class CTFRequest:
    """CTF challenge request schema"""
    challenge_name: str
    category: str
    description: str
    points: int
    difficulty: str
    files: List[str]

@dataclass
class WorkflowResponse:
    """Workflow response schema"""
    success: bool
    workflow_id: str
    estimated_time: int
    tools_count: int
    steps: List[Dict[str, Any]]
    priority_score: float

def validate_tool_execution_request(data: Dict[str, Any]) -> List[ValidationError]:
    """Validate tool execution request"""
    errors = []
    
    if "tool_name" not in data:
        errors.append(ValidationError("tool_name", "Tool name is required", None))
    elif not isinstance(data["tool_name"], str):
        errors.append(ValidationError("tool_name", "Tool name must be a string", data["tool_name"]))
    
    if "parameters" not in data:
        errors.append(ValidationError("parameters", "Parameters are required", None))
    elif not isinstance(data["parameters"], dict):
        errors.append(ValidationError("parameters", "Parameters must be a dictionary", data["parameters"]))
    
    if "use_recovery" in data and not isinstance(data["use_recovery"], bool):
        errors.append(ValidationError("use_recovery", "use_recovery must be a boolean", data["use_recovery"]))
    
    if "timeout" in data and data["timeout"] is not None:
        if not isinstance(data["timeout"], int) or data["timeout"] <= 0:
            errors.append(ValidationError("timeout", "Timeout must be a positive integer", data["timeout"]))
    
    return errors

def validate_intelligence_request(data: Dict[str, Any]) -> List[ValidationError]:
    """Validate intelligence analysis request"""
    errors = []
    
    if "target" not in data:
        errors.append(ValidationError("target", "Target is required", None))
    elif not isinstance(data["target"], str):
        errors.append(ValidationError("target", "Target must be a string", data["target"]))
    
    if "objective" in data and not isinstance(data["objective"], str):
        errors.append(ValidationError("objective", "Objective must be a string", data["objective"]))
    
    if "max_tools" in data:
        if not isinstance(data["max_tools"], int) or data["max_tools"] <= 0:
            errors.append(ValidationError("max_tools", "max_tools must be a positive integer", data["max_tools"]))
    
    return errors

def validate_process_management_request(data: Dict[str, Any]) -> List[ValidationError]:
    """Validate process management request"""
    errors = []
    
    if "action" not in data:
        errors.append(ValidationError("action", "Action is required", None))
    elif data["action"] not in ["list", "status", "terminate", "pause", "resume"]:
        errors.append(ValidationError("action", "Invalid action", data["action"]))
    
    if data.get("action") in ["status", "terminate", "pause", "resume"]:
        if "pid" not in data:
            errors.append(ValidationError("pid", "PID is required for this action", None))
        elif not isinstance(data["pid"], int) or data["pid"] <= 0:
            errors.append(ValidationError("pid", "PID must be a positive integer", data["pid"]))
    
    return errors

def format_success_response(data: Any, status_code: int = 200) -> Dict[str, Any]:
    """Format successful API response"""
    from datetime import datetime
    
    return {
        "success": True,
        "data": data,
        "timestamp": datetime.now().isoformat(),
        "status_code": status_code
    }

def format_error_response(error: str, message: str, status_code: int = 400, details: Dict[str, Any] = None) -> Dict[str, Any]:
    """Format error API response"""
    from datetime import datetime
    
    return {
        "success": False,
        "error": error,
        "message": message,
        "status_code": status_code,
        "timestamp": datetime.now().isoformat(),
        "details": details
    }

def format_validation_error_response(errors: List[ValidationError]) -> Dict[str, Any]:
    """Format validation error response"""
    return format_error_response(
        error="Validation Error",
        message="Request validation failed",
        status_code=400,
        details={
            "validation_errors": [
                {"field": err.field, "message": err.message, "value": err.value}
                for err in errors
            ]
        }
    )
