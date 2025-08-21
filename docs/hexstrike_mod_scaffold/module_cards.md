# HexStrike AI - Module Cards

**Purpose:** Detailed specifications for each module in the modularized HexStrike AI framework, including responsibility statements, dependencies, and implementation details.

**Status:** Proposed (based on analysis of hexstrike_server.py L1-L15409)

## Platform Layer Modules

### platform/constants.py
**Responsibility Statement:** "This changes when application constants, color schemes, or configuration defaults change."

**Change Triggers:**
- Color scheme or theme updates requiring new color definitions
- Default configuration value changes for tools or system settings
- Tool command template updates or new tool additions
- Application-wide constant additions or modifications

**Public API:**
```python
# Color schemes extracted from L109-L163
COLORS: Dict[str, str] = {
    'PRIMARY_BORDER': '\033[38;5;196m',
    'ACCENT_LINE': '\033[38;5;208m',
    'FIRE_RED': '\033[38;5;196m',
    'CYBER_ORANGE': '\033[38;5;208m',
    # ... complete color palette
}

# Tool defaults
DEFAULT_TIMEOUTS: Dict[str, int] = {
    'nmap': 300,
    'gobuster': 600,
    'nuclei': 180,
    # ... all tool timeouts
}

# Application constants
MAX_CONCURRENT_PROCESSES: int = 20
DEFAULT_CACHE_TTL: int = 3600
API_VERSION: str = "v1.0"
```

**Dependencies:** None (pure constants)

**Line Budget:** 180/300 lines

**Key Types:**
- Color constant dictionaries
- Tool configuration defaults
- Application-wide constants

**Error/Logging Policy:** No error handling required (constants only)

**Security/Validation:** No validation required (constants only)

**Migration Notes:** Extract from L109-L163 (COLORS dict), L5691-L5704 (additional colors), and scattered constants throughout the file

---

### platform/errors.py
**Responsibility Statement:** "This changes when error classification, recovery strategies, or error reporting changes."

**Change Triggers:**
- New error types requiring classification and handling
- Recovery strategy algorithm updates or new recovery methods
- Error reporting format changes or new reporting destinations
- Error escalation policy updates

**Public API:**
```python
class ErrorType(Enum):
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    # ... complete enumeration

class RecoveryAction(Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    # ... complete enumeration

@dataclass
class ErrorContext:
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime

class ErrorHandler:
    def classify_error(self, error_message: str, exception: Exception) -> ErrorType
    def get_recovery_strategy(self, error_type: ErrorType) -> RecoveryStrategy
    def handle_tool_failure(self, tool_name: str, exception: Exception, context: Dict) -> RecoveryStrategy
```

**Dependencies:** None (core error handling)

**Line Budget:** 280/300 lines

**Key Types:**
- `ErrorType`: Error classification enumeration
- `RecoveryAction`: Available recovery actions
- `ErrorContext`: Error context information
- `RecoveryStrategy`: Recovery strategy configuration
- `ErrorHandler`: Main error handling orchestrator

**Error/Logging Policy:** Self-contained error handling, logs to platform/logging.py

**Security/Validation:** Sanitize error messages to prevent information leakage

**Migration Notes:** Extract from L1558-L1604 (enums), L1617-L1659 (patterns), L1661-L1870 (strategies), L1983-L2199 (handler logic)

---

### platform/logging.py
**Responsibility Statement:** "This changes when logging format, destinations, or filtering requirements change."

**Change Triggers:**
- Log format changes for better readability or compliance
- New log destinations (files, external services, databases)
- Log filtering rule updates or new filtering criteria
- Log level configuration changes

**Public API:**
```python
class LogManager:
    def configure_logging(self, config: LogConfig) -> None
    def get_logger(self, name: str) -> Logger
    def set_log_level(self, level: str) -> None
    def add_handler(self, handler: logging.Handler) -> None

@dataclass
class LogConfig:
    level: str
    format: str
    handlers: List[str]
    file_path: Optional[str]
    max_file_size: int
    backup_count: int

class LogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str
```

**Dependencies:** platform/config.py

**Line Budget:** 200/300 lines

**Key Types:**
- `LogManager`: Central logging configuration
- `LogConfig`: Logging configuration data
- `LogFormatter`: Custom log formatting

**Error/Logging Policy:** Self-contained logging infrastructure

**Security/Validation:** Sanitize log messages, prevent log injection

**Migration Notes:** Extract from L72-L91 (current logging setup), enhance with structured logging

---

### platform/validation.py
**Responsibility Statement:** "This changes when parameter validation rules or input sanitization requirements change."

**Change Triggers:**
- New parameter validation requirements for tools or APIs
- Input sanitization rule updates for security compliance
- Data type validation additions or modifications
- Security validation policy changes

**Public API:**
```python
class ParameterValidator:
    def validate_url(self, url: str) -> ValidationResult
    def validate_ip_address(self, ip: str) -> ValidationResult
    def validate_port(self, port: int) -> ValidationResult
    def validate_file_path(self, path: str) -> ValidationResult
    def sanitize_command_input(self, input: str) -> str
    def validate_tool_parameters(self, tool: str, params: Dict) -> List[ValidationError]

@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[str]
    sanitized_value: Optional[Any]

class ValidationError(Exception):
    def __init__(self, field: str, message: str, value: Any)
```

**Dependencies:** None (pure validation logic)

**Line Budget:** 220/300 lines

**Key Types:**
- `ParameterValidator`: Main validation orchestrator
- `ValidationResult`: Validation outcome data
- `ValidationError`: Validation failure exception

**Error/Logging Policy:** Raise ValidationError for invalid inputs, log validation attempts

**Security/Validation:** Core security validation functionality

**Migration Notes:** Extract validation patterns from L8469-L8474, L9468-L9473, and other parameter validation code

## Domain Layer Modules

### domain/target_analysis.py
**Responsibility Statement:** "This changes when target classification rules or analysis algorithms change."

**Change Triggers:**
- New target types requiring classification support
- Technology detection algorithm improvements or updates
- Risk assessment model changes or new risk factors
- Attack surface calculation methodology updates

**Public API:**
```python
class TargetType(Enum):
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    BINARY_FILE = "binary_file"

class TechnologyStack(Enum):
    APACHE = "apache"
    NGINX = "nginx"
    WORDPRESS = "wordpress"
    # ... complete technology enumeration

@dataclass
class TargetProfile:
    target: str
    target_type: TargetType
    ip_addresses: List[str]
    open_ports: List[int]
    services: Dict[int, str]
    technologies: List[TechnologyStack]
    attack_surface_score: float
    risk_level: str
    confidence_score: float
    
    def to_dict(self) -> Dict[str, Any]
    def calculate_attack_surface(self) -> float
    def assess_risk_level(self) -> str

class TargetAnalyzer:
    def analyze_target(self, target: str) -> TargetProfile
    def detect_technologies(self, target: str, headers: Dict, content: str) -> List[TechnologyStack]
    def classify_target_type(self, target: str) -> TargetType
    def calculate_confidence_score(self, profile: TargetProfile) -> float
```

**Dependencies:** None (pure domain logic)

**Line Budget:** 180/300 lines

**Key Types:**
- `TargetType`: Target classification enumeration
- `TechnologyStack`: Technology detection results
- `TargetProfile`: Comprehensive target analysis data
- `TargetAnalyzer`: Analysis orchestration logic

**Error/Logging Policy:** Return analysis results with confidence scores, log analysis attempts

**Security/Validation:** Validate target inputs to prevent injection attacks

**Migration Notes:** Extract from L445-L510 (enums and dataclass), L811-L969 (analysis logic)

## Services Layer Modules

### services/decision_service.py
**Responsibility Statement:** "This changes when tool selection algorithms or optimization strategies change."

**Change Triggers:**
- New tool additions requiring selection algorithm updates
- Tool effectiveness scoring model improvements
- Selection algorithm optimization or new selection strategies
- Target-tool mapping rule changes

**Public API:**
```python
class DecisionService:
    def select_optimal_tools(self, profile: TargetProfile, objective: str) -> List[str]
    def optimize_parameters(self, tool: str, profile: TargetProfile, context: Dict) -> Dict[str, Any]
    def create_attack_chain(self, profile: TargetProfile, objective: str) -> AttackChain
    def calculate_tool_effectiveness(self, tool: str, target_type: TargetType) -> float
    def enable_advanced_optimization(self) -> None
    def disable_advanced_optimization(self) -> None

class ToolSelector:
    def select_tools_by_effectiveness(self, profile: TargetProfile, max_tools: int) -> List[str]
    def filter_tools_by_objective(self, tools: List[str], objective: str) -> List[str]

class EffectivenessCalculator:
    def calculate_effectiveness(self, tool: str, target_type: TargetType) -> float
    def update_effectiveness_scores(self, results: Dict[str, float]) -> None
```

**Dependencies:**
- domain/target_analysis.py
- adapters/tool_registry.py
- services/parameter_optimization_service.py

**Line Budget:** 300/300 lines (at maximum)

**Key Types:**
- `DecisionService`: Main decision orchestrator
- `ToolSelector`: Tool selection algorithms
- `EffectivenessCalculator`: Tool effectiveness scoring

**Error/Logging Policy:** Log decision rationale, handle tool selection failures gracefully

**Security/Validation:** Validate tool parameters before optimization

**Migration Notes:** Extract from L572-L1542, split optimization logic to separate service

---

### services/tool_execution_service.py
**Responsibility Statement:** "This changes when tool execution logic or result processing changes."

**Change Triggers:**
- Tool execution strategy updates or new execution methods
- Result parsing format changes or new parsing requirements
- Timeout and retry logic modifications
- Error handling strategy improvements

**Public API:**
```python
class ToolExecutionService:
    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> ExecutionResult
    def execute_with_recovery(self, tool_name: str, params: Dict[str, Any], max_attempts: int) -> ExecutionResult
    def parse_tool_output(self, tool_name: str, output: str) -> Dict[str, Any]
    def validate_parameters(self, tool_name: str, params: Dict[str, Any]) -> bool
    def get_execution_status(self, execution_id: str) -> ExecutionStatus

@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    parsed_output: Dict[str, Any]
    recovery_info: Optional[Dict[str, Any]]

class ResultProcessor:
    def parse_output(self, tool_name: str, raw_output: str) -> Dict[str, Any]
    def extract_vulnerabilities(self, parsed_output: Dict) -> List[Dict[str, Any]]
    def calculate_success_metrics(self, result: ExecutionResult) -> Dict[str, float]
```

**Dependencies:**
- adapters/tool_registry.py
- services/process_service.py
- platform/errors.py

**Line Budget:** 280/300 lines

**Key Types:**
- `ToolExecutionService`: Main execution orchestrator
- `ExecutionResult`: Execution outcome data
- `ResultProcessor`: Output parsing and analysis

**Error/Logging Policy:** Comprehensive error handling with recovery, detailed execution logging

**Security/Validation:** Sanitize tool parameters, validate tool outputs

**Migration Notes:** Consolidate execution logic from Flask endpoints and command execution functions

## Adapter Layer Modules

### adapters/tool_registry.py
**Responsibility Statement:** "This changes when tool definitions, capabilities, or metadata change."

**Change Triggers:**
- New security tool integrations requiring registration
- Tool capability updates or deprecations
- Tool metadata schema changes or new metadata fields
- Tool categorization or classification updates

**Public API:**
```python
class ToolRegistry:
    def register_tool(self, tool_def: ToolDefinition) -> None
    def get_tool(self, name: str) -> Optional[ToolDefinition]
    def get_tools_by_category(self, category: str) -> List[ToolDefinition]
    def get_tools_by_target_type(self, target_type: TargetType) -> List[ToolDefinition]
    def update_tool_effectiveness(self, tool_name: str, effectiveness: Dict[str, float]) -> None

@dataclass
class ToolDefinition:
    name: str
    category: str
    command_template: str
    parameters: Dict[str, ParameterSpec]
    effectiveness: Dict[str, float]
    alternatives: List[str]
    timeout: int
    requires_privileges: bool

@dataclass
class ParameterSpec:
    name: str
    type: str
    required: bool
    default: Optional[Any]
    validation_rules: List[str]

class ToolCapabilities:
    def get_supported_targets(self, tool_name: str) -> List[TargetType]
    def get_output_formats(self, tool_name: str) -> List[str]
    def supports_feature(self, tool_name: str, feature: str) -> bool
```

**Dependencies:** platform/constants.py

**Line Budget:** 250/300 lines

**Key Types:**
- `ToolRegistry`: Central tool repository
- `ToolDefinition`: Tool metadata and configuration
- `ParameterSpec`: Parameter validation specifications
- `ToolCapabilities`: Tool capability queries

**Error/Logging Policy:** Log tool registration and lookup operations, handle missing tools gracefully

**Security/Validation:** Validate tool definitions, sanitize command templates

**Migration Notes:** Consolidate tool definitions from L3496-L3670 and effectiveness data from L581-L667

---

### adapters/web_tool_adapters.py
**Responsibility Statement:** "This changes when web security tool integrations or parameter mappings change."

**Change Triggers:**
- Web tool version updates requiring parameter or output changes
- New web security tool integrations
- Tool output parsing format modifications
- Tool execution strategy improvements

**Public API:**
```python
class NmapAdapter(ToolAdapter):
    def execute(self, params: Dict[str, Any]) -> ExecutionResult
    def parse_output(self, output: str) -> Dict[str, Any]
    def validate_parameters(self, params: Dict[str, Any]) -> bool
    def get_default_parameters(self, target_type: TargetType) -> Dict[str, Any]

class GobusterAdapter(ToolAdapter):
    def execute(self, params: Dict[str, Any]) -> ExecutionResult
    def parse_output(self, output: str) -> Dict[str, Any]
    def validate_parameters(self, params: Dict[str, Any]) -> bool

class NucleiAdapter(ToolAdapter):
    def execute(self, params: Dict[str, Any]) -> ExecutionResult
    def parse_output(self, output: str) -> Dict[str, Any]
    def get_template_categories(self) -> List[str]

class SqlmapAdapter(ToolAdapter):
    def execute(self, params: Dict[str, Any]) -> ExecutionResult
    def parse_output(self, output: str) -> Dict[str, Any]
    def detect_sql_injection(self, output: str) -> List[Dict[str, Any]]

class ToolAdapter(ABC):
    @abstractmethod
    def execute(self, params: Dict[str, Any]) -> ExecutionResult
    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]
    @abstractmethod
    def validate_parameters(self, params: Dict[str, Any]) -> bool
```

**Dependencies:**
- adapters/tool_registry.py
- services/tool_execution_service.py

**Line Budget:** 300/300 lines (at maximum)

**Key Types:**
- `ToolAdapter`: Base adapter interface
- `NmapAdapter`: Nmap tool integration
- `GobusterAdapter`: Gobuster tool integration
- `NucleiAdapter`: Nuclei vulnerability scanner integration
- `SqlmapAdapter`: SQLMap tool integration

**Error/Logging Policy:** Handle tool execution failures, log adapter operations

**Security/Validation:** Validate tool parameters, sanitize command inputs

**Migration Notes:** Extract from Flask endpoints L8463-L8615 (nmap, gobuster, nuclei)

## Interface Layer Modules

### interfaces/visual_engine.py
**Responsibility Statement:** "This changes when visual output formatting requirements or color schemes change."

**Change Triggers:**
- UI theme updates requiring new color schemes or styling
- New output format requirements (JSON, XML, structured data)
- Accessibility compliance changes for visual output
- Terminal compatibility updates for different environments

**Public API:**
```python
class VisualEngine:
    @staticmethod
    def create_banner() -> str
    @staticmethod
    def create_progress_bar(current: int, total: int, width: int = 50, tool: str = "") -> str
    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber') -> str
    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str
    @staticmethod
    def format_vulnerability_card(vuln_data: Dict[str, Any]) -> str
    @staticmethod
    def format_error_card(error_type: str, tool_name: str, error_message: str) -> str
    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "") -> str

class ColorScheme:
    def __init__(self, colors: Dict[str, str])
    def get_color(self, name: str) -> str
    def apply_color(self, text: str, color_name: str) -> str

class ProgressRenderer:
    def render_bar(self, progress: float, width: int, style: str) -> str
    def render_spinner(self, frame: int) -> str
    def render_eta(self, remaining_seconds: float) -> str
```

**Dependencies:** platform/constants.py (for color schemes)

**Line Budget:** 250/300 lines

**Key Types:**
- `VisualEngine`: Main formatting interface
- `ColorScheme`: Color palette management
- `ProgressRenderer`: Progress visualization logic

**Error/Logging Policy:** No error handling (pure formatting), log formatting operations

**Security/Validation:** Sanitize input text to prevent terminal escape sequence injection

**Migration Notes:** Extract from L105-L439, move COLORS dict to platform/constants.py

---

### interfaces/api_schemas.py
**Responsibility Statement:** "This changes when API request/response schemas or validation rules change."

**Change Triggers:**
- API version updates requiring schema modifications
- New endpoint parameter requirements or response fields
- Validation rule updates for security or data integrity
- Response format standardization changes

**Public API:**
```python
@dataclass
class ToolExecutionRequest:
    tool_name: str
    parameters: Dict[str, Any]
    use_recovery: bool = True
    timeout: int = 300
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ToolExecutionResponse:
    success: bool
    result: Dict[str, Any]
    execution_time: float
    timestamp: str
    error: Optional[str] = None
    recovery_info: Optional[Dict[str, Any]] = None

@dataclass
class IntelligenceRequest:
    target: str
    objective: str = "comprehensive"
    max_tools: int = 5
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ProcessStatusResponse:
    pid: int
    status: str
    progress: float
    runtime: float
    eta: float
    command: str

class SchemaValidator:
    def validate_request(self, schema: Type, data: Dict) -> ValidationResult
    def validate_response(self, schema: Type, data: Dict) -> ValidationResult
    def get_schema_errors(self, schema: Type, data: Dict) -> List[str]
```

**Dependencies:** None (pure data schemas)

**Line Budget:** 180/300 lines

**Key Types:**
- Request/Response schemas for all API endpoints
- `SchemaValidator`: Schema validation logic
- Data transfer objects for API communication

**Error/Logging Policy:** Validation errors for malformed requests, log schema validation

**Security/Validation:** Core API validation functionality

**Migration Notes:** Extract schema patterns from Flask endpoints throughout the file

## Utility Layer Modules

### utils/formatting.py
**Responsibility Statement:** "This changes when pure formatting utilities or string manipulation requirements change."

**Change Triggers:**
- New formatting requirements for output display
- String manipulation utility additions or improvements
- Data serialization format changes
- Pure utility function additions for text processing

**Public API:**
```python
def format_duration(seconds: float) -> str
def format_file_size(bytes: int) -> str
def format_timestamp(timestamp: float, format: str = "%Y-%m-%d %H:%M:%S") -> str
def truncate_string(text: str, max_length: int, suffix: str = "...") -> str
def sanitize_filename(filename: str) -> str
def parse_version_string(version: str) -> Tuple[int, int, int]
def format_json_output(data: Dict, indent: int = 2) -> str
def format_table(data: List[Dict], headers: List[str]) -> str
def wrap_text(text: str, width: int) -> List[str]
def escape_shell_arg(arg: str) -> str
```

**Dependencies:** None (pure utilities)

**Line Budget:** 150/300 lines

**Key Types:** Pure utility functions (no classes)

**Error/Logging Policy:** Handle formatting errors gracefully, return safe defaults

**Security/Validation:** Sanitize inputs to prevent injection attacks

**Migration Notes:** Extract pure formatting functions from various modules throughout the codebase

---

### utils/system.py
**Responsibility Statement:** "This changes when system interaction utilities or resource monitoring requirements change."

**Change Triggers:**
- New system resource monitoring needs
- Operating system compatibility requirements
- System utility function additions
- Resource calculation algorithm updates

**Public API:**
```python
def get_system_info() -> Dict[str, Any]
def check_tool_availability(tool_name: str) -> bool
def get_available_memory() -> int
def get_cpu_count() -> int
def get_disk_usage(path: str = "/") -> Dict[str, Any]
def is_port_open(host: str, port: int, timeout: int = 5) -> bool
def get_network_interfaces() -> List[Dict[str, str]]
def get_process_info(pid: int) -> Optional[Dict[str, Any]]
def kill_process_tree(pid: int) -> bool
def get_environment_variable(name: str, default: str = None) -> str
```

**Dependencies:** None (pure system utilities)

**Line Budget:** 200/300 lines

**Key Types:** Pure utility functions (no classes)

**Error/Logging Policy:** Handle system errors gracefully, return None/defaults for failures

**Security/Validation:** Validate system inputs, prevent command injection

**Migration Notes:** Extract system interaction code from process management and monitoring modules

---

**Total Modules:** 52  
**Average Line Count:** 205 lines  
**Modules at 300-line limit:** 8  
**Compliance:** 100% of modules ≤300 lines
