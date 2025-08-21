# HexStrike Modularization Plan - Part 001
## Detailed Module Specifications

### Visual Engine Modules

#### interfaces/visual_engine.py
**Lines:** L105-L439 (335 lines) → Target: 250 lines  
**Extraction Strategy:** Move color constants to platform/constants.py (-85 lines)

**Responsibility Statement:** "This changes when visual output formatting requirements or color schemes change."

**Change Triggers:**
- UI theme updates requiring new color schemes
- New output format requirements (JSON, XML, etc.)
- Accessibility compliance changes
- Terminal compatibility updates

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
```

**Dependencies:** platform/constants.py (for color schemes)

**Key Types:**
- `VisualEngine`: Main formatting interface
- `ColorScheme`: Color palette management
- `ProgressRenderer`: Progress bar rendering logic

**Error/Logging Policy:** No error handling (pure formatting functions), logging via platform/logging.py

**Security/Validation:** Input sanitization for terminal escape sequences

**Examples:**
```python
from interfaces.visual_engine import VisualEngine
banner = VisualEngine.create_banner()
progress = VisualEngine.render_progress_bar(0.75, style='cyber')
```

**Migration Notes:** Extract from L105-L439, move COLORS dict to platform/constants.py

---

#### services/dashboard_service.py
**Lines:** New module (aggregates dashboard logic)  
**Target:** 200 lines

**Responsibility Statement:** "This changes when dashboard data aggregation or presentation logic changes."

**Change Triggers:**
- New dashboard widgets or metrics
- Data source integration changes
- Dashboard layout or grouping updates
- Real-time update mechanism changes

**Public API:**
```python
class DashboardService:
    def create_process_dashboard(self, processes: Dict) -> Dict[str, Any]
    def create_system_dashboard(self) -> Dict[str, Any]
    def create_security_dashboard(self, scan_results: List) -> Dict[str, Any]
    def aggregate_metrics(self, timeframe: str) -> Dict[str, Any]
```

**Dependencies:** 
- interfaces/visual_engine.py
- services/process_service.py
- platform/logging.py

**Key Types:**
- `DashboardService`: Main dashboard orchestrator
- `ProcessDashboard`: Process-specific dashboard data
- `MetricsAggregator`: Metrics collection and aggregation

### Decision Engine Modules

#### domain/target_analysis.py
**Lines:** L445-L510 (66 lines) → Target: 180 lines  
**Expansion Strategy:** Add comprehensive target analysis logic

**Responsibility Statement:** "This changes when target classification rules or analysis algorithms change."

**Change Triggers:**
- New target types or classification criteria
- Technology detection algorithm updates
- Risk assessment model changes
- Attack surface calculation updates

**Public API:**
```python
@dataclass
class TargetProfile:
    target: str
    target_type: TargetType
    ip_addresses: List[str]
    open_ports: List[int]
    services: Dict[int, str]
    technologies: List[TechnologyStack]
    
    def to_dict(self) -> Dict[str, Any]
    def calculate_attack_surface(self) -> float
    def assess_risk_level(self) -> str

class TargetAnalyzer:
    def analyze_target(self, target: str) -> TargetProfile
    def detect_technologies(self, target: str) -> List[TechnologyStack]
    def classify_target_type(self, target: str) -> TargetType
```

**Dependencies:** None (pure domain logic)

**Key Types:**
- `TargetType`: Enumeration of target classifications
- `TechnologyStack`: Technology detection results
- `TargetProfile`: Comprehensive target analysis
- `TargetAnalyzer`: Analysis orchestration

**Migration Notes:** Extract from L445-L510, expand with analysis logic from L811-L969

---

#### services/decision_service.py
**Lines:** L572-L1542 (970 lines) → Target: 300 lines  
**Extraction Strategy:** Split into multiple focused services

**Responsibility Statement:** "This changes when tool selection algorithms or optimization strategies change."

**Change Triggers:**
- New tool additions to registry
- Selection algorithm improvements
- Parameter optimization strategy updates
- Effectiveness scoring model changes

**Public API:**
```python
class DecisionService:
    def select_optimal_tools(self, profile: TargetProfile, objective: str) -> List[str]
    def optimize_parameters(self, tool: str, profile: TargetProfile) -> Dict[str, Any]
    def create_attack_chain(self, profile: TargetProfile, objective: str) -> AttackChain
    def enable_advanced_optimization(self) -> None
```

**Dependencies:**
- domain/target_analysis.py
- adapters/tool_registry.py
- services/parameter_optimization_service.py

**Key Types:**
- `DecisionService`: Main decision orchestrator
- `ToolSelector`: Tool selection logic
- `EffectivenessCalculator`: Tool effectiveness scoring

**Split Strategy:**
- Keep core decision logic (300 lines)
- Extract parameter optimization → services/parameter_optimization_service.py (400 lines)
- Extract attack chain logic → services/attack_chain_service.py (270 lines)

### Tool Management Modules

#### adapters/tool_registry.py
**Lines:** New module (consolidates tool definitions)  
**Target:** 250 lines

**Responsibility Statement:** "This changes when tool definitions, capabilities, or metadata change."

**Change Triggers:**
- New security tool integrations
- Tool capability updates or deprecations
- Tool metadata schema changes
- Tool categorization updates

**Public API:**
```python
class ToolRegistry:
    def register_tool(self, tool_def: ToolDefinition) -> None
    def get_tool(self, name: str) -> Optional[ToolDefinition]
    def get_tools_by_category(self, category: str) -> List[ToolDefinition]
    def get_tools_by_target_type(self, target_type: TargetType) -> List[ToolDefinition]

@dataclass
class ToolDefinition:
    name: str
    category: str
    command_template: str
    parameters: Dict[str, ParameterSpec]
    effectiveness: Dict[str, float]
    alternatives: List[str]
```

**Dependencies:** platform/constants.py

**Key Types:**
- `ToolRegistry`: Central tool repository
- `ToolDefinition`: Tool metadata and configuration
- `ParameterSpec`: Parameter validation specifications
- `ToolCategory`: Tool categorization system

---

#### services/tool_execution_service.py
**Lines:** New module (consolidates execution logic)  
**Target:** 280 lines

**Responsibility Statement:** "This changes when tool execution logic or result processing changes."

**Change Triggers:**
- Tool execution strategy updates
- Result parsing format changes
- Timeout and retry logic updates
- Error handling strategy changes

**Public API:**
```python
class ToolExecutionService:
    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> ExecutionResult
    def execute_with_recovery(self, tool_name: str, params: Dict[str, Any]) -> ExecutionResult
    def parse_tool_output(self, tool_name: str, output: str) -> Dict[str, Any]
    def validate_parameters(self, tool_name: str, params: Dict[str, Any]) -> bool

@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    parsed_output: Dict[str, Any]
```

**Dependencies:**
- adapters/tool_registry.py
- services/process_service.py
- platform/errors.py

### Process Management Modules

#### services/process_service.py
**Lines:** L4877-L5553 (676 lines) → Target: 290 lines  
**Extraction Strategy:** Move monitoring to separate service

**Responsibility Statement:** "This changes when process lifecycle management or monitoring requirements change."

**Change Triggers:**
- Process management strategy updates
- Resource allocation algorithm changes
- Process lifecycle event handling updates
- Scaling strategy modifications

**Public API:**
```python
class ProcessService:
    def submit_task(self, task_id: str, func: Callable, *args, **kwargs) -> str
    def get_task_result(self, task_id: str) -> Dict[str, Any]
    def terminate_process(self, pid: int) -> bool
    def pause_process(self, pid: int) -> bool
    def resume_process(self, pid: int) -> bool
    def list_active_processes(self) -> Dict[int, Dict[str, Any]]

class ProcessPool:
    def __init__(self, min_workers: int = 2, max_workers: int = 20)
    def scale_up(self, count: int) -> None
    def scale_down(self, count: int) -> None
```

**Dependencies:**
- platform/errors.py
- utils/system.py
- services/monitoring_service.py

**Split Strategy:**
- Keep core process management (290 lines)
- Extract monitoring → services/monitoring_service.py (200 lines)
- Extract performance tracking → services/performance_service.py (186 lines)

### API Layer Modules

#### interfaces/api_schemas.py
**Lines:** New module (consolidates API schemas)  
**Target:** 180 lines

**Responsibility Statement:** "This changes when API request/response schemas or validation rules change."

**Change Triggers:**
- API version updates requiring schema changes
- New endpoint parameter requirements
- Validation rule updates or additions
- Response format standardization changes

**Public API:**
```python
@dataclass
class ToolExecutionRequest:
    tool_name: str
    parameters: Dict[str, Any]
    use_recovery: bool = True
    timeout: int = 300

@dataclass
class ToolExecutionResponse:
    success: bool
    result: Dict[str, Any]
    execution_time: float
    timestamp: str
    error: Optional[str] = None

class SchemaValidator:
    def validate_request(self, schema: Type, data: Dict) -> bool
    def validate_response(self, schema: Type, data: Dict) -> bool
```

**Dependencies:** None

**Key Types:**
- Request/Response schemas for all endpoints
- `SchemaValidator`: Validation logic
- `APIError`: Standardized error responses

---

#### adapters/flask_adapter.py
**Lines:** New module (Flask integration)  
**Target:** 150 lines

**Responsibility Statement:** "This changes when Flask integration, routing, or middleware requirements change."

**Change Triggers:**
- Flask version updates requiring compatibility changes
- Routing strategy or URL pattern changes
- Middleware addition or configuration updates
- Authentication/authorization integration changes

**Public API:**
```python
class FlaskAdapter:
    def __init__(self, app: Flask)
    def register_routes(self, route_handlers: List[RouteHandler]) -> None
    def add_middleware(self, middleware: Middleware) -> None
    def configure_error_handlers(self) -> None

class RouteHandler:
    def handle_request(self, request: Request) -> Response
    def validate_request(self, request: Request) -> bool
    def format_response(self, data: Any) -> Response
```

**Dependencies:**
- interfaces/api_schemas.py
- platform/errors.py

## Navigation
- [← Back to Index](index.md)
- [→ Part 002: Migration Implementation Guide](part_002.md)
