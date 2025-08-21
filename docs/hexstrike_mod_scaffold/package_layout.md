# HexStrike AI - Package Layout

**Purpose:** This document defines the proposed directory structure for the modularized HexStrike AI framework, ensuring modules remain ≤300 lines and follow layered architecture principles.

**Status:** Proposed (based on analysis of hexstrike_server.py L1-L15409)

## Directory Structure

```
src/hexstrike/
├── __init__.py                          # Main package initialization
├── main.py                              # Application entry point (50 lines)
│
├── interfaces/                          # Interface definitions and contracts
│   ├── __init__.py
│   ├── visual_engine.py                 # Visual formatting interfaces (250/300)
│   ├── api_schemas.py                   # API request/response schemas (180/300)
│   └── tool_interface.py               # Tool adapter interface (120/300)
│
├── services/                            # Business logic and orchestration
│   ├── __init__.py
│   ├── decision_service.py              # AI-powered tool selection (300/300)
│   ├── attack_chain_service.py          # Attack chain generation (220/300)
│   ├── parameter_optimization_service.py # Tool parameter optimization (280/300)
│   ├── tool_execution_service.py        # Tool execution orchestration (280/300)
│   ├── process_service.py               # Process lifecycle management (290/300)
│   ├── monitoring_service.py            # System monitoring and metrics (200/300)
│   ├── performance_service.py           # Performance tracking (186/300)
│   ├── dashboard_service.py             # Dashboard data aggregation (200/300)
│   ├── bugbounty_service.py             # Bug bounty workflow management (300/300)
│   ├── reconnaissance_service.py        # Reconnaissance automation (200/300)
│   ├── vulnerability_hunting_service.py # Vulnerability hunting logic (180/300)
│   ├── ctf_service.py                   # CTF challenge orchestration (280/300)
│   ├── ctf_crypto_service.py            # CTF cryptography analysis (300/300)
│   ├── ctf_forensics_service.py         # CTF forensics analysis (300/300)
│   ├── ctf_binary_service.py            # CTF binary analysis (300/300)
│   └── ctf_team_service.py              # CTF team coordination (250/300)
│
├── domain/                              # Pure business logic and entities
│   ├── __init__.py
│   ├── target_analysis.py               # Target classification and analysis (180/300)
│   ├── vulnerability_models.py          # Vulnerability data models (150/300)
│   ├── attack_models.py                 # Attack chain and step models (120/300)
│   └── ctf_models.py                    # CTF challenge models (100/300)
│
├── adapters/                            # External system integrations
│   ├── __init__.py
│   ├── tool_registry.py                 # Central tool repository (250/300)
│   ├── flask_adapter.py                 # Flask framework integration (150/300)
│   ├── api_endpoint_handlers.py         # API endpoint handling (250/300)
│   ├── web_tool_adapters.py             # Web security tool adapters (300/300)
│   ├── cloud_tool_adapters.py           # Cloud security tool adapters (290/300)
│   ├── network_tool_adapters.py         # Network tool adapters (280/300)
│   ├── ctf_tool_adapter.py              # CTF-specific tool adapter (300/300)
│   ├── binary_tool_adapters.py          # Binary analysis tool adapters (270/300)
│   └── ai_service_adapters.py           # AI/ML service integrations (200/300)
│
├── platform/                           # Cross-cutting concerns
│   ├── __init__.py
│   ├── config.py                        # Configuration management (150/300)
│   ├── logging.py                       # Logging infrastructure (200/300)
│   ├── errors.py                        # Error handling and recovery (280/300)
│   ├── constants.py                     # Application constants (180/300)
│   ├── validation.py                    # Input validation utilities (220/300)
│   ├── caching.py                       # Caching infrastructure (160/300)
│   └── security.py                      # Security utilities (140/300)
│
├── utils/                               # Pure utility functions
│   ├── __init__.py
│   ├── formatting.py                    # String and output formatting (150/300)
│   ├── system.py                        # System interaction utilities (200/300)
│   ├── network.py                       # Network utility functions (120/300)
│   ├── file_operations.py               # File handling utilities (100/300)
│   └── crypto_utils.py                  # Cryptographic utilities (180/300)
│
└── legacy/                              # Backward compatibility
    ├── __init__.py
    ├── compatibility_shims.py           # Import compatibility layer (200/300)
    └── deprecated_apis.py               # Deprecated API endpoints (150/300)
```

## Module Size Tracking

### Current Status (Post-Extraction)
- **Total Modules:** 52
- **Average Size:** 205 lines
- **Largest Module:** 300 lines (multiple modules at limit)
- **Smallest Module:** 50 lines (main.py)
- **Modules at 300-line limit:** 8 modules
- **Modules requiring further splitting:** 0

### Size Distribution
```
Lines    Count    Modules
50-100   4        main.py, ctf_models.py, attack_models.py, file_operations.py
101-150  8        visual_engine.py, api_schemas.py, vulnerability_models.py, etc.
151-200  15       Most service and adapter modules
201-250  17       Larger service modules and complex adapters
251-300  8        Maximum-size modules (decision_service.py, etc.)
```

## Layered Architecture Compliance

### Layer Dependencies (Allowed)
```
interfaces/ → services/ → domain/
services/ → adapters/ → platform/
adapters/ → platform/ → utils/
platform/ → utils/
```

### Forbidden Dependencies
- `domain/` → `services/` (DIP violation)
- `domain/` → `adapters/` (DIP violation)
- `utils/` → any other layer (utility isolation)
- Any circular dependencies between modules

### Import Validation Rules
1. **Interfaces Layer:** Can only import from `domain/`, `platform/`, `utils/`
2. **Services Layer:** Can import from `interfaces/`, `domain/`, `adapters/`, `platform/`, `utils/`
3. **Domain Layer:** Can only import from `utils/` (pure business logic)
4. **Adapters Layer:** Can import from `interfaces/`, `platform/`, `utils/`
5. **Platform Layer:** Can only import from `utils/`
6. **Utils Layer:** No imports from other layers (pure utilities)

## Module Splitting Strategy

### Modules Requiring Immediate Splitting
**None** - All modules designed to be ≤300 lines

### Modules at Risk (280+ lines)
1. **decision_service.py (300/300)** - Monitor for growth, consider splitting optimization logic
2. **parameter_optimization_service.py (280/300)** - 20-line buffer remaining
3. **tool_execution_service.py (280/300)** - 20-line buffer remaining
4. **process_service.py (290/300)** - 10-line buffer remaining
5. **cloud_tool_adapters.py (290/300)** - 10-line buffer remaining

### Contingency Splitting Plans
If any module exceeds 300 lines:

**decision_service.py → Split into:**
- `decision_service.py` (core decision logic, 200 lines)
- `tool_selection_service.py` (tool selection algorithms, 150 lines)

**parameter_optimization_service.py → Split into:**
- `parameter_optimization_service.py` (core optimization, 180 lines)
- `optimization_algorithms.py` (specific algorithms, 150 lines)

## Migration Notes

### Phase 1: Platform and Utils
Create foundation modules first:
- `platform/` modules (constants, errors, logging, validation)
- `utils/` modules (formatting, system, network, file_operations)

### Phase 2: Domain and Interfaces
Establish business logic and contracts:
- `domain/` modules (target_analysis, vulnerability_models, attack_models)
- `interfaces/` modules (visual_engine, api_schemas, tool_interface)

### Phase 3: Services
Implement business logic orchestration:
- Core services (decision_service, tool_execution_service, process_service)
- Specialized services (bugbounty_service, ctf_service, monitoring_service)

### Phase 4: Adapters
Migrate external integrations:
- Tool adapters (web_tool_adapters, cloud_tool_adapters, network_tool_adapters)
- Infrastructure adapters (flask_adapter, api_endpoint_handlers)

### Phase 5: Legacy Compatibility
Maintain backward compatibility:
- `legacy/compatibility_shims.py` for import compatibility
- `legacy/deprecated_apis.py` for API compatibility

## Quality Assurance

### Automated Checks
1. **Line Count Validation:** CI fails if any module >300 lines
2. **Import Cycle Detection:** Automated detection of circular imports
3. **Layer Violation Detection:** Validate import rules compliance
4. **Duplication Detection:** Monitor for code duplication across modules

### Manual Reviews
1. **Architecture Review:** Validate module boundaries and responsibilities
2. **Code Review:** Ensure SRP compliance and clean interfaces
3. **Performance Review:** Monitor for performance regressions
4. **Documentation Review:** Validate module documentation completeness

---

**Note:** This package layout is designed to support the complete modularization of hexstrike_server.py (15,409 lines) into 52 focused modules, each ≤300 lines, following DRY and SOLID principles with no import cycles.
