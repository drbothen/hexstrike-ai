# HexStrike AI Reference Documentation

## Overview

**HexStrike AI - Advanced Penetration Testing Framework Server**

Enhanced with AI-Powered Intelligence & Automation for Bug Bounty, CTF, Red Team, and Security Research operations.

### Quick Stats
- **Total Lines:** 15,410
- **Documentation Progress:** 1,542/15,410 lines (10.0%)
- **Total Entities Documented:** 11 major entities
- **Classes:** 6 (including 1 major AI engine)
- **Enums:** 2 target classification systems
- **Dataclasses:** 2 data structures
- **Constants:** 2 configuration values
- **Imports:** 25+ standard and third-party libraries

### File Overview
- **Source:** `reference-server.py` - Monolithic penetration testing framework
- **Architecture:** Two-script system with FastMCP integration
- **Framework:** Flask-based API with AI decision engine
- **Coverage:** 10.0% complete (chunk 1 of ~15 chunks)

## Reconstruction Overview

### High-Level Architecture
1. **Visual Engine:** Modern terminal UI with reddish hacker theme
2. **Intelligence Core:** AI-powered tool selection and parameter optimization
3. **Target Analysis:** Comprehensive profiling and classification system
4. **Attack Planning:** Automated attack chain generation
5. **Tool Integration:** 100+ security tools with intelligent optimization

### Key Dependencies
- **Flask:** Web framework for API endpoints
- **AI Libraries:** For intelligent decision making
- **Security Tools:** Integration with 100+ penetration testing tools
- **Visualization:** Advanced terminal UI with ANSI colors

## Entity Catalog

### Core Classes (Lines 105-1542)

#### Visual & UI Components
- **[ModernVisualEngine](support/class.ModernVisualEngine.md)** (105-439)
  - Beautiful terminal output formatting
  - Reddish hacker theme with 256-color support
  - Progress bars, dashboards, and status indicators
  - 11 static methods for visual formatting

#### Target Analysis System
- **[TargetType](support/enum.TargetType.md)** (445-453)
  - Enumeration of target types (web apps, networks, APIs, cloud, mobile, binaries)
- **[TechnologyStack](support/enum.TechnologyStack.md)** (455-471)
  - Technology detection (Apache, Nginx, PHP, WordPress, React, etc.)
- **[TargetProfile](support/dataclass.TargetProfile.md)** (473-510)
  - Comprehensive target analysis data structure
  - Attack surface scoring and risk assessment

#### Attack Planning System
- **[AttackStep](support/dataclass.AttackStep.md)** (512-520)
  - Individual attack step with success probability
- **[AttackChain](support/class.AttackChain.md)** (522-570)
  - Sequence of coordinated attacks
  - Compound probability calculation

#### AI Intelligence Engine
- **[IntelligentDecisionEngine](support/class.IntelligentDecisionEngine.md)** (572-1542)
  - AI-powered tool selection and optimization
  - 30+ methods including 25 tool-specific optimizers
  - Target analysis and attack chain creation
  - Technology detection and parameter tuning

### Configuration & Setup

#### Constants
- **[API_PORT](entities/constant.config.API_PORT.md)** (98)
  - Server port with environment variable support
- **[API_HOST](entities/constant.config.API_HOST.md)** (99)
  - Server host binding configuration

#### Imports
- **[argparse](entities/import.standard.argparse.md)** (21)
  - Command-line argument parsing
- **[json](entities/import.standard.json.md)** (22)
  - JSON operations for API responses

## How to Reconstruct

### Build Order
1. Install dependencies (Flask, security tools, AI libraries)
2. Set up environment variables (HEXSTRIKE_PORT, HEXSTRIKE_HOST)
3. Initialize visual engine and color schemes
4. Configure target analysis and classification systems
5. Set up AI decision engine with tool effectiveness mappings
6. Initialize attack pattern databases
7. Configure Flask application and API endpoints

### Critical Bootstraps
- Logging configuration with fallback handling
- Flask app initialization with JSON configuration
- AI decision engine with tool effectiveness mappings
- Visual engine color palette and formatting

### Config/Environment Variables
- `HEXSTRIKE_PORT`: API server port (default: 8888)
- `HEXSTRIKE_HOST`: API server host (default: 127.0.0.1)

## Testing Strategy

### Validation Approach
- Visual output testing across terminal types
- AI decision engine accuracy validation
- Tool parameter optimization effectiveness
- Attack chain success probability validation
- Target analysis and classification accuracy

### Key Test Areas
- Color compatibility and ANSI support
- Tool effectiveness mappings
- Parameter optimization logic
- Attack pattern generation
- JSON serialization/deserialization

## Important Notes

### Known Limitations
- Documentation is 10.0% complete (chunk 1 only)
- Remaining 14,000+ lines contain API endpoints, workflows, and tool integrations
- Full reconstruction requires completion of all chunks

### Areas Requiring Manual Review
- Tool effectiveness calibration
- Attack pattern validation
- Security tool integration testing
- Performance optimization validation

### Next Documentation Phases
- Chunk 2: Error handling and recovery systems
- Chunk 3: Bug bounty and CTF workflows
- Chunks 4-15: API endpoints, tool integrations, and execution engines

---

*Documentation generated by systematic analysis of reference-server.py*
*Progress: Chunk 1 of ~15 chunks complete*
