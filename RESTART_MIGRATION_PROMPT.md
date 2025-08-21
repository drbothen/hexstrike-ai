# HexStrike AI Complete Endpoint Migration - Restart Prompt

## CRITICAL ISSUE IDENTIFIED
The previous migration session incorrectly **deleted endpoints from the monolith without migrating them to modular handlers first**. This approach loses functionality and is incorrect.

## CURRENT STATE
- ✅ **Modular infrastructure is complete and working**
- ✅ **All endpoint handler modules created** (34 modules, all ≤300 lines)
- ✅ **Flask adapter integration ready**
- ❌ **98 Flask endpoints still in monolith** (need proper migration)
- ❌ **6 modules still exceed 300-line limit** (need splitting)

## CORRECT MIGRATION METHODOLOGY

### Phase 1: Implement Endpoints in Modular Handlers FIRST
For each endpoint in the monolith:

1. **Identify the endpoint** in `hexstrike_server.py`
2. **Copy the endpoint logic** to the appropriate modular handler:
   - Tool endpoints → `src/hexstrike/adapters/endpoints/tool_endpoints.py` or specialized handlers
   - CTF endpoints → `src/hexstrike/adapters/endpoints/ctf_endpoints.py`
   - Bug bounty → `src/hexstrike/adapters/endpoints/bugbounty_endpoints.py`
   - Intelligence → `src/hexstrike/adapters/endpoints/intelligence_endpoints.py`
   - Visual → `src/hexstrike/adapters/endpoints/visual_endpoints.py`
   - Process → `src/hexstrike/adapters/endpoints/process_endpoints.py`
   - Vuln intel → `src/hexstrike/adapters/endpoints/vuln_intel_endpoints.py`

3. **Update FlaskAdapter** in `src/hexstrike/adapters/flask_adapter.py` to register the new endpoint
4. **Test the endpoint works** via the modular route
5. **ONLY THEN remove** from `hexstrike_server.py`

### Phase 2: Extract Remaining Large Classes
Still need to extract from `hexstrike_server.py`:

1. **ModernVisualEngine** (334 lines) → `src/hexstrike/interfaces/visual_engine.py`
2. **IntelligentDecisionEngine** (970 lines) → Split into:
   - `src/hexstrike/services/intelligent_decision_engine.py` (≤300 lines)
   - `src/hexstrike/services/tool_effectiveness_manager.py`
   - `src/hexstrike/services/attack_chain_builder.py`
3. **CTFWorkflowManager** → `src/hexstrike/services/ctf/ctf_workflow_manager.py`
4. **BugBountyWorkflowManager** → `src/hexstrike/services/bugbounty/bugbounty_workflow_manager.py`

### Phase 3: Split Oversized Modules
Current modules exceeding 300 lines:
- `src/hexstrike/services/intelligent_decision_engine.py`: 405 lines
- `src/hexstrike/services/ctf/ctf_workflow_manager.py`: 319 lines  
- `src/hexstrike/services/bugbounty/bugbounty_workflow_manager.py`: 302 lines
- `src/hexstrike/adapters/flask_adapter.py`: 326 lines
- `src/hexstrike/adapters/endpoints/tool_endpoints.py`: 352 lines
- `src/hexstrike/adapters/endpoints/comprehensive_tool_endpoints.py`: 330 lines

## ENDPOINT MIGRATION PRIORITY LIST

### High Priority Tool Endpoints (80+ remaining):
```
/api/tools/nuclei
/api/tools/prowler  
/api/tools/rustscan
/api/tools/masscan
/api/tools/nmap-advanced
/api/tools/autorecon
/api/tools/enum4linux-ng
/api/tools/rpcclient
/api/tools/nbtscan
/api/tools/arp-scan
```

### CTF Endpoints (7+ remaining):
```
/api/ctf/create-challenge-workflow
/api/ctf/auto-solve-challenge
/api/ctf/team-strategy
/api/ctf/suggest-tools
/api/ctf/cryptography-solver
/api/ctf/forensics-analyzer
/api/ctf/binary-analyzer
```

### Bug Bounty Endpoints (6+ remaining):
```
/api/bugbounty/reconnaissance-workflow
/api/bugbounty/vulnerability-hunting-workflow
/api/bugbounty/business-logic-workflow
/api/bugbounty/osint-workflow
/api/bugbounty/file-upload-testing
/api/bugbounty/comprehensive-assessment
```

## VALIDATION COMMANDS

### Check Migration Status:
```bash
python check_migration_status.py
```

### Verify Line Limits:
```bash
find src/ -name "*.py" | xargs wc -l | awk '$1 > 300 {print $2 " exceeds 300 lines (" $1 ")"; exit 1}'
```

### Test Server Startup:
```bash
python hexstrike_server.py --port 8889
curl http://localhost:8889/health
```

## EXISTING MODULAR INFRASTRUCTURE

### Endpoint Handlers Ready:
- ✅ `src/hexstrike/adapters/endpoints/python_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/vuln_intel_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/advanced_process_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/ai_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/cache_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/command_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/comprehensive_tool_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/file_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/health_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/payload_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/process_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/tool_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/ctf_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/bugbounty_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/intelligence_endpoints.py`
- ✅ `src/hexstrike/adapters/endpoints/visual_endpoints.py`

### Flask Integration:
- ✅ `src/hexstrike/adapters/flask_adapter.py` (ready for endpoint registration)
- ✅ `src/hexstrike/legacy/compatibility_shims.py` (backward compatibility)

## SUCCESS CRITERIA
- [ ] 0 Flask endpoints remaining in `hexstrike_server.py`
- [ ] All modules ≤300 lines
- [ ] Server starts successfully
- [ ] All endpoints functional via modular routes
- [ ] Backward compatibility maintained
- [ ] CI pipeline passes

## EXECUTION COMMAND

```bash
# Start new Devin session with this prompt:
Execute complete HexStrike AI endpoint migration using CORRECT methodology:

1. MIGRATE endpoints from hexstrike_server.py to modular handlers FIRST
2. Update FlaskAdapter to register new endpoints  
3. Test functionality via modular routes
4. ONLY THEN remove from monolith
5. Extract remaining large classes (ModernVisualEngine, IntelligentDecisionEngine)
6. Split oversized modules to meet 300-line limit
7. Validate 100% migration completion

Current state: 98 endpoints in monolith, 6 oversized modules
Target: 0 endpoints in monolith, 0 oversized modules
Repository: drbothen/hexstrike-ai
Branch: devin/1755744065-hexstrike-modularization
PR: #2 (update existing, don't create new)

CRITICAL: Implement in modular handlers BEFORE removing from monolith!
```

## REPOSITORY STATE
- **Branch**: `devin/1755744065-hexstrike-modularization`
- **PR**: #2 (update existing)
- **Monolith**: `hexstrike_server.py` (13,447 lines, 98 endpoints)
- **Status**: Ready for proper endpoint migration
