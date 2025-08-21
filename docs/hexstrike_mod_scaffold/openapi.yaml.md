# HexStrike AI - OpenAPI Specification

**Purpose:** Complete OpenAPI 3.0 specification for the modularized HexStrike AI framework REST API, documenting all endpoints, schemas, and security requirements.

**Status:** Proposed (based on analysis of Flask endpoints in hexstrike_server.py L7000+)

## OpenAPI Specification

### openapi.yaml
```yaml
openapi: 3.0.3
info:
  title: HexStrike AI - Penetration Testing Framework API
  description: |
    HexStrike AI is a comprehensive penetration testing framework that provides
    AI-powered tool selection, parameter optimization, and automated security
    testing workflows for web applications, networks, cloud services, and CTF challenges.
    
    ## Features
    - Intelligent tool selection and parameter optimization
    - Automated vulnerability scanning and assessment
    - CTF challenge automation and analysis
    - Bug bounty reconnaissance workflows
    - Cloud security assessment tools
    - Real-time process management and monitoring
    
    ## Authentication
    API key authentication is required for all endpoints. Include your API key
    in the `X-API-Key` header.
    
    ## Rate Limiting
    API requests are rate limited to 100 requests per minute per API key.
    
  version: 1.0.0
  contact:
    name: HexStrike AI Support
    url: https://github.com/drbothen/hexstrike-ai
    email: support@hexstrike.ai
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: http://localhost:8888/api/v1
    description: Local development server
  - url: https://api.hexstrike.ai/v1
    description: Production server

security:
  - ApiKeyAuth: []

paths:
  # Tool Execution Endpoints
  /tools/execute:
    post:
      summary: Execute Security Tool
      description: Execute a security tool with specified parameters and intelligent error recovery
      operationId: executeTool
      tags:
        - Tool Execution
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ToolExecutionRequest'
            examples:
              nmap_scan:
                summary: Nmap network scan
                value:
                  tool_name: "nmap"
                  parameters:
                    target: "example.com"
                    scan_type: "-sV -sC"
                    ports: "1-1000"
                  use_recovery: true
                  timeout: 300
              gobuster_scan:
                summary: Gobuster directory scan
                value:
                  tool_name: "gobuster"
                  parameters:
                    url: "https://example.com"
                    mode: "dir"
                    wordlist: "/usr/share/wordlists/dirb/common.txt"
                  use_recovery: true
                  timeout: 600
      responses:
        '200':
          description: Tool execution completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ToolExecutionResponse'
        '400':
          description: Invalid request parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '429':
          description: Rate limit exceeded
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '500':
          description: Internal server error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

  # Intelligence Endpoints
  /intelligence/analyze-target:
    post:
      summary: Analyze Target
      description: Analyze a target and create comprehensive profile using AI-powered analysis
      operationId: analyzeTarget
      tags:
        - Intelligence
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TargetAnalysisRequest'
      responses:
        '200':
          description: Target analysis completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TargetAnalysisResponse'

  /intelligence/select-tools:
    post:
      summary: Select Optimal Tools
      description: Select optimal security tools based on target profile and objective
      operationId: selectOptimalTools
      tags:
        - Intelligence
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ToolSelectionRequest'
      responses:
        '200':
          description: Tool selection completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ToolSelectionResponse'

  /intelligence/create-attack-chain:
    post:
      summary: Create Attack Chain
      description: Create an intelligent attack chain based on target profile
      operationId: createAttackChain
      tags:
        - Intelligence
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AttackChainRequest'
      responses:
        '200':
          description: Attack chain created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AttackChainResponse'

  /intelligence/smart-scan:
    post:
      summary: Intelligent Smart Scan
      description: Execute comprehensive scan using AI-driven tool selection and parallel execution
      operationId: intelligentSmartScan
      tags:
        - Intelligence
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SmartScanRequest'
      responses:
        '200':
          description: Smart scan completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SmartScanResponse'

  # Process Management Endpoints
  /processes:
    get:
      summary: List Active Processes
      description: Get list of all active processes with status information
      operationId: listActiveProcesses
      tags:
        - Process Management
      responses:
        '200':
          description: Active processes retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProcessListResponse'

  /processes/{pid}:
    get:
      summary: Get Process Status
      description: Get detailed status information for a specific process
      operationId: getProcessStatus
      tags:
        - Process Management
      parameters:
        - name: pid
          in: path
          required: true
          schema:
            type: integer
          description: Process ID
      responses:
        '200':
          description: Process status retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProcessStatusResponse'
        '404':
          description: Process not found

  /processes/{pid}/terminate:
    post:
      summary: Terminate Process
      description: Terminate a specific process
      operationId: terminateProcess
      tags:
        - Process Management
      parameters:
        - name: pid
          in: path
          required: true
          schema:
            type: integer
          description: Process ID
      responses:
        '200':
          description: Process terminated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SuccessResponse'

  # CTF Endpoints
  /ctf/analyze-challenge:
    post:
      summary: Analyze CTF Challenge
      description: Analyze a CTF challenge and suggest appropriate tools and strategies
      operationId: analyzeCTFChallenge
      tags:
        - CTF
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CTFChallengeRequest'
      responses:
        '200':
          description: CTF challenge analysis completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CTFChallengeResponse'

  /ctf/crypto-solver:
    post:
      summary: CTF Crypto Solver
      description: Analyze and solve cryptographic challenges using AI-powered techniques
      operationId: ctfCryptoSolver
      tags:
        - CTF
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CTFCryptoRequest'
      responses:
        '200':
          description: Crypto analysis completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CTFCryptoResponse'

  # Bug Bounty Endpoints
  /bugbounty/reconnaissance:
    post:
      summary: Bug Bounty Reconnaissance
      description: Create and execute comprehensive reconnaissance workflow for bug bounty targets
      operationId: bugBountyReconnaissance
      tags:
        - Bug Bounty
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BugBountyReconRequest'
      responses:
        '200':
          description: Reconnaissance workflow created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BugBountyReconResponse'

  # Vulnerability Intelligence Endpoints
  /vuln-intel/cve-monitor:
    post:
      summary: CVE Monitoring
      description: Monitor CVE databases for new vulnerabilities with AI analysis
      operationId: cveMonitor
      tags:
        - Vulnerability Intelligence
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CVEMonitorRequest'
      responses:
        '200':
          description: CVE monitoring completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CVEMonitorResponse'

  /vuln-intel/exploit-generate:
    post:
      summary: Generate Exploits
      description: Generate exploits from vulnerability data using AI
      operationId: generateExploits
      tags:
        - Vulnerability Intelligence
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ExploitGenerationRequest'
      responses:
        '200':
          description: Exploit generation completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ExploitGenerationResponse'

components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

  schemas:
    # Request Schemas
    ToolExecutionRequest:
      type: object
      required:
        - tool_name
        - parameters
      properties:
        tool_name:
          type: string
          description: Name of the security tool to execute
          example: "nmap"
        parameters:
          type: object
          description: Tool-specific parameters
          additionalProperties: true
          example:
            target: "example.com"
            scan_type: "-sV -sC"
            ports: "1-1000"
        use_recovery:
          type: boolean
          description: Enable intelligent error recovery
          default: true
        timeout:
          type: integer
          description: Execution timeout in seconds
          default: 300
          minimum: 1
          maximum: 3600
        context:
          type: object
          description: Additional context for execution
          additionalProperties: true

    TargetAnalysisRequest:
      type: object
      required:
        - target
      properties:
        target:
          type: string
          description: Target to analyze (URL, IP, domain)
          example: "example.com"
        context:
          type: object
          description: Additional context for analysis
          additionalProperties: true

    ToolSelectionRequest:
      type: object
      required:
        - target
      properties:
        target:
          type: string
          description: Target for tool selection
          example: "example.com"
        objective:
          type: string
          description: Scanning objective
          enum: ["comprehensive", "quick", "stealth", "ctf", "bug_bounty"]
          default: "comprehensive"
        max_tools:
          type: integer
          description: Maximum number of tools to select
          default: 5
          minimum: 1
          maximum: 20

    AttackChainRequest:
      type: object
      required:
        - target
      properties:
        target:
          type: string
          description: Target for attack chain creation
          example: "example.com"
        objective:
          type: string
          description: Attack objective
          enum: ["comprehensive", "quick", "stealth"]
          default: "comprehensive"

    SmartScanRequest:
      type: object
      required:
        - target
      properties:
        target:
          type: string
          description: Target for smart scan
          example: "example.com"
        objective:
          type: string
          description: Scanning objective
          enum: ["comprehensive", "quick", "stealth"]
          default: "comprehensive"
        max_tools:
          type: integer
          description: Maximum number of tools to execute
          default: 5
          minimum: 1
          maximum: 10

    CTFChallengeRequest:
      type: object
      required:
        - challenge_name
        - category
      properties:
        challenge_name:
          type: string
          description: Name of the CTF challenge
          example: "crypto_challenge_1"
        category:
          type: string
          description: Challenge category
          enum: ["web", "crypto", "pwn", "forensics", "rev", "misc", "osint"]
        description:
          type: string
          description: Challenge description
        files:
          type: array
          items:
            type: string
          description: Challenge files
        hints:
          type: array
          items:
            type: string
          description: Available hints

    CTFCryptoRequest:
      type: object
      required:
        - cipher_text
      properties:
        cipher_text:
          type: string
          description: Encrypted text to analyze
        cipher_type:
          type: string
          description: Suspected cipher type
          enum: ["caesar", "vigenere", "rsa", "aes", "des", "unknown"]
          default: "unknown"
        additional_info:
          type: string
          description: Additional information about the cipher

    BugBountyReconRequest:
      type: object
      required:
        - domain
      properties:
        domain:
          type: string
          description: Target domain for reconnaissance
          example: "example.com"
        scope:
          type: array
          items:
            type: string
          description: In-scope domains and subdomains
        exclusions:
          type: array
          items:
            type: string
          description: Out-of-scope domains and paths
        priority_vulns:
          type: array
          items:
            type: string
          description: Priority vulnerability types to focus on

    CVEMonitorRequest:
      type: object
      properties:
        hours:
          type: integer
          description: Hours to look back for new CVEs
          default: 24
          minimum: 1
          maximum: 168
        severity_filter:
          type: string
          description: Severity filter for CVEs
          default: "HIGH,CRITICAL"
        keywords:
          type: string
          description: Keywords to filter CVEs

    ExploitGenerationRequest:
      type: object
      required:
        - cve_id
      properties:
        cve_id:
          type: string
          description: CVE identifier
          example: "CVE-2024-1234"
        target_os:
          type: string
          description: Target operating system
          enum: ["linux", "windows", "macos", "unknown"]
        target_arch:
          type: string
          description: Target architecture
          enum: ["x86", "x64", "arm", "arm64"]
          default: "x64"
        exploit_type:
          type: string
          description: Type of exploit to generate
          enum: ["poc", "weaponized", "metasploit"]
          default: "poc"

    # Response Schemas
    ToolExecutionResponse:
      type: object
      properties:
        success:
          type: boolean
          description: Whether the tool execution was successful
        result:
          $ref: '#/components/schemas/ExecutionResult'
        timestamp:
          type: string
          format: date-time
          description: Execution timestamp

    ExecutionResult:
      type: object
      properties:
        success:
          type: boolean
        stdout:
          type: string
          description: Tool standard output
        stderr:
          type: string
          description: Tool standard error
        return_code:
          type: integer
          description: Tool exit code
        execution_time:
          type: number
          format: float
          description: Execution time in seconds
        parsed_output:
          type: object
          description: Parsed tool output
          additionalProperties: true
        recovery_info:
          type: object
          description: Recovery information if error recovery was used
          additionalProperties: true

    TargetAnalysisResponse:
      type: object
      properties:
        success:
          type: boolean
        target_profile:
          $ref: '#/components/schemas/TargetProfile'
        timestamp:
          type: string
          format: date-time

    TargetProfile:
      type: object
      properties:
        target:
          type: string
        target_type:
          type: string
          enum: ["web_application", "network_host", "api_endpoint", "cloud_service", "binary_file"]
        ip_addresses:
          type: array
          items:
            type: string
        open_ports:
          type: array
          items:
            type: integer
        services:
          type: object
          additionalProperties:
            type: string
        technologies:
          type: array
          items:
            type: string
        attack_surface_score:
          type: number
          format: float
          minimum: 0
          maximum: 10
        risk_level:
          type: string
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        confidence_score:
          type: number
          format: float
          minimum: 0
          maximum: 1

    ToolSelectionResponse:
      type: object
      properties:
        success:
          type: boolean
        target:
          type: string
        objective:
          type: string
        target_profile:
          $ref: '#/components/schemas/TargetProfile'
        selected_tools:
          type: array
          items:
            type: string
        tool_count:
          type: integer
        timestamp:
          type: string
          format: date-time

    AttackChainResponse:
      type: object
      properties:
        success:
          type: boolean
        target:
          type: string
        objective:
          type: string
        target_profile:
          $ref: '#/components/schemas/TargetProfile'
        attack_chain:
          $ref: '#/components/schemas/AttackChain'
        timestamp:
          type: string
          format: date-time

    AttackChain:
      type: object
      properties:
        steps:
          type: array
          items:
            $ref: '#/components/schemas/AttackStep'
        success_probability:
          type: number
          format: float
          minimum: 0
          maximum: 1
        estimated_time:
          type: integer
          description: Estimated execution time in seconds
        risk_level:
          type: string
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    AttackStep:
      type: object
      properties:
        tool:
          type: string
        parameters:
          type: object
          additionalProperties: true
        expected_outcome:
          type: string
        success_probability:
          type: number
          format: float
          minimum: 0
          maximum: 1
        execution_time_estimate:
          type: integer

    SmartScanResponse:
      type: object
      properties:
        success:
          type: boolean
        target:
          type: string
        target_profile:
          $ref: '#/components/schemas/TargetProfile'
        tools_executed:
          type: array
          items:
            $ref: '#/components/schemas/ToolExecutionResult'
        total_vulnerabilities:
          type: integer
        execution_summary:
          $ref: '#/components/schemas/ExecutionSummary'
        combined_output:
          type: string
        timestamp:
          type: string
          format: date-time

    ToolExecutionResult:
      type: object
      properties:
        tool:
          type: string
        parameters:
          type: object
          additionalProperties: true
        status:
          type: string
          enum: ["success", "failed", "skipped"]
        timestamp:
          type: string
          format: date-time
        execution_time:
          type: number
          format: float
        stdout:
          type: string
        stderr:
          type: string
        vulnerabilities_found:
          type: integer
        command:
          type: string
        success:
          type: boolean

    ExecutionSummary:
      type: object
      properties:
        total_tools:
          type: integer
        successful_tools:
          type: integer
        failed_tools:
          type: integer
        success_rate:
          type: number
          format: float
        total_execution_time:
          type: number
          format: float
        tools_used:
          type: array
          items:
            type: string

    ProcessListResponse:
      type: object
      properties:
        success:
          type: boolean
        processes:
          type: array
          items:
            $ref: '#/components/schemas/ProcessInfo'
        total_processes:
          type: integer
        timestamp:
          type: string
          format: date-time

    ProcessStatusResponse:
      type: object
      properties:
        success:
          type: boolean
        process:
          $ref: '#/components/schemas/ProcessInfo'
        timestamp:
          type: string
          format: date-time

    ProcessInfo:
      type: object
      properties:
        pid:
          type: integer
        command:
          type: string
        status:
          type: string
          enum: ["running", "paused", "terminated", "completed"]
        runtime:
          type: string
        progress_percent:
          type: string
        progress_bar:
          type: string
        eta:
          type: string
        bytes_processed:
          type: integer
        last_output:
          type: string

    CTFChallengeResponse:
      type: object
      properties:
        success:
          type: boolean
        analysis:
          $ref: '#/components/schemas/CTFAnalysis'
        timestamp:
          type: string
          format: date-time

    CTFAnalysis:
      type: object
      properties:
        challenge_name:
          type: string
        category:
          type: string
        difficulty_estimate:
          type: string
          enum: ["easy", "medium", "hard", "insane"]
        recommended_tools:
          type: array
          items:
            type: string
        suggested_approach:
          type: array
          items:
            type: string
        time_estimate:
          type: integer
          description: Estimated solve time in minutes

    CTFCryptoResponse:
      type: object
      properties:
        success:
          type: boolean
        analysis:
          $ref: '#/components/schemas/CryptoAnalysis'
        timestamp:
          type: string
          format: date-time

    CryptoAnalysis:
      type: object
      properties:
        cipher_type:
          type: string
        confidence:
          type: number
          format: float
          minimum: 0
          maximum: 1
        recommended_tools:
          type: array
          items:
            type: string
        next_steps:
          type: array
          items:
            type: string
        potential_solutions:
          type: array
          items:
            type: string

    BugBountyReconResponse:
      type: object
      properties:
        success:
          type: boolean
        workflow:
          $ref: '#/components/schemas/ReconWorkflow'
        timestamp:
          type: string
          format: date-time

    ReconWorkflow:
      type: object
      properties:
        target:
          type: string
        phases:
          type: array
          items:
            $ref: '#/components/schemas/ReconPhase'
        estimated_time:
          type: integer
        tools_count:
          type: integer

    ReconPhase:
      type: object
      properties:
        name:
          type: string
        description:
          type: string
        tools:
          type: array
          items:
            type: object
            properties:
              tool:
                type: string
              params:
                type: object
                additionalProperties: true
        expected_outputs:
          type: array
          items:
            type: string
        estimated_time:
          type: integer

    CVEMonitorResponse:
      type: object
      properties:
        success:
          type: boolean
        cve_monitoring:
          $ref: '#/components/schemas/CVEMonitoringResult'
        exploitability_analysis:
          type: array
          items:
            $ref: '#/components/schemas/ExploitabilityAnalysis'
        timestamp:
          type: string
          format: date-time

    CVEMonitoringResult:
      type: object
      properties:
        total_cves:
          type: integer
        cves:
          type: array
          items:
            $ref: '#/components/schemas/CVEInfo'
        timeframe:
          type: string
        severity_filter:
          type: string

    CVEInfo:
      type: object
      properties:
        cve_id:
          type: string
        description:
          type: string
        severity:
          type: string
        cvss_score:
          type: number
          format: float
        published_date:
          type: string
          format: date-time

    ExploitabilityAnalysis:
      type: object
      properties:
        cve_id:
          type: string
        exploitability_level:
          type: string
          enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        exploitability_score:
          type: number
          format: float
          minimum: 0
          maximum: 10
        existing_exploits:
          type: integer
        analysis_details:
          type: object
          additionalProperties: true

    ExploitGenerationResponse:
      type: object
      properties:
        success:
          type: boolean
        cve_analysis:
          $ref: '#/components/schemas/ExploitabilityAnalysis'
        exploit_generation:
          $ref: '#/components/schemas/ExploitGenerationResult'
        existing_exploits:
          $ref: '#/components/schemas/ExistingExploitsInfo'
        target_info:
          type: object
          additionalProperties: true
        timestamp:
          type: string
          format: date-time

    ExploitGenerationResult:
      type: object
      properties:
        success:
          type: boolean
        cve_id:
          type: string
        vulnerability_type:
          type: string
        exploit_code:
          type: string
        parameters:
          type: object
          additionalProperties: true
        instructions:
          type: string
        evasion_applied:
          type: string

    ExistingExploitsInfo:
      type: object
      properties:
        total_exploits:
          type: integer
        exploit_sources:
          type: array
          items:
            type: string
        exploit_types:
          type: array
          items:
            type: string

    # Common Schemas
    SuccessResponse:
      type: object
      properties:
        success:
          type: boolean
        message:
          type: string
        timestamp:
          type: string
          format: date-time

    ErrorResponse:
      type: object
      properties:
        success:
          type: boolean
          example: false
        error:
          type: string
          description: Error message
        error_code:
          type: string
          description: Machine-readable error code
        timestamp:
          type: string
          format: date-time

  # Response Headers
  headers:
    X-RateLimit-Limit:
      description: Request limit per minute
      schema:
        type: integer
    X-RateLimit-Remaining:
      description: Remaining requests in current window
      schema:
        type: integer
    X-RateLimit-Reset:
      description: Time when rate limit resets (Unix timestamp)
      schema:
        type: integer

tags:
  - name: Tool Execution
    description: Execute security tools with intelligent parameter optimization
  - name: Intelligence
    description: AI-powered target analysis and tool selection
  - name: Process Management
    description: Manage and monitor running processes
  - name: CTF
    description: CTF challenge analysis and automation
  - name: Bug Bounty
    description: Bug bounty reconnaissance and workflow automation
  - name: Vulnerability Intelligence
    description: CVE monitoring and exploit generation

externalDocs:
  description: HexStrike AI Documentation
  url: https://docs.hexstrike.ai
```

## API Usage Examples

### Tool Execution Example
```bash
curl -X POST "http://localhost:8888/api/v1/tools/execute" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "nmap",
    "parameters": {
      "target": "example.com",
      "scan_type": "-sV -sC",
      "ports": "1-1000"
    },
    "use_recovery": true,
    "timeout": 300
  }'
```

### Smart Scan Example
```bash
curl -X POST "http://localhost:8888/api/v1/intelligence/smart-scan" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "objective": "comprehensive",
    "max_tools": 5
  }'
```

### CTF Challenge Analysis Example
```bash
curl -X POST "http://localhost:8888/api/v1/ctf/analyze-challenge" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge_name": "crypto_challenge_1",
    "category": "crypto",
    "description": "Decrypt the message using the given key",
    "files": ["encrypted.txt", "key.txt"]
  }'
```

---

**Note:** This OpenAPI specification provides complete documentation for the modularized HexStrike AI framework API, enabling automatic client generation, interactive documentation, and comprehensive API testing.
