# HexStrike AI - Sample Configuration

**Purpose:** Sample configuration files for the modularized HexStrike AI framework, demonstrating all configuration options and best practices.

**Status:** Proposed (designed for modular architecture configuration)

## Main Configuration File

### config.yaml
```yaml
# HexStrike AI Framework Configuration
# This file contains all configuration options for the modularized framework

# Application Settings
app:
  name: "HexStrike AI"
  version: "2.0.0"
  environment: "development"  # development, staging, production
  debug: true
  
  # Server Configuration
  server:
    host: "0.0.0.0"
    port: 8888
    workers: 4
    timeout: 300
    max_request_size: "100MB"
    
  # Security Settings
  security:
    api_key_required: true
    rate_limit:
      enabled: true
      requests_per_minute: 100
      burst_limit: 20
    cors:
      enabled: true
      origins: ["http://localhost:3000", "https://hexstrike.ai"]
      methods: ["GET", "POST", "PUT", "DELETE"]
      headers: ["Content-Type", "Authorization", "X-API-Key"]

# Logging Configuration
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "%(asctime)s [%(levelname)8s] %(name)s: %(message)s"
  
  # Log Destinations
  handlers:
    console:
      enabled: true
      level: "INFO"
      format: "%(asctime)s [%(levelname)8s] %(name)s: %(message)s"
    
    file:
      enabled: true
      level: "DEBUG"
      filename: "logs/hexstrike.log"
      max_size: "10MB"
      backup_count: 5
      format: "%(asctime)s [%(levelname)8s] %(filename)s:%(lineno)d %(funcName)s(): %(message)s"
    
    syslog:
      enabled: false
      level: "WARNING"
      facility: "local0"
      address: ["localhost", 514]
  
  # Module-specific logging levels
  loggers:
    "hexstrike.services.decision_service": "DEBUG"
    "hexstrike.adapters.tool_registry": "INFO"
    "hexstrike.platform.errors": "WARNING"

# Database Configuration
database:
  # Primary database for application data
  primary:
    type: "postgresql"  # postgresql, mysql, sqlite
    host: "localhost"
    port: 5432
    database: "hexstrike"
    username: "hexstrike_user"
    password: "${DB_PASSWORD}"  # Environment variable
    pool_size: 10
    max_overflow: 20
    echo: false  # SQL query logging
  
  # Cache database (Redis)
  cache:
    type: "redis"
    host: "localhost"
    port: 6379
    database: 0
    password: "${REDIS_PASSWORD}"
    max_connections: 50
    socket_timeout: 5
    socket_connect_timeout: 5

# Process Management
process_management:
  # Process pool configuration
  pool:
    min_workers: 2
    max_workers: 20
    scale_threshold: 0.8
    worker_timeout: 300
    
  # Resource monitoring
  monitoring:
    enabled: true
    interval: 15  # seconds
    history_size: 1000
    
    # Resource thresholds
    thresholds:
      cpu_high: 80.0
      memory_high: 85.0
      disk_high: 90.0
      network_high: 80.0
  
  # Performance optimization
  optimization:
    auto_scaling: true
    resource_based_optimization: true
    cache_optimization: true

# Tool Configuration
tools:
  # Tool execution settings
  execution:
    default_timeout: 300
    max_concurrent_tools: 10
    retry_attempts: 3
    retry_delay: 5
    
  # Tool-specific configurations
  nmap:
    default_args: "-T4 -Pn"
    max_timeout: 1800
    stealth_args: "-T2 --max-retries 1"
    aggressive_args: "-T5 --min-rate 1000"
    
  gobuster:
    default_wordlist: "/usr/share/wordlists/dirb/common.txt"
    default_threads: 20
    max_threads: 100
    default_extensions: "php,html,txt,js"
    
  nuclei:
    template_path: "/opt/nuclei-templates"
    default_severity: "critical,high,medium"
    max_threads: 25
    rate_limit: 150
    
  sqlmap:
    default_level: 1
    default_risk: 1
    max_level: 5
    max_risk: 3
    default_threads: 5

# Intelligence Engine Configuration
intelligence:
  # Decision engine settings
  decision_engine:
    advanced_optimization: true
    effectiveness_learning: true
    confidence_threshold: 0.7
    
  # Target analysis
  target_analysis:
    dns_resolution_timeout: 10
    port_scan_timeout: 30
    technology_detection_timeout: 15
    
  # Tool selection
  tool_selection:
    max_tools_per_objective: 10
    effectiveness_weight: 0.6
    speed_weight: 0.3
    reliability_weight: 0.1

# Error Handling Configuration
error_handling:
  # Recovery settings
  recovery:
    enabled: true
    max_attempts: 3
    backoff_multiplier: 2.0
    max_backoff_delay: 60
    
  # Error classification
  classification:
    confidence_threshold: 0.8
    pattern_matching: true
    ml_classification: false  # Future feature
    
  # Escalation settings
  escalation:
    human_escalation_threshold: 3
    critical_error_immediate_escalation: true
    escalation_timeout: 300

# CTF Configuration
ctf:
  # Challenge analysis
  analysis:
    timeout: 600
    max_file_size: "100MB"
    supported_categories: ["web", "crypto", "pwn", "forensics", "rev", "misc", "osint"]
    
  # Tool paths
  tools:
    ghidra_path: "/opt/ghidra"
    radare2_path: "/usr/bin/r2"
    gdb_path: "/usr/bin/gdb"
    pwntools_python: "/usr/bin/python3"
    
  # Binary analysis
  binary_analysis:
    max_analysis_time: 1800
    enable_dynamic_analysis: true
    enable_symbolic_execution: false  # Resource intensive
    
  # Crypto analysis
  crypto_analysis:
    max_key_length: 4096
    enable_factorization: true
    factorization_timeout: 300

# Bug Bounty Configuration
bug_bounty:
  # Reconnaissance settings
  reconnaissance:
    max_subdomains: 10000
    dns_timeout: 10
    http_timeout: 30
    max_crawl_depth: 3
    
  # Workflow settings
  workflows:
    parallel_execution: true
    max_parallel_tools: 5
    result_correlation: true
    
  # Reporting
  reporting:
    auto_generate_reports: true
    include_screenshots: true
    vulnerability_scoring: true

# Cloud Security Configuration
cloud_security:
  # AWS Configuration
  aws:
    default_region: "us-east-1"
    profile: "default"
    max_concurrent_checks: 10
    
  # Azure Configuration
  azure:
    subscription_id: "${AZURE_SUBSCRIPTION_ID}"
    tenant_id: "${AZURE_TENANT_ID}"
    
  # GCP Configuration
  gcp:
    project_id: "${GCP_PROJECT_ID}"
    credentials_path: "${GCP_CREDENTIALS_PATH}"
    
  # Kubernetes Configuration
  kubernetes:
    config_path: "~/.kube/config"
    namespace: "default"
    timeout: 300

# API Configuration
api:
  # Versioning
  version: "v1"
  base_path: "/api/v1"
  
  # Documentation
  docs:
    enabled: true
    swagger_ui: true
    redoc: true
    openapi_url: "/api/v1/openapi.json"
    
  # Rate limiting
  rate_limiting:
    storage: "redis"  # redis, memory
    key_func: "ip_and_api_key"
    
  # Response formatting
  response:
    include_timestamp: true
    include_request_id: true
    pretty_json: true

# Caching Configuration
caching:
  # Cache backends
  backends:
    default: "redis"
    session: "redis"
    tool_results: "redis"
    
  # Cache settings
  settings:
    default_ttl: 3600  # 1 hour
    max_key_length: 250
    key_prefix: "hexstrike:"
    
  # Cache policies
  policies:
    tool_results:
      ttl: 7200  # 2 hours
      max_size: "100MB"
    
    target_analysis:
      ttl: 1800  # 30 minutes
      max_size: "50MB"

# Security Configuration
security:
  # Encryption
  encryption:
    algorithm: "AES-256-GCM"
    key_derivation: "PBKDF2"
    iterations: 100000
    
  # API Keys
  api_keys:
    length: 32
    algorithm: "HS256"
    expiration: 2592000  # 30 days
    
  # Input validation
  input_validation:
    max_string_length: 10000
    max_array_length: 1000
    sanitize_html: true
    validate_urls: true
    
  # Command execution security
  command_execution:
    sandbox_enabled: true
    allowed_commands: ["nmap", "gobuster", "nuclei", "sqlmap"]
    command_timeout: 3600
    resource_limits:
      max_memory: "2GB"
      max_cpu_time: 1800

# Monitoring and Metrics
monitoring:
  # Metrics collection
  metrics:
    enabled: true
    backend: "prometheus"  # prometheus, statsd, datadog
    port: 9090
    
  # Health checks
  health_checks:
    enabled: true
    endpoint: "/health"
    checks:
      - "database"
      - "redis"
      - "disk_space"
      - "memory_usage"
    
  # Alerting
  alerting:
    enabled: false
    webhook_url: "${ALERT_WEBHOOK_URL}"
    channels: ["email", "slack"]

# Development Settings
development:
  # Debug settings
  debug:
    enabled: true
    profiling: false
    sql_echo: false
    
  # Hot reload
  hot_reload:
    enabled: true
    watch_directories: ["src/hexstrike"]
    ignore_patterns: ["*.pyc", "__pycache__", ".git"]
    
  # Testing
  testing:
    mock_external_tools: true
    test_data_path: "tests/fixtures"
    coverage_threshold: 80

# Production Settings
production:
  # Performance
  performance:
    preload_modules: true
    optimize_imports: true
    enable_caching: true
    
  # Security
  security:
    strict_mode: true
    hide_error_details: true
    secure_headers: true
    
  # Monitoring
  monitoring:
    detailed_logging: false
    performance_monitoring: true
    error_tracking: true
```

## Environment-Specific Configurations

### config/development.yaml
```yaml
# Development environment overrides
app:
  debug: true
  environment: "development"

logging:
  level: "DEBUG"
  handlers:
    console:
      level: "DEBUG"

database:
  primary:
    echo: true  # Enable SQL logging in development
    
tools:
  execution:
    default_timeout: 60  # Shorter timeouts for development

development:
  debug:
    enabled: true
    profiling: true
  hot_reload:
    enabled: true
  testing:
    mock_external_tools: true
```

### config/production.yaml
```yaml
# Production environment overrides
app:
  debug: false
  environment: "production"
  server:
    workers: 8

logging:
  level: "WARNING"
  handlers:
    console:
      level: "ERROR"
    file:
      level: "INFO"

security:
  api_keys:
    expiration: 604800  # 7 days in production

production:
  performance:
    preload_modules: true
    optimize_imports: true
  security:
    strict_mode: true
    hide_error_details: true
  monitoring:
    detailed_logging: false
    performance_monitoring: true
```

## Environment Variables Template

### .env.example
```bash
# HexStrike AI Environment Variables
# Copy this file to .env and fill in your values

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=hexstrike
DB_USER=hexstrike_user
DB_PASSWORD=your_secure_password_here

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password_here

# API Security
API_SECRET_KEY=your_very_long_and_secure_secret_key_here
JWT_SECRET_KEY=another_very_secure_secret_for_jwt_tokens

# Cloud Provider Credentials
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=us-east-1

AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
AZURE_TENANT_ID=your_azure_tenant_id
AZURE_SUBSCRIPTION_ID=your_azure_subscription_id

GCP_PROJECT_ID=your_gcp_project_id
GCP_CREDENTIALS_PATH=/path/to/gcp/credentials.json

# External Service APIs
SHODAN_API_KEY=your_shodan_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret

# Monitoring and Alerting
SENTRY_DSN=your_sentry_dsn_here
SLACK_WEBHOOK_URL=your_slack_webhook_url
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=your_email@gmail.com
EMAIL_PASSWORD=your_email_password

# Development Settings
FLASK_ENV=development
FLASK_DEBUG=1
PYTHONPATH=/app/src

# Security Tool Paths (if not in PATH)
NMAP_PATH=/usr/bin/nmap
GOBUSTER_PATH=/usr/bin/gobuster
NUCLEI_PATH=/usr/bin/nuclei
SQLMAP_PATH=/usr/bin/sqlmap

# CTF Tool Paths
GHIDRA_PATH=/opt/ghidra
RADARE2_PATH=/usr/bin/r2
GDB_PATH=/usr/bin/gdb
PWNTOOLS_PYTHON=/usr/bin/python3

# Optional: Custom wordlists and templates
WORDLIST_PATH=/usr/share/wordlists
NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates
CUSTOM_PAYLOADS_PATH=/opt/custom-payloads
```

## Docker Configuration

### docker-compose.yml
```yaml
version: '3.8'

services:
  hexstrike:
    build: .
    ports:
      - "8888:8888"
    environment:
      - FLASK_ENV=production
      - DB_HOST=postgres
      - REDIS_HOST=redis
    env_file:
      - .env
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
      - ./data:/app/data
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: hexstrike
      POSTGRES_USER: hexstrike_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    restart: unless-stopped
    
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    restart: unless-stopped
    
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana:/etc/grafana/provisioning
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:
```

## Configuration Validation

### config_validator.py
```python
"""
Configuration validation for HexStrike AI framework.
"""

from typing import Dict, Any, List
import yaml
import os
from pathlib import Path

class ConfigValidator:
    """Validate configuration files and environment variables."""
    
    REQUIRED_SECTIONS = [
        'app', 'logging', 'database', 'process_management',
        'tools', 'intelligence', 'error_handling'
    ]
    
    REQUIRED_ENV_VARS = [
        'DB_PASSWORD', 'REDIS_PASSWORD', 'API_SECRET_KEY'
    ]
    
    def validate_config_file(self, config_path: str) -> List[str]:
        """Validate configuration file structure and values."""
        errors = []
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            return [f"Failed to load config file: {e}"]
        
        # Check required sections
        for section in self.REQUIRED_SECTIONS:
            if section not in config:
                errors.append(f"Missing required section: {section}")
        
        # Validate specific settings
        if 'app' in config:
            app_config = config['app']
            if 'server' in app_config:
                server_config = app_config['server']
                port = server_config.get('port', 8888)
                if not isinstance(port, int) or port < 1 or port > 65535:
                    errors.append("Invalid server port")
        
        return errors
    
    def validate_environment(self) -> List[str]:
        """Validate required environment variables."""
        errors = []
        
        for env_var in self.REQUIRED_ENV_VARS:
            if not os.getenv(env_var):
                errors.append(f"Missing required environment variable: {env_var}")
        
        return errors
    
    def validate_tool_paths(self, config: Dict[str, Any]) -> List[str]:
        """Validate that required tools are available."""
        errors = []
        
        required_tools = ['nmap', 'gobuster', 'nuclei']
        
        for tool in required_tools:
            tool_path = config.get('tools', {}).get(tool, {}).get('path')
            if tool_path and not Path(tool_path).exists():
                errors.append(f"Tool not found at specified path: {tool_path}")
        
        return errors

# Usage example
if __name__ == "__main__":
    validator = ConfigValidator()
    
    config_errors = validator.validate_config_file("config.yaml")
    env_errors = validator.validate_environment()
    
    all_errors = config_errors + env_errors
    
    if all_errors:
        print("Configuration validation failed:")
        for error in all_errors:
            print(f"  - {error}")
        exit(1)
    else:
        print("Configuration validation passed!")
```

---

**Note:** This sample configuration provides comprehensive settings for the modularized HexStrike AI framework, covering all aspects from basic application settings to advanced security and monitoring configurations.
