# HexStrike AI - Requirements Specification

**Purpose:** Define Python dependencies for the modularized HexStrike AI framework with version pinning and security considerations.

**Status:** Proposed (based on analysis of hexstrike_server.py imports L21-L66)

## Core Dependencies

### requirements.txt
```txt
# Web Framework
Flask==2.3.3
Flask-CORS==4.0.0
Werkzeug==2.3.7

# HTTP and Networking
requests==2.31.0
urllib3==2.0.7
httpx==0.25.0

# Async and Concurrency
asyncio-mqtt==0.13.0
aiohttp==3.8.6

# Data Processing and Serialization
pydantic==2.4.2
marshmallow==3.20.1
jsonschema==4.19.1

# Database and Caching
redis==5.0.1
SQLAlchemy==2.0.23
alembic==1.12.1

# Security and Cryptography
cryptography==41.0.7
bcrypt==4.0.1
PyJWT==2.8.0
passlib==1.7.4

# System and Process Management
psutil==5.9.6
subprocess32==3.5.4; python_version < "3.3"

# Web Scraping and Browser Automation
selenium==4.15.2
beautifulsoup4==4.12.2
lxml==4.9.3
html5lib==1.1

# Network Security Tools Integration
python-nmap==0.7.1
scapy==2.5.0

# File and Data Handling
PyYAML==6.0.1
toml==0.10.2
configparser==6.0.0
python-dotenv==1.0.0

# Logging and Monitoring
structlog==23.2.0
colorlog==6.7.0

# Testing and Quality Assurance
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
pytest-mock==3.12.0

# Code Quality Tools
black==23.10.1
isort==5.12.0
flake8==6.1.0
mypy==1.7.0
bandit==1.7.5

# Documentation
Sphinx==7.2.6
sphinx-rtd-theme==1.3.0

# Development Utilities
ipython==8.17.2
jupyter==1.0.0
```

### Development Dependencies

#### requirements-dev.txt
```txt
# Include base requirements
-r requirements.txt

# Additional development tools
grimp==1.3.0                    # Import cycle detection
import-linter==1.12.0           # Layer dependency validation
radon==6.0.1                    # Code complexity analysis
safety==2.3.5                   # Security vulnerability scanning
pre-commit==3.5.0               # Git hooks for quality checks

# Performance and Profiling
memory-profiler==0.61.0
line-profiler==4.1.1
py-spy==0.3.14

# Database tools
pgcli==3.5.0                    # PostgreSQL CLI
redis-cli==3.5.3               # Redis CLI

# API testing
httpie==3.2.2
postman-cli==1.0.0

# Container and deployment
docker==6.1.3
kubernetes==28.1.0

# Monitoring and observability
prometheus-client==0.19.0
grafana-api==1.0.3
```

## Security Tool Dependencies

### requirements-security.txt
```txt
# Network scanning and reconnaissance
python-nmap==0.7.1
python-masscan==0.1.6
shodan==1.29.1

# Web application security
requests-oauthlib==1.3.1
requests-toolbelt==1.0.0
urllib3[secure]==2.0.7

# Cryptographic analysis
pycryptodome==3.19.0
cryptography==41.0.7
hashlib-compat==1.0.1

# Binary analysis support
capstone==5.0.1                 # Disassembly engine
keystone-engine==0.9.2          # Assembly engine
unicorn==2.0.1                  # CPU emulator

# Network protocol analysis
dpkt==1.9.8
pyshark==0.6
netaddr==0.9.0

# Forensics and steganography
pillow==10.1.0                  # Image processing
python-magic==0.4.27           # File type detection
exifread==3.0.0                 # EXIF data extraction
```

## Cloud and Container Dependencies

### requirements-cloud.txt
```txt
# AWS integration
boto3==1.34.0
botocore==1.34.0
awscli==1.32.0

# Azure integration
azure-identity==1.15.0
azure-mgmt-compute==30.4.0
azure-mgmt-network==25.2.0

# Google Cloud integration
google-cloud-compute==1.14.1
google-cloud-storage==2.10.0
google-auth==2.23.4

# Kubernetes integration
kubernetes==28.1.0
kubectl==1.28.0

# Container security
docker==6.1.3
podman-py==4.7.0

# Infrastructure as Code
terraform-compliance==1.3.44
checkov==3.0.0
```

## CTF and Binary Analysis Dependencies

### requirements-ctf.txt
```txt
# Binary analysis and reverse engineering
pwntools==4.11.0
ropper==1.13.8
capstone==5.0.1
keystone-engine==0.9.2
unicorn==2.0.1

# Cryptographic challenges
pycryptodome==3.19.0
gmpy2==2.1.5
sympy==1.12
sage-package==0.1.0             # Symbolic math

# Forensics and steganography
pillow==10.1.0
numpy==1.25.2
scipy==1.11.4
matplotlib==3.8.2

# Network analysis
scapy==2.5.0
dpkt==1.9.8
pyshark==0.6

# Web exploitation
requests==2.31.0
beautifulsoup4==4.12.2
selenium==4.15.2

# Miscellaneous CTF tools
z3-solver==4.12.2.0             # SMT solver
angr==9.2.77                    # Binary analysis platform
```

## Version Pinning Strategy

### Security Considerations
```txt
# Critical security packages - pin exact versions
cryptography==41.0.7           # Security-critical
PyJWT==2.8.0                   # Authentication tokens
requests==2.31.0               # HTTP security
urllib3==2.0.7                 # Network security

# Framework packages - pin minor versions
Flask>=2.3.0,<2.4.0           # Web framework stability
SQLAlchemy>=2.0.0,<2.1.0      # Database ORM stability

# Tool integration - allow patch updates
python-nmap>=0.7.0,<0.8.0     # Security tool integration
selenium>=4.15.0,<5.0.0        # Browser automation

# Development tools - allow minor updates
pytest>=7.4.0,<8.0.0          # Testing framework
black>=23.0.0,<24.0.0          # Code formatting
mypy>=1.7.0,<2.0.0             # Type checking
```

### Compatibility Matrix
```txt
# Python version compatibility
python_requires = ">=3.9,<4.0"

# Operating system compatibility
# Linux: Full support (primary target)
# macOS: Full support (development)
# Windows: Limited support (WSL recommended)

# Architecture compatibility
# x86_64: Full support
# ARM64: Limited support (some binary tools may not work)
```

## Installation Instructions

### Production Installation
```bash
# Create virtual environment
python -m venv hexstrike_env
source hexstrike_env/bin/activate  # Linux/macOS
# hexstrike_env\Scripts\activate   # Windows

# Install production dependencies
pip install -r requirements.txt

# Install security tools (optional)
pip install -r requirements-security.txt

# Install cloud dependencies (optional)
pip install -r requirements-cloud.txt
```

### Development Installation
```bash
# Install all dependencies including development tools
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Install CTF dependencies (optional)
pip install -r requirements-ctf.txt
```

### Docker Installation
```dockerfile
# Dockerfile for HexStrike AI
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements*.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/

# Set Python path
ENV PYTHONPATH=/app/src

# Expose port
EXPOSE 8888

# Run application
CMD ["python", "-m", "hexstrike.main"]
```

## Dependency Security Scanning

### Safety Configuration
```txt
# .safety-policy.json
{
  "security": {
    "ignore-vulnerabilities": [],
    "ignore-severity-rules": {
      "low": false,
      "medium": false,
      "high": false,
      "critical": false
    },
    "continue-on-vulnerability-error": false
  },
  "alert": {
    "ignore-vulnerabilities": [],
    "ignore-severity-rules": {
      "low": true,
      "medium": false,
      "high": false,
      "critical": false
    }
  }
}
```

### Automated Dependency Updates
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    assignees:
      - "maintainer"
    commit-message:
      prefix: "deps"
      include: "scope"
```

## Migration Notes

### From Monolith Dependencies
**Observed:** Current hexstrike_server.py imports (L21-L66):
- Flask, requests, selenium, beautifulsoup4, asyncio, threading, subprocess
- psutil, time, datetime, json, os, sys, re, base64, hashlib
- mitmproxy, concurrent.futures, pathlib, urllib.parse

**Proposed:** Modular dependency management:
- Core dependencies in main requirements.txt
- Optional feature dependencies in separate files
- Development dependencies isolated
- Security-focused version pinning

### Breaking Changes
- **None expected** - All current dependencies maintained
- **New additions** - Quality assurance and development tools
- **Version updates** - Security patches and stability improvements

---

**Note:** This requirements specification ensures secure, stable, and maintainable dependencies for the modularized HexStrike AI framework while maintaining compatibility with existing functionality.
