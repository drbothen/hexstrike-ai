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
    print(f"❌ Critical Error: Modular components not available ({e})")
    print("❌ Cannot start HexStrike AI - modular architecture is required")
    sys.exit(1)


from src.hexstrike.interfaces.visual_engine import ModernVisualEngine

# ============================================================================
# INTELLIGENT DECISION ENGINE (v6.0 ENHANCEMENT)
# ============================================================================

from src.hexstrike.models.target_models import TargetType, TechnologyStack, TargetProfile, AttackStep, AttackChain



# Global decision engine instance (using compatibility shim)
decision_engine = None  # Will be initialized in modular mode

# ============================================================================
# INTELLIGENT ERROR HANDLING AND RECOVERY SYSTEM (v11.0 ENHANCEMENT)
# ============================================================================

from enum import Enum
from dataclasses import dataclass
from typing import Callable, Union
import traceback
import time
import random

from src.hexstrike.services.recovery_strategy import ErrorType, RecoveryAction, ErrorContext, RecoveryStrategy


# Global error handler and degradation manager instances
from src.hexstrike.services.error_handler import IntelligentErrorHandler
from src.hexstrike.services.graceful_degradation import GracefulDegradation

error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()

# ============================================================================
# BUG BOUNTY HUNTING SPECIALIZED WORKFLOWS (v6.0 ENHANCEMENT)
# ============================================================================


from src.hexstrike.services.file_upload_testing import FileUploadTestingFramework

# Global bug bounty workflow manager
fileupload_framework = FileUploadTestingFramework()

# ============================================================================
# CTF COMPETITION EXCELLENCE FRAMEWORK (v6.0 ENHANCEMENT)
# ============================================================================

from src.hexstrike.models.ctf_models import CTFChallenge

from src.hexstrike.services.ctf.ctf_workflow_manager import CTFWorkflowManager



# ============================================================================
# ADVANCED PARAMETER OPTIMIZATION AND INTELLIGENCE (v9.0 ENHANCEMENT)
# ============================================================================

from src.hexstrike.services.rate_limit_detector import RateLimitDetector

from src.hexstrike.services.failure_recovery_system import FailureRecoverySystem

from src.hexstrike.services.performance_monitor import PerformanceMonitor

from src.hexstrike.services.advanced_cache import AdvancedCache

from src.hexstrike.services.enhanced_process_manager import EnhancedProcessManager

# ResourceMonitor extracted to src/hexstrike/services/resource_monitor.py
from src.hexstrike.services.resource_monitor import ResourceMonitor

from src.hexstrike.services.performance_dashboard import PerformanceDashboard

# Global instances
rate_limiter = RateLimitDetector()
failure_recovery = FailureRecoverySystem()


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
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['CYBER_ORANGE']}🌐 Port:{ModernVisualEngine.COLORS['RESET']} {args.port}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['WARNING']}🔧 Debug Mode:{ModernVisualEngine.COLORS['RESET']} {args.debug}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}🏗️  Modular Mode:{ModernVisualEngine.COLORS['RESET']} {args.modular}
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['ELECTRIC_PURPLE']}💾 Cache Size:{ModernVisualEngine.COLORS['RESET']} 1000 | TTL: 3600s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['TERMINAL_GRAY']}⏱️  Command Timeout:{ModernVisualEngine.COLORS['RESET']} 300s
{ModernVisualEngine.COLORS['BOLD']}│{ModernVisualEngine.COLORS['RESET']} {ModernVisualEngine.COLORS['MATRIX_GREEN']}✨ Enhanced Visual Engine:{ModernVisualEngine.COLORS['RESET']} Active
{ModernVisualEngine.COLORS['MATRIX_GREEN']}{ModernVisualEngine.COLORS['BOLD']}╰─────────────────────────────────────────────────────────────────────────────╯{ModernVisualEngine.COLORS['RESET']}
"""
    
    for line in startup_info.strip().split('\n'):
        if line.strip():
            logger.info(line)
    

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
            modular_app.run(host=API_HOST, port=args.port, debug=args.debug)
            
        except ImportError as e:
            logger.error(f"❌ Failed to initialize modular architecture: {e}")
            logger.info("🔄 Falling back to monolithic mode...")
            MODULAR_MODE = False
        except Exception as e:
            logger.error(f"❌ Error in modular initialization: {e}")
            logger.info("🔄 Falling back to monolithic mode...")
            MODULAR_MODE = False
    
    if not MODULAR_MODE:
        logger.error("❌ Modular architecture failed to initialize")
        logger.error("❌ Cannot start server - modular mode is required")
        sys.exit(1)
