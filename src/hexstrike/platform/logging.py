"""
Logging infrastructure and configuration.

This module changes when logging format, destinations, or filtering requirements change.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime

@dataclass
class LogConfig:
    """Logging configuration data"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    handlers: List[str] = None
    file_path: Optional[str] = "hexstrike.log"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    console_output: bool = True

    def __post_init__(self):
        if self.handlers is None:
            self.handlers = ["console", "file"]

class LogFormatter(logging.Formatter):
    """Custom log formatter with color support"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional colors"""
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        if self.use_colors and record.levelname in self.COLORS:
            color = self.COLORS[record.levelname]
            reset = self.COLORS['RESET']
            log_format = f"{color}%(asctime)s - %(name)s - %(levelname)s{reset} - %(message)s"
        
        formatter = logging.Formatter(log_format)
        return formatter.format(record)

class LogManager:
    """Central logging configuration and management"""
    
    def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.config: Optional[LogConfig] = None
        self.handlers: List[logging.Handler] = []
    
    def configure_logging(self, config: LogConfig) -> None:
        """Configure logging with provided configuration"""
        self.config = config
        
        # Clear existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        self.handlers.clear()
        
        log_level = getattr(logging, config.level.upper(), logging.INFO)
        root_logger.setLevel(log_level)
        
        if "console" in config.handlers and config.console_output:
            self._add_console_handler()
        
        if "file" in config.handlers and config.file_path:
            self._add_file_handler(config.file_path, config.max_file_size, config.backup_count)
    
    def _add_console_handler(self) -> None:
        """Add console handler with color formatting"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(LogFormatter(use_colors=True))
        
        root_logger = logging.getLogger()
        root_logger.addHandler(console_handler)
        self.handlers.append(console_handler)
    
    def _add_file_handler(self, file_path: str, max_size: int, backup_count: int) -> None:
        """Add rotating file handler"""
        try:
            log_file = Path(file_path)
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                file_path,
                maxBytes=max_size,
                backupCount=backup_count
            )
            file_handler.setFormatter(LogFormatter(use_colors=False))
            
            root_logger = logging.getLogger()
            root_logger.addHandler(file_handler)
            self.handlers.append(file_handler)
            
        except PermissionError:
            # Fallback to console-only logging if file creation fails
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(LogFormatter(use_colors=True))
            
            root_logger = logging.getLogger()
            root_logger.addHandler(console_handler)
            self.handlers.append(console_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create logger with specified name"""
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        
        return self.loggers[name]
    
    def set_log_level(self, level: str) -> None:
        """Set log level for all loggers"""
        log_level = getattr(logging, level.upper(), logging.INFO)
        
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        for handler in self.handlers:
            handler.setLevel(log_level)
    
    def add_handler(self, handler: logging.Handler) -> None:
        """Add custom handler"""
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        self.handlers.append(handler)
    
    def get_log_stats(self) -> Dict[str, Any]:
        """Get logging statistics"""
        return {
            "active_loggers": len(self.loggers),
            "active_handlers": len(self.handlers),
            "log_level": logging.getLevelName(logging.getLogger().level),
            "config": {
                "level": self.config.level if self.config else "INFO",
                "handlers": self.config.handlers if self.config else [],
                "file_path": self.config.file_path if self.config else None
            } if self.config else None
        }

log_manager = LogManager()

default_config = LogConfig()
log_manager.configure_logging(default_config)

def get_logger(name: str) -> logging.Logger:
    """Convenience function to get logger"""
    return log_manager.get_logger(name)

def configure_logging(config: LogConfig) -> None:
    """Convenience function to configure logging"""
    log_manager.configure_logging(config)
