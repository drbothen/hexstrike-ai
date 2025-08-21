"""
Colored logging formatter service.

This module changes when logging formatting or color schemes change.
"""

import logging

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green  
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        """Format log record with colors"""
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        
        emoji_map = {
            'DEBUG': '🔍',
            'INFO': '✅', 
            'WARNING': '⚠️',
            'ERROR': '❌',
            'CRITICAL': '🚨'
        }
        
        emoji = emoji_map.get(record.levelname.strip('\033[0m\033[32m\033[31m\033[33m\033[35m\033[36m'), '📝')
        record.msg = f"{emoji} {record.msg}"
        
        return super().format(record)
