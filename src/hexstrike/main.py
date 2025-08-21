"""
HexStrike AI - Main application entry point.

This module serves as the new entry point for the modularized HexStrike AI framework.
"""

import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hexstrike.platform.logging import configure_logging, LogConfig
from hexstrike.platform.constants import API_HOST, API_PORT
from hexstrike.interfaces.visual_engine import ModernVisualEngine

log_config = LogConfig(
    level="INFO",
    file_path="hexstrike.log",
    console_output=True
)
configure_logging(log_config)

logger = logging.getLogger(__name__)

def main():
    """Main application entry point"""
    try:
        print(ModernVisualEngine.create_banner())
        
        logger.info("🚀 Starting HexStrike AI v6.0 - Modular Architecture")
        logger.info(f"🌐 API Server will be available at http://{API_HOST}:{API_PORT}")
        
        from hexstrike_server import app
        
        app.run(
            host=API_HOST,
            port=API_PORT,
            debug=False,
            threaded=True
        )
        
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down HexStrike AI...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
