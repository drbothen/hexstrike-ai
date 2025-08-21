"""
Python environment management endpoint handlers.

This module changes when Python environment or package management requirements change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
import subprocess
import sys
import pkg_resources

logger = logging.getLogger(__name__)

class PythonEndpoints:
    """Python environment management endpoint handlers"""
    
    def install_package(self) -> Dict[str, Any]:
        """Install Python package"""
        try:
            data = request.get_json()
            package_name = data.get('package', '')
            
            if not package_name:
                return jsonify({"error": "No package name provided"}), 400
            
            logger.info(f"📦 Installing Python package: {package_name}")
            
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', package_name
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info(f"✅ Package {package_name} installed successfully")
                return jsonify({
                    "success": True,
                    "package": package_name,
                    "message": f"Package {package_name} installed successfully",
                    "output": result.stdout
                })
            else:
                logger.error(f"💥 Failed to install package {package_name}")
                return jsonify({
                    "success": False,
                    "package": package_name,
                    "error": result.stderr,
                    "output": result.stdout
                }), 500
                
        except subprocess.TimeoutExpired:
            logger.error("💥 Package installation timed out")
            return jsonify({"error": "Package installation timed out"}), 408
        except Exception as e:
            logger.error(f"💥 Error installing package: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def list_packages(self) -> Dict[str, Any]:
        """List installed Python packages"""
        try:
            installed_packages = []
            for dist in pkg_resources.working_set:
                installed_packages.append({
                    "name": dist.project_name,
                    "version": dist.version,
                    "location": dist.location
                })
            
            logger.info(f"📋 Listed {len(installed_packages)} installed packages")
            
            return jsonify({
                "success": True,
                "packages": installed_packages,
                "count": len(installed_packages)
            })
            
        except Exception as e:
            logger.error(f"💥 Error listing packages: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def get_python_info(self) -> Dict[str, Any]:
        """Get Python environment information"""
        try:
            python_info = {
                "version": sys.version,
                "executable": sys.executable,
                "platform": sys.platform,
                "path": sys.path[:5],  # First 5 paths only
                "prefix": sys.prefix
            }
            
            logger.info("🐍 Retrieved Python environment information")
            
            return jsonify({
                "success": True,
                "python_info": python_info
            })
            
        except Exception as e:
            logger.error(f"💥 Error getting Python info: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
