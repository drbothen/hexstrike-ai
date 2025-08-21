"""
File operations endpoint handlers.

This module changes when file operation API endpoints change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
import os
import shutil
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class FileEndpoints:
    """File operations endpoint handlers"""
    
    def __init__(self):
        pass
    
    def create_file(self):
        """Create a new file"""
        try:
            data = request.get_json()
            filepath = data.get('filepath')
            content = data.get('content', '')
            
            if not filepath:
                return jsonify({"error": "Filepath is required"}), 400
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            logger.info(f"📄 Created file: {filepath}")
            return jsonify({"success": True, "message": f"File created: {filepath}"})
            
        except Exception as e:
            logger.error(f"💥 Error creating file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def modify_file(self):
        """Modify an existing file"""
        try:
            data = request.get_json()
            filepath = data.get('filepath')
            content = data.get('content', '')
            
            if not filepath:
                return jsonify({"error": "Filepath is required"}), 400
            
            if not os.path.exists(filepath):
                return jsonify({"error": "File does not exist"}), 404
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            logger.info(f"📝 Modified file: {filepath}")
            return jsonify({"success": True, "message": f"File modified: {filepath}"})
            
        except Exception as e:
            logger.error(f"💥 Error modifying file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def delete_file(self):
        """Delete a file or directory"""
        try:
            data = request.get_json()
            filepath = data.get('filepath')
            
            if not filepath:
                return jsonify({"error": "Filepath is required"}), 400
            
            if os.path.isfile(filepath):
                os.remove(filepath)
                logger.info(f"🗑️ Deleted file: {filepath}")
                return jsonify({"success": True, "message": f"File deleted: {filepath}"})
            elif os.path.isdir(filepath):
                shutil.rmtree(filepath)
                logger.info(f"🗑️ Deleted directory: {filepath}")
                return jsonify({"success": True, "message": f"Directory deleted: {filepath}"})
            else:
                return jsonify({"error": "File or directory does not exist"}), 404
                
        except Exception as e:
            logger.error(f"💥 Error deleting file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def list_files(self):
        """List files in a directory"""
        try:
            directory = request.args.get('directory', '.')
            
            if not os.path.exists(directory):
                return jsonify({"error": "Directory does not exist"}), 404
            
            files = []
            for item in Path(directory).iterdir():
                files.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                    "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })
            
            return jsonify({"success": True, "files": files})
            
        except Exception as e:
            logger.error(f"💥 Error listing files: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def read_file(self):
        """Read file contents"""
        try:
            filepath = request.args.get('filepath')
            
            if not filepath:
                return jsonify({"error": "Filepath is required"}), 400
            
            if not os.path.exists(filepath):
                return jsonify({"error": "File does not exist"}), 404
            
            if not os.path.isfile(filepath):
                return jsonify({"error": "Path is not a file"}), 400
            
            with open(filepath, 'r') as f:
                content = f.read()
            
            return jsonify({
                "success": True,
                "content": content,
                "filepath": filepath
            })
            
        except Exception as e:
            logger.error(f"💥 Error reading file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def copy_file(self):
        """Copy a file or directory"""
        try:
            data = request.get_json()
            source = data.get('source')
            destination = data.get('destination')
            
            if not source or not destination:
                return jsonify({"error": "Source and destination are required"}), 400
            
            if not os.path.exists(source):
                return jsonify({"error": "Source does not exist"}), 404
            
            if os.path.isfile(source):
                shutil.copy2(source, destination)
                logger.info(f"📋 Copied file: {source} -> {destination}")
                return jsonify({"success": True, "message": f"File copied: {source} -> {destination}"})
            elif os.path.isdir(source):
                shutil.copytree(source, destination)
                logger.info(f"📋 Copied directory: {source} -> {destination}")
                return jsonify({"success": True, "message": f"Directory copied: {source} -> {destination}"})
            
        except Exception as e:
            logger.error(f"💥 Error copying file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def move_file(self):
        """Move a file or directory"""
        try:
            data = request.get_json()
            source = data.get('source')
            destination = data.get('destination')
            
            if not source or not destination:
                return jsonify({"error": "Source and destination are required"}), 400
            
            if not os.path.exists(source):
                return jsonify({"error": "Source does not exist"}), 404
            
            shutil.move(source, destination)
            logger.info(f"📦 Moved: {source} -> {destination}")
            return jsonify({"success": True, "message": f"Moved: {source} -> {destination}"})
            
        except Exception as e:
            logger.error(f"💥 Error moving file: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def get_file_info(self):
        """Get file information"""
        try:
            filepath = request.args.get('filepath')
            
            if not filepath:
                return jsonify({"error": "Filepath is required"}), 400
            
            if not os.path.exists(filepath):
                return jsonify({"error": "File does not exist"}), 404
            
            stat = os.stat(filepath)
            info = {
                "name": os.path.basename(filepath),
                "path": filepath,
                "size": stat.st_size,
                "type": "directory" if os.path.isdir(filepath) else "file",
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": oct(stat.st_mode)[-3:]
            }
            
            return jsonify({
                "success": True,
                "info": info
            })
            
        except Exception as e:
            logger.error(f"💥 Error getting file info: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
