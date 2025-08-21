"""
File and directory operation utilities.

This module changes when file handling requirements change.
"""

import os
import shutil
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

class FileOperations:
    """File and directory operation utilities"""
    
    def create_temp_directory(self, prefix: str = "hexstrike_") -> str:
        """Create temporary directory"""
        temp_dir = tempfile.mkdtemp(prefix=prefix)
        logger.info(f"Created temporary directory: {temp_dir}")
        return temp_dir
    
    def cleanup_temp_directory(self, temp_dir: str) -> bool:
        """Clean up temporary directory"""
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
                return True
        except Exception as e:
            logger.error(f"Failed to cleanup directory {temp_dir}: {str(e)}")
        return False
    
    def ensure_directory_exists(self, directory: str) -> bool:
        """Ensure directory exists, create if needed"""
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"Failed to create directory {directory}: {str(e)}")
            return False
    
    def copy_file(self, source: str, destination: str) -> bool:
        """Copy file from source to destination"""
        try:
            shutil.copy2(source, destination)
            logger.info(f"Copied file from {source} to {destination}")
            return True
        except Exception as e:
            logger.error(f"Failed to copy file: {str(e)}")
            return False
    
    def move_file(self, source: str, destination: str) -> bool:
        """Move file from source to destination"""
        try:
            shutil.move(source, destination)
            logger.info(f"Moved file from {source} to {destination}")
            return True
        except Exception as e:
            logger.error(f"Failed to move file: {str(e)}")
            return False
    
    def delete_file(self, file_path: str) -> bool:
        """Delete file"""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Deleted file: {file_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to delete file {file_path}: {str(e)}")
        return False
    
    def get_file_size(self, file_path: str) -> Optional[int]:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"Failed to get file size for {file_path}: {str(e)}")
            return None
    
    def list_files_in_directory(self, directory: str, pattern: str = "*") -> List[str]:
        """List files in directory matching pattern"""
        try:
            path = Path(directory)
            return [str(f) for f in path.glob(pattern) if f.is_file()]
        except Exception as e:
            logger.error(f"Failed to list files in {directory}: {str(e)}")
            return []
    
    def read_file_content(self, file_path: str) -> Optional[str]:
        """Read file content as string"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {str(e)}")
            return None
    
    def write_file_content(self, file_path: str, content: str) -> bool:
        """Write content to file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Wrote content to file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {str(e)}")
            return False
    
    def append_to_file(self, file_path: str, content: str) -> bool:
        """Append content to file"""
        try:
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Appended content to file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to append to file {file_path}: {str(e)}")
            return False

file_ops = FileOperations()
