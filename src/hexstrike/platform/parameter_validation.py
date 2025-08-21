"""
Parameter validation utilities.

This module changes when validation rules change.
"""

from typing import Dict, Any, List, Optional, Union
import re
import ipaddress
import logging
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of parameter validation"""
    is_valid: bool
    error_message: str = ""
    sanitized_value: Any = None

class ParameterValidator:
    """Validates and sanitizes tool parameters"""
    
    def validate_url(self, url: str) -> ValidationResult:
        """Validate URL format"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return ValidationResult(
                    is_valid=False,
                    error_message="Invalid URL format"
                )
            
            if parsed.scheme not in ['http', 'https']:
                return ValidationResult(
                    is_valid=False,
                    error_message="URL must use http or https scheme"
                )
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=url
            )
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                error_message=f"URL validation error: {str(e)}"
            )
    
    def validate_ip_address(self, ip: str) -> ValidationResult:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return ValidationResult(
                is_valid=True,
                sanitized_value=ip
            )
        except ValueError:
            return ValidationResult(
                is_valid=False,
                error_message="Invalid IP address format"
            )
    
    def validate_domain(self, domain: str) -> ValidationResult:
        """Validate domain name format"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        if not domain_pattern.match(domain):
            return ValidationResult(
                is_valid=False,
                error_message="Invalid domain name format"
            )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=domain
        )
    
    def validate_port_range(self, ports: str) -> ValidationResult:
        """Validate port range format"""
        try:
            if '-' in ports:
                start, end = ports.split('-')
                start_port = int(start)
                end_port = int(end)
                
                if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    return ValidationResult(
                        is_valid=False,
                        error_message="Port numbers must be between 1 and 65535"
                    )
                
                if start_port > end_port:
                    return ValidationResult(
                        is_valid=False,
                        error_message="Start port must be less than or equal to end port"
                    )
            
            elif ',' in ports:
                port_list = ports.split(',')
                for port in port_list:
                    port_num = int(port.strip())
                    if not (1 <= port_num <= 65535):
                        return ValidationResult(
                            is_valid=False,
                            error_message="Port numbers must be between 1 and 65535"
                        )
            
            else:
                port_num = int(ports)
                if not (1 <= port_num <= 65535):
                    return ValidationResult(
                        is_valid=False,
                        error_message="Port number must be between 1 and 65535"
                    )
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=ports
            )
            
        except ValueError:
            return ValidationResult(
                is_valid=False,
                error_message="Invalid port format"
            )
    
    def validate_file_path(self, path: str) -> ValidationResult:
        """Validate file path"""
        if not path:
            return ValidationResult(
                is_valid=False,
                error_message="File path cannot be empty"
            )
        
        if '..' in path:
            return ValidationResult(
                is_valid=False,
                error_message="Path traversal not allowed"
            )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=path
        )
    
    def validate_wordlist_path(self, path: str) -> ValidationResult:
        """Validate wordlist file path"""
        result = self.validate_file_path(path)
        if not result.is_valid:
            return result
        
        if not path.endswith(('.txt', '.list', '.wordlist')):
            return ValidationResult(
                is_valid=False,
                error_message="Wordlist must be a text file"
            )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=path
        )
    
    def validate_timeout(self, timeout: Union[int, str]) -> ValidationResult:
        """Validate timeout value"""
        try:
            timeout_val = int(timeout)
            
            if timeout_val <= 0:
                return ValidationResult(
                    is_valid=False,
                    error_message="Timeout must be positive"
                )
            
            if timeout_val > 3600:
                return ValidationResult(
                    is_valid=False,
                    error_message="Timeout cannot exceed 1 hour"
                )
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=timeout_val
            )
            
        except ValueError:
            return ValidationResult(
                is_valid=False,
                error_message="Timeout must be a number"
            )
    
    def validate_thread_count(self, threads: Union[int, str]) -> ValidationResult:
        """Validate thread count"""
        try:
            thread_count = int(threads)
            
            if thread_count <= 0:
                return ValidationResult(
                    is_valid=False,
                    error_message="Thread count must be positive"
                )
            
            if thread_count > 100:
                return ValidationResult(
                    is_valid=False,
                    error_message="Thread count cannot exceed 100"
                )
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=thread_count
            )
            
        except ValueError:
            return ValidationResult(
                is_valid=False,
                error_message="Thread count must be a number"
            )

validator = ParameterValidator()
