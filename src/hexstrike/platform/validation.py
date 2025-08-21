"""
Parameter validation and input sanitization utilities.

This module changes when parameter validation rules or input sanitization requirements change.
"""

import re
import ipaddress
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Validation outcome data"""
    is_valid: bool
    errors: List[str]
    sanitized_value: Optional[Any] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

class ValidationError(Exception):
    """Validation failure exception"""
    
    def __init__(self, field: str, message: str, value: Any):
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"Validation error for field '{field}': {message}")

class ParameterValidator:
    """Main validation orchestrator"""
    
    def __init__(self):
        self.url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        self.domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        self.command_injection_patterns = [
            r'[;&|`$()]',  # Command separators and substitution
            r'\.\./',      # Directory traversal
            r'<|>',        # Redirection
            r'\s--\s',     # SQL injection
            r'<script',    # XSS
            r'javascript:', # JavaScript injection
        ]
    
    def validate_url(self, url: str) -> ValidationResult:
        """Validate URL format and safety"""
        errors = []
        warnings = []
        
        if not url:
            errors.append("URL cannot be empty")
            return ValidationResult(False, errors)
        
        if not self.url_pattern.match(url):
            errors.append("Invalid URL format")
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            if parsed.scheme not in ['http', 'https']:
                errors.append(f"Unsupported URL scheme: {parsed.scheme}")
            
            if parsed.hostname:
                try:
                    ip = ipaddress.ip_address(parsed.hostname)
                    if ip.is_private or ip.is_loopback:
                        warnings.append("URL points to private/localhost address")
                except ValueError:
                    pass  # Not an IP address, which is fine
            
            sanitized_url = urllib.parse.urlunparse(parsed)
            
        except Exception as e:
            errors.append(f"URL parsing error: {str(e)}")
            sanitized_url = url
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized_url if len(errors) == 0 else None
        )
    
    def validate_ip_address(self, ip: str) -> ValidationResult:
        """Validate IP address format"""
        errors = []
        warnings = []
        
        if not ip:
            errors.append("IP address cannot be empty")
            return ValidationResult(False, errors)
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private:
                warnings.append("IP address is in private range")
            elif ip_obj.is_loopback:
                warnings.append("IP address is loopback")
            elif ip_obj.is_multicast:
                warnings.append("IP address is multicast")
            
            sanitized_ip = str(ip_obj)
            
        except ValueError as e:
            errors.append(f"Invalid IP address: {str(e)}")
            sanitized_ip = None
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized_ip
        )
    
    def validate_port(self, port: Union[int, str]) -> ValidationResult:
        """Validate port number"""
        errors = []
        warnings = []
        
        try:
            port_int = int(port)
            
            if port_int < 1 or port_int > 65535:
                errors.append("Port must be between 1 and 65535")
            elif port_int < 1024:
                warnings.append("Port is in privileged range (< 1024)")
            
            sanitized_port = port_int
            
        except (ValueError, TypeError):
            errors.append("Port must be a valid integer")
            sanitized_port = None
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized_port
        )
    
    def validate_file_path(self, path: str, must_exist: bool = False) -> ValidationResult:
        """Validate file path"""
        errors = []
        warnings = []
        
        if not path:
            errors.append("File path cannot be empty")
            return ValidationResult(False, errors)
        
        try:
            path_obj = Path(path)
            
            if '..' in path:
                errors.append("Directory traversal detected in path")
            
            if must_exist and not path_obj.exists():
                errors.append("File does not exist")
            
            if path.startswith('/etc/') or path.startswith('/proc/'):
                warnings.append("Path points to system directory")
            
            sanitized_path = str(path_obj.resolve())
            
        except Exception as e:
            errors.append(f"Path validation error: {str(e)}")
            sanitized_path = None
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized_path
        )
    
    def validate_domain(self, domain: str) -> ValidationResult:
        """Validate domain name"""
        errors = []
        warnings = []
        
        if not domain:
            errors.append("Domain cannot be empty")
            return ValidationResult(False, errors)
        
        if domain.startswith(('http://', 'https://')):
            domain = urllib.parse.urlparse(domain).netloc
        
        if not self.domain_pattern.match(domain):
            errors.append("Invalid domain format")
        
        if len(domain) > 253:
            errors.append("Domain name too long (max 253 characters)")
        
        if domain.lower() in ['localhost', '127.0.0.1', '::1']:
            warnings.append("Domain is localhost")
        
        sanitized_domain = domain.lower().strip()
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized_domain
        )
    
    def sanitize_command_input(self, input_str: str) -> str:
        """Sanitize command input to prevent injection"""
        if not input_str:
            return ""
        
        sanitized = input_str
        
        for pattern in self.command_injection_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        sanitized = ' '.join(sanitized.split())
        
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000]
            logger.warning("Command input truncated due to length")
        
        return sanitized
    
    def validate_tool_parameters(self, tool: str, params: Dict[str, Any]) -> List[ValidationError]:
        """Validate tool-specific parameters"""
        errors = []
        
        if 'target' in params:
            target = params['target']
            if isinstance(target, str):
                url_result = self.validate_url(target)
                if not url_result.is_valid:
                    domain_result = self.validate_domain(target)
                    if not domain_result.is_valid:
                        ip_result = self.validate_ip_address(target)
                        if not ip_result.is_valid:
                            errors.append(ValidationError('target', 'Invalid target format', target))
        
        if 'port' in params:
            port_result = self.validate_port(params['port'])
            if not port_result.is_valid:
                errors.append(ValidationError('port', port_result.errors[0], params['port']))
        
        if 'timeout' in params:
            try:
                timeout = int(params['timeout'])
                if timeout < 1 or timeout > 3600:
                    errors.append(ValidationError('timeout', 'Timeout must be between 1 and 3600 seconds', timeout))
            except (ValueError, TypeError):
                errors.append(ValidationError('timeout', 'Timeout must be a valid integer', params['timeout']))
        
        if 'threads' in params:
            try:
                threads = int(params['threads'])
                if threads < 1 or threads > 1000:
                    errors.append(ValidationError('threads', 'Threads must be between 1 and 1000', threads))
            except (ValueError, TypeError):
                errors.append(ValidationError('threads', 'Threads must be a valid integer', params['threads']))
        
        if tool == 'nmap':
            self._validate_nmap_params(params, errors)
        elif tool == 'gobuster':
            self._validate_gobuster_params(params, errors)
        elif tool == 'nuclei':
            self._validate_nuclei_params(params, errors)
        
        return errors
    
    def _validate_nmap_params(self, params: Dict[str, Any], errors: List[ValidationError]) -> None:
        """Validate nmap-specific parameters"""
        if 'scan_type' in params:
            scan_type = params['scan_type']
            if not isinstance(scan_type, str):
                errors.append(ValidationError('scan_type', 'Scan type must be a string', scan_type))
            elif any(dangerous in scan_type for dangerous in [';', '|', '&', '`']):
                errors.append(ValidationError('scan_type', 'Scan type contains dangerous characters', scan_type))
    
    def _validate_gobuster_params(self, params: Dict[str, Any], errors: List[ValidationError]) -> None:
        """Validate gobuster-specific parameters"""
        if 'mode' in params:
            mode = params['mode']
            valid_modes = ['dir', 'dns', 'fuzz', 'vhost']
            if mode not in valid_modes:
                errors.append(ValidationError('mode', f'Mode must be one of: {valid_modes}', mode))
        
        if 'wordlist' in params:
            wordlist_result = self.validate_file_path(params['wordlist'], must_exist=True)
            if not wordlist_result.is_valid:
                errors.append(ValidationError('wordlist', wordlist_result.errors[0], params['wordlist']))
    
    def _validate_nuclei_params(self, params: Dict[str, Any], errors: List[ValidationError]) -> None:
        """Validate nuclei-specific parameters"""
        if 'severity' in params:
            severity = params['severity']
            valid_severities = ['critical', 'high', 'medium', 'low', 'info']
            if severity not in valid_severities:
                errors.append(ValidationError('severity', f'Severity must be one of: {valid_severities}', severity))

validator = ParameterValidator()
