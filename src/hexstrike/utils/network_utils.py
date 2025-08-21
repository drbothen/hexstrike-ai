"""
Network utility functions.

This module changes when network operation requirements change.
"""

import socket
import requests
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class NetworkUtils:
    """Network operation utilities"""
    
    def __init__(self):
        self.timeout = 10
    
    def check_port_open(self, host: str, port: int, timeout: int = 5) -> bool:
        """Check if port is open on host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.error(f"Error checking port {port} on {host}: {str(e)}")
            return False
    
    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except Exception as e:
            logger.error(f"Failed to resolve hostname {hostname}: {str(e)}")
            return None
    
    def get_local_ip(self) -> Optional[str]:
        """Get local IP address"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception as e:
            logger.error(f"Failed to get local IP: {str(e)}")
            return None
    
    def check_url_accessible(self, url: str, timeout: int = 10) -> bool:
        """Check if URL is accessible"""
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code < 400
        except Exception as e:
            logger.error(f"URL {url} not accessible: {str(e)}")
            return False
    
    def get_url_status_code(self, url: str, timeout: int = 10) -> Optional[int]:
        """Get HTTP status code for URL"""
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code
        except Exception as e:
            logger.error(f"Failed to get status code for {url}: {str(e)}")
            return None
    
    def download_file(self, url: str, local_path: str, timeout: int = 30) -> bool:
        """Download file from URL"""
        try:
            response = requests.get(url, timeout=timeout, stream=True)
            response.raise_for_status()
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Downloaded file from {url} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to download file from {url}: {str(e)}")
            return False
    
    def extract_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception as e:
            logger.error(f"Failed to extract domain from {url}: {str(e)}")
            return None
    
    def scan_ports(self, host: str, ports: List[int], timeout: int = 1) -> List[int]:
        """Scan multiple ports on host"""
        open_ports = []
        
        for port in ports:
            if self.check_port_open(host, port, timeout):
                open_ports.append(port)
        
        return open_ports
    
    def get_network_interfaces(self) -> Dict[str, str]:
        """Get network interfaces and their IP addresses"""
        interfaces = {}
        
        try:
            hostname = socket.gethostname()
            interfaces['hostname'] = hostname
            
            local_ip = self.get_local_ip()
            if local_ip:
                interfaces['local_ip'] = local_ip
            
        except Exception as e:
            logger.error(f"Failed to get network interfaces: {str(e)}")
        
        return interfaces

network_utils = NetworkUtils()
