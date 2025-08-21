"""
Application constants, color schemes, and configuration defaults.

This module changes when application constants, color schemes, or configuration defaults change.
"""

from typing import Dict, Any

COLORS: Dict[str, str] = {
    'PRIMARY_BORDER': '\033[38;5;196m',
    'ACCENT_LINE': '\033[38;5;208m',
    'FIRE_RED': '\033[38;5;196m',
    'CYBER_ORANGE': '\033[38;5;208m',
    'NEON_GREEN': '\033[38;5;46m',
    'ELECTRIC_BLUE': '\033[38;5;33m',
    'PURPLE_GLOW': '\033[38;5;129m',
    'YELLOW_BRIGHT': '\033[38;5;226m',
    'WHITE_BRIGHT': '\033[38;5;15m',
    'GRAY_DARK': '\033[38;5;240m',
    'RESET': '\033[0m',
    'BOLD': '\033[1m',
    'DIM': '\033[2m',
    'UNDERLINE': '\033[4m',
    'BLINK': '\033[5m',
    'REVERSE': '\033[7m',
    'STRIKETHROUGH': '\033[9m',
    'TOOL_RUNNING': '\033[38;5;226m',
    'TOOL_SUCCESS': '\033[38;5;46m',
    'TOOL_ERROR': '\033[38;5;196m',
    'TOOL_WARNING': '\033[38;5;208m',
    'SUCCESS': '\033[38;5;46m',
    'ERROR': '\033[38;5;196m',
    'WARNING': '\033[38;5;208m',
    'INFO': '\033[38;5;33m',
    'CRITICAL': '\033[38;5;129m',
    'HIGH': '\033[38;5;196m',
    'MEDIUM': '\033[38;5;208m',
    'LOW': '\033[38;5;226m',
    'UNKNOWN': '\033[38;5;240m'
}

DEFAULT_TIMEOUTS: Dict[str, int] = {
    'nmap': 300,
    'gobuster': 600,
    'nuclei': 180,
    'sqlmap': 900,
    'hydra': 600,
    'john': 1800,
    'hashcat': 3600,
    'rustscan': 120,
    'masscan': 180,
    'feroxbuster': 600,
    'ffuf': 300,
    'dirsearch': 600,
    'nikto': 900,
    'wpscan': 600,
    'enum4linux': 300,
    'smbmap': 180,
    'rpcclient': 120,
    'nbtscan': 60,
    'arp-scan': 30,
    'responder': 300,
    'amass': 1800,
    'subfinder': 300,
    'assetfinder': 180,
    'fierce': 300,
    'dnsenum': 600,
    'theharvester': 900,
    'sherlock': 300,
    'prowler': 1800,
    'scout-suite': 2400,
    'trivy': 600,
    'kube-hunter': 900,
    'kube-bench': 300,
    'checkov': 600,
    'terrascan': 300,
    'volatility': 3600,
    'binwalk': 600,
    'strings': 180,
    'ghidra': 1800,
    'radare2': 900,
    'gdb': 1800,
    'pwntools': 600,
    'ropper': 300,
    'angr': 1800
}

DEFAULT_THREADS: Dict[str, int] = {
    'gobuster': 10,
    'feroxbuster': 50,
    'ffuf': 40,
    'dirsearch': 30,
    'nuclei': 25,
    'rustscan': 500,
    'masscan': 1000,
    'hydra': 16,
    'john': 4,
    'hashcat': 1
}

DEFAULT_WORDLISTS: Dict[str, str] = {
    'directories': '/usr/share/wordlists/dirb/common.txt',
    'subdomains': '/usr/share/wordlists/amass/subdomains-top1mil-5000.txt',
    'passwords': '/usr/share/wordlists/rockyou.txt',
    'usernames': '/usr/share/wordlists/metasploit/unix_users.txt',
    'web_content': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
}

MAX_CONCURRENT_PROCESSES: int = 20
DEFAULT_CACHE_TTL: int = 3600
API_VERSION: str = "v1.0"
API_PORT: int = 8888
API_HOST: str = "127.0.0.1"

TOOL_CATEGORIES: Dict[str, list] = {
    'network_discovery': ['nmap', 'rustscan', 'masscan', 'autorecon'],
    'web_discovery': ['gobuster', 'feroxbuster', 'dirsearch', 'ffuf'],
    'vulnerability_scanning': ['nuclei', 'nikto', 'wpscan', 'jaeles'],
    'subdomain_enumeration': ['subfinder', 'amass', 'assetfinder', 'fierce'],
    'parameter_discovery': ['arjun', 'paramspider', 'x8'],
    'password_attacks': ['hydra', 'john', 'hashcat', 'medusa'],
    'cloud_security': ['prowler', 'scout-suite', 'trivy', 'kube-hunter'],
    'binary_analysis': ['ghidra', 'radare2', 'binwalk', 'strings'],
    'forensics': ['volatility', 'steghide', 'foremost', 'exiftool'],
    'osint': ['theharvester', 'sherlock', 'maltego']
}

SEVERITY_LEVELS: list = ['critical', 'high', 'medium', 'low', 'info']

COMMON_PORTS: Dict[str, list] = {
    'top_100': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080],
    'web': [80, 443, 8080, 8443, 8000, 8888, 9000, 9090],
    'database': [1433, 1521, 3306, 5432, 6379, 27017],
    'remote_access': [22, 23, 3389, 5900, 5985, 5986]
}
