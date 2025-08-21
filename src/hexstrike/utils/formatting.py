"""
String and output formatting utilities.

This module changes when pure formatting utilities or string manipulation requirements change.
"""

import json
import re
from typing import Any, Dict, Tuple, Optional
from datetime import datetime, timedelta

def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

def format_file_size(bytes_count: int) -> str:
    """Format file size in bytes to human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate string to maximum length with suffix"""
    if len(text) <= max_length:
        return text
    
    truncated_length = max_length - len(suffix)
    if truncated_length <= 0:
        return suffix[:max_length]
    
    return text[:truncated_length] + suffix

def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing/replacing invalid characters"""
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    
    if len(sanitized) > 255:
        name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
        max_name_length = 255 - len(ext) - 1 if ext else 255
        sanitized = name[:max_name_length] + ('.' + ext if ext else '')
    
    if not sanitized or sanitized.isspace():
        sanitized = "unnamed_file"
    
    return sanitized

def parse_version_string(version: str) -> Tuple[int, int, int]:
    """Parse version string into major, minor, patch tuple"""
    version = version.lstrip('v')
    
    parts = re.findall(r'\d+', version)
    
    if len(parts) >= 3:
        return int(parts[0]), int(parts[1]), int(parts[2])
    elif len(parts) == 2:
        return int(parts[0]), int(parts[1]), 0
    elif len(parts) == 1:
        return int(parts[0]), 0, 0
    else:
        return 0, 0, 0

def format_json_output(data: Dict[str, Any], indent: int = 2, sort_keys: bool = True) -> str:
    """Format dictionary as pretty JSON string"""
    try:
        return json.dumps(data, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        return f"JSON formatting error: {str(e)}"

def format_table(headers: list, rows: list, max_width: int = 80) -> str:
    """Format data as ASCII table"""
    if not headers or not rows:
        return ""
    
    col_widths = [len(str(header)) for header in headers]
    
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    total_width = sum(col_widths) + len(headers) * 3 + 1
    if total_width > max_width:
        available_width = max_width - len(headers) * 3 - 1
        scale_factor = available_width / sum(col_widths)
        col_widths = [max(8, int(width * scale_factor)) for width in col_widths]
    
    lines = []
    
    header_line = "| " + " | ".join(str(headers[i]).ljust(col_widths[i]) for i in range(len(headers))) + " |"
    lines.append(header_line)
    
    separator = "|-" + "-|-".join("-" * width for width in col_widths) + "-|"
    lines.append(separator)
    
    for row in rows:
        row_line = "| " + " | ".join(
            truncate_string(str(row[i] if i < len(row) else ""), col_widths[i], "...")
            .ljust(col_widths[i]) for i in range(len(headers))
        ) + " |"
        lines.append(row_line)
    
    return "\n".join(lines)

def format_progress_percentage(current: int, total: int) -> str:
    """Format progress as percentage string"""
    if total == 0:
        return "0.0%"
    
    percentage = (current / total) * 100
    return f"{percentage:.1f}%"

def format_timestamp(timestamp: Optional[datetime] = None, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format timestamp to string"""
    if timestamp is None:
        timestamp = datetime.now()
    
    return timestamp.strftime(format_str)

def format_relative_time(timestamp: datetime) -> str:
    """Format timestamp as relative time (e.g., '2 hours ago')"""
    now = datetime.now()
    diff = now - timestamp
    
    if diff.total_seconds() < 60:
        return "just now"
    elif diff.total_seconds() < 3600:
        minutes = int(diff.total_seconds() / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif diff.total_seconds() < 86400:
        hours = int(diff.total_seconds() / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    else:
        days = diff.days
        return f"{days} day{'s' if days != 1 else ''} ago"

def format_command_output(command: str, stdout: str, stderr: str, return_code: int) -> str:
    """Format command execution output"""
    lines = [
        f"Command: {command}",
        f"Return Code: {return_code}",
        ""
    ]
    
    if stdout:
        lines.extend([
            "STDOUT:",
            "=" * 40,
            stdout,
            ""
        ])
    
    if stderr:
        lines.extend([
            "STDERR:",
            "=" * 40,
            stderr,
            ""
        ])
    
    return "\n".join(lines)

def format_vulnerability_summary(vulnerabilities: list) -> str:
    """Format vulnerability list as summary"""
    if not vulnerabilities:
        return "No vulnerabilities found."
    
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'unknown').lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    summary_lines = [f"Total vulnerabilities: {len(vulnerabilities)}"]
    
    for severity in ['critical', 'high', 'medium', 'low', 'info', 'unknown']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            summary_lines.append(f"  {severity.capitalize()}: {count}")
    
    return "\n".join(summary_lines)

def escape_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def format_hex_dump(data: bytes, width: int = 16) -> str:
    """Format binary data as hex dump"""
    lines = []
    
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        
        offset = f"{i:08x}"
        
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        hex_bytes = hex_bytes.ljust(width * 3 - 1)
        
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        
        lines.append(f"{offset}  {hex_bytes}  |{ascii_repr}|")
    
    return '\n'.join(lines)
