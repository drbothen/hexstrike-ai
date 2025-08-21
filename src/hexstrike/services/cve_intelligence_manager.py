"""
CVE intelligence management and vulnerability analysis service.

This module changes when CVE analysis or vulnerability intelligence strategies change.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class CVEIntelligenceManager:
    """Advanced CVE intelligence and vulnerability analysis"""
    
    def __init__(self):
        self.vulnerability_database = {}
        self.intelligence_sources = []
        self.analysis_cache = {}
        
    def create_banner(self, text: str, width: int = 80) -> str:
        """Create a formatted banner for display"""
        border = "=" * width
        padding = (width - len(text) - 2) // 2
        return f"{border}\n{' ' * padding} {text} {' ' * padding}\n{border}"
    
    def render_progress_bar(self, current: int, total: int, width: int = 50, 
                          prefix: str = "", suffix: str = "") -> str:
        """Render a progress bar for long-running operations"""
        if total == 0:
            percent = 100
        else:
            percent = (current / total) * 100
        
        filled_width = int(width * current // total) if total > 0 else 0
        bar = "█" * filled_width + "░" * (width - filled_width)
        
        return f"\r{prefix} |{bar}| {current}/{total} ({percent:.1f}%) {suffix}"
    
    def render_vulnerability_card(self, vuln_data: Dict[str, Any]) -> str:
        """Render a vulnerability information card"""
        cve_id = vuln_data.get("cve_id", "Unknown")
        severity = vuln_data.get("severity", "Unknown")
        description = vuln_data.get("description", "No description available")
        
        if len(description) > 100:
            description = description[:97] + "..."
        
        severity_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "Unknown": "⚪"
        }
        
        severity_icon = severity_colors.get(severity.upper(), "⚪")
        
        card = f"""
┌─ {cve_id} ─────────────────────────────────────────┐
│ Severity: {severity_icon} {severity.upper()}                           │
│ Description: {description:<35} │
└─────────────────────────────────────────────────────┘
"""
        return card
    
    def create_live_dashboard(self, stats: Dict[str, Any]) -> str:
        """Create a live dashboard display"""
        total_vulns = stats.get("total_vulnerabilities", 0)
        critical_vulns = stats.get("critical_vulnerabilities", 0)
        high_vulns = stats.get("high_vulnerabilities", 0)
        scan_progress = stats.get("scan_progress", 0)
        
        dashboard = f"""
╔══════════════════════════════════════════════════════════════╗
║                    CVE Intelligence Dashboard                 ║
╠══════════════════════════════════════════════════════════════╣
║ Total Vulnerabilities: {total_vulns:<10}                        ║
║ Critical: {critical_vulns:<5} High: {high_vulns:<5}                           ║
║ Scan Progress: {scan_progress}%                                    ║
╚══════════════════════════════════════════════════════════════╝
"""
        return dashboard
    
    def format_tool_output(self, tool_name: str, output: str, 
                          max_lines: int = 20) -> str:
        """Format tool output for display"""
        lines = output.split('\n')
        
        if len(lines) > max_lines:
            displayed_lines = lines[:max_lines]
            truncated_count = len(lines) - max_lines
            displayed_lines.append(f"... ({truncated_count} more lines truncated)")
        else:
            displayed_lines = lines
        
        formatted_output = f"""
┌─ {tool_name} Output ─────────────────────────────────────────┐
"""
        for line in displayed_lines:
            if len(line) > 60:
                line = line[:57] + "..."
            formatted_output += f"│ {line:<60} │\n"
        
        formatted_output += "└─────────────────────────────────────────────────────────────┘"
        
        return formatted_output
    
    def create_summary_report(self, scan_results: Dict[str, Any]) -> str:
        """Create a comprehensive summary report"""
        total_targets = scan_results.get("total_targets", 0)
        vulnerabilities_found = scan_results.get("vulnerabilities_found", 0)
        scan_duration = scan_results.get("scan_duration", 0)
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                        Scan Summary Report                    ║
╠══════════════════════════════════════════════════════════════╣
║ Targets Scanned: {total_targets:<10}                            ║
║ Vulnerabilities Found: {vulnerabilities_found:<10}                  ║
║ Scan Duration: {scan_duration:.2f} seconds                        ║
║ Status: Complete                                             ║
╚══════════════════════════════════════════════════════════════╝
"""
        return report
