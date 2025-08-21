"""
Visual engine endpoint handlers.

This module changes when visual API endpoints or rendering capabilities change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...interfaces.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

class VisualEndpoints:
    """Visual engine endpoint handlers"""
    
    def __init__(self):
        self.visual_engine = ModernVisualEngine()
    
    def vulnerability_card(self) -> Dict[str, Any]:
        """Create formatted vulnerability card"""
        try:
            data = request.get_json()
            
            vuln_data = {
                'severity': data.get('severity', 'unknown'),
                'title': data.get('title', 'Unknown Vulnerability'),
                'description': data.get('description', 'No description available'),
                'cvss': data.get('cvss', 'N/A')
            }
            
            formatted_card = self.visual_engine.format_vulnerability_card(vuln_data)
            
            logger.info(f"🎨 Created vulnerability card for {vuln_data['severity']} severity")
            
            return jsonify({
                "success": True,
                "vulnerability": vuln_data,
                "formatted_card": formatted_card,
                "message": "Vulnerability card created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating vulnerability card: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def summary_report(self) -> Dict[str, Any]:
        """Create visual summary report"""
        try:
            data = request.get_json()
            
            report_data = {
                'title': data.get('title', 'Security Assessment Report'),
                'target': data.get('target', ''),
                'vulnerabilities': data.get('vulnerabilities', []),
                'tools_used': data.get('tools_used', []),
                'execution_time': data.get('execution_time', 0)
            }
            
            report_sections = []
            
            report_sections.append(self.visual_engine.create_section_header(report_data['title']))
            
            if report_data['target']:
                report_sections.append(f"Target: {self.visual_engine.format_highlighted_text(report_data['target'])}")
            
            if report_data['vulnerabilities']:
                report_sections.append(self.visual_engine.create_section_header("Vulnerabilities Found"))
                for vuln in report_data['vulnerabilities']:
                    vuln_card = self.visual_engine.format_vulnerability_card(vuln)
                    report_sections.append(vuln_card)
            
            if report_data['tools_used']:
                report_sections.append(self.visual_engine.create_section_header("Tools Used"))
                for tool in report_data['tools_used']:
                    tool_status = self.visual_engine.format_tool_status(tool, "SUCCESS")
                    report_sections.append(tool_status)
            
            formatted_report = "\n\n".join(report_sections)
            
            logger.info(f"📊 Created summary report for {report_data['target']}")
            
            return jsonify({
                "success": True,
                "report_data": report_data,
                "formatted_report": formatted_report,
                "message": "Summary report created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating summary report: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def tool_output(self) -> Dict[str, Any]:
        """Format tool execution output"""
        try:
            data = request.get_json()
            
            tool_name = data.get('tool_name', '')
            status = data.get('status', 'RUNNING')
            target = data.get('target', '')
            progress = data.get('progress', 0.0)
            command = data.get('command', '')
            output = data.get('output', '')
            
            formatted_elements = []
            
            if command:
                command_display = self.visual_engine.format_command_execution(command, status.lower())
                formatted_elements.append(command_display)
            
            if tool_name:
                tool_status = self.visual_engine.format_tool_status(tool_name, status, target, progress)
                formatted_elements.append(tool_status)
            
            if progress > 0:
                progress_bar = self.visual_engine.render_progress_bar(
                    progress, 
                    width=50, 
                    label=f"{tool_name} Progress"
                )
                formatted_elements.append(progress_bar)
            
            if output:
                formatted_elements.append(f"\nOutput:\n{output}")
            
            formatted_output = "\n".join(formatted_elements)
            
            logger.info(f"🖥️ Formatted output for {tool_name}")
            
            return jsonify({
                "success": True,
                "tool_name": tool_name,
                "status": status,
                "formatted_output": formatted_output,
                "message": "Tool output formatted"
            })
            
        except Exception as e:
            logger.error(f"💥 Error formatting tool output: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def progress_dashboard(self) -> Dict[str, Any]:
        """Create live progress dashboard"""
        try:
            data = request.get_json()
            
            processes = data.get('processes', {})
            
            dashboard = self.visual_engine.create_live_dashboard(processes)
            
            logger.info(f"📊 Created progress dashboard for {len(processes)} processes")
            
            return jsonify({
                "success": True,
                "process_count": len(processes),
                "dashboard": dashboard,
                "message": "Progress dashboard created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating progress dashboard: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def error_card(self) -> Dict[str, Any]:
        """Create formatted error card"""
        try:
            data = request.get_json()
            
            error_type = data.get('error_type', 'UNKNOWN')
            tool_name = data.get('tool_name', 'Unknown Tool')
            error_message = data.get('error_message', 'An error occurred')
            recovery_action = data.get('recovery_action', '')
            
            formatted_card = self.visual_engine.format_error_card(
                error_type, 
                tool_name, 
                error_message, 
                recovery_action
            )
            
            logger.info(f"❌ Created error card for {tool_name}")
            
            return jsonify({
                "success": True,
                "error_info": {
                    "type": error_type,
                    "tool": tool_name,
                    "message": error_message,
                    "recovery": recovery_action
                },
                "formatted_card": formatted_card,
                "message": "Error card created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating error card: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def banner(self) -> Dict[str, Any]:
        """Create application banner"""
        try:
            banner = self.visual_engine.create_banner()
            
            logger.info("🎨 Created application banner")
            
            return jsonify({
                "success": True,
                "banner": banner,
                "message": "Application banner created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating banner: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
