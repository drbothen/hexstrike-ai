"""
Bug bounty hunting endpoint handlers.

This module changes when bug bounty API endpoints or hunting strategies change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.bugbounty.bugbounty_workflow_manager import BugBountyWorkflowManager, BugBountyTarget
from ...interfaces.visual_engine import ModernVisualEngine

logger = logging.getLogger(__name__)

class BugBountyEndpoints:
    """Bug bounty hunting endpoint handlers"""
    
    def __init__(self):
        self.bugbounty_manager = BugBountyWorkflowManager()
    
    def reconnaissance_workflow(self) -> Dict[str, Any]:
        """Create comprehensive reconnaissance workflow"""
        try:
            data = request.get_json()
            
            target = BugBountyTarget(
                domain=data.get('domain', ''),
                scope=data.get('scope', []),
                out_of_scope=data.get('out_of_scope', []),
                program_type=data.get('program_type', 'web'),
                priority_vulns=data.get('priority_vulns', ['rce', 'sqli', 'xss', 'idor', 'ssrf'])
            )
            
            workflow = self.bugbounty_manager.create_reconnaissance_workflow(target)
            
            logger.info(f"🔍 Created reconnaissance workflow for {target.domain}")
            
            return jsonify({
                "success": True,
                "target": target.domain,
                "workflow": workflow,
                "message": "Bug bounty reconnaissance workflow created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating reconnaissance workflow: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def vulnerability_hunting_workflow(self) -> Dict[str, Any]:
        """Create vulnerability hunting workflow"""
        try:
            data = request.get_json()
            
            target = BugBountyTarget(
                domain=data.get('domain', ''),
                priority_vulns=data.get('priority_vulns', ['rce', 'sqli', 'xss'])
            )
            
            workflow = self.bugbounty_manager.create_vulnerability_hunting_workflow(target)
            
            logger.info(f"🎯 Created vulnerability hunting workflow for {target.domain}")
            
            return jsonify({
                "success": True,
                "target": target.domain,
                "workflow": workflow,
                "message": "Vulnerability hunting workflow created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating vulnerability workflow: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def business_logic_workflow(self) -> Dict[str, Any]:
        """Create business logic testing workflow"""
        try:
            data = request.get_json()
            
            target = BugBountyTarget(
                domain=data.get('domain', ''),
                program_type=data.get('program_type', 'web')
            )
            
            workflow = self.bugbounty_manager.create_business_logic_workflow(target)
            
            logger.info(f"🧠 Created business logic workflow for {target.domain}")
            
            return jsonify({
                "success": True,
                "target": target.domain,
                "workflow": workflow,
                "message": "Business logic testing workflow created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating business logic workflow: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def osint_workflow(self) -> Dict[str, Any]:
        """Create OSINT gathering workflow"""
        try:
            data = request.get_json()
            
            target = BugBountyTarget(
                domain=data.get('domain', '')
            )
            
            workflow = self.bugbounty_manager.create_osint_workflow(target)
            
            logger.info(f"🕵️ Created OSINT workflow for {target.domain}")
            
            return jsonify({
                "success": True,
                "target": target.domain,
                "workflow": workflow,
                "message": "OSINT gathering workflow created"
            })
            
        except Exception as e:
            logger.error(f"💥 Error creating OSINT workflow: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def prioritize_vulnerabilities(self) -> Dict[str, Any]:
        """Prioritize discovered vulnerabilities"""
        try:
            data = request.get_json()
            
            discovered_vulns = data.get('vulnerabilities', [])
            
            prioritized = self.bugbounty_manager.prioritize_vulnerabilities(discovered_vulns)
            
            logger.info(f"📊 Prioritized {len(discovered_vulns)} vulnerabilities")
            
            return jsonify({
                "success": True,
                "prioritized_vulnerabilities": prioritized,
                "total_count": len(discovered_vulns),
                "message": "Vulnerabilities prioritized by impact"
            })
            
        except Exception as e:
            logger.error(f"💥 Error prioritizing vulnerabilities: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def suggest_next_steps(self) -> Dict[str, Any]:
        """Suggest next steps based on findings"""
        try:
            data = request.get_json()
            
            current_findings = data.get('findings', {})
            
            suggestions = self.bugbounty_manager.suggest_next_steps(current_findings)
            
            logger.info(f"💡 Generated {len(suggestions)} suggestions")
            
            return jsonify({
                "success": True,
                "suggestions": suggestions,
                "findings_summary": current_findings,
                "message": "Next steps suggested based on current findings"
            })
            
        except Exception as e:
            logger.error(f"💥 Error suggesting next steps: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def estimate_bounty_potential(self) -> Dict[str, Any]:
        """Estimate bounty potential"""
        try:
            data = request.get_json()
            
            target = BugBountyTarget(
                domain=data.get('domain', ''),
                program_type=data.get('program_type', 'web'),
                bounty_range=data.get('bounty_range', 'unknown')
            )
            
            workflow_results = data.get('results', {})
            
            bounty_estimate = self.bugbounty_manager.estimate_bounty_potential(target, workflow_results)
            
            logger.info(f"💰 Estimated bounty potential for {target.domain}")
            
            return jsonify({
                "success": True,
                "target": target.domain,
                "bounty_estimate": bounty_estimate,
                "message": "Bounty potential estimated"
            })
            
        except Exception as e:
            logger.error(f"💥 Error estimating bounty potential: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
</new_str>
