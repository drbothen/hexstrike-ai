"""
Payload generation endpoint handlers.

This module changes when payload generation requirements change.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
import random
import string

logger = logging.getLogger(__name__)

class PayloadEndpoints:
    """Payload generation endpoint handlers"""
    
    def generate_payload(self) -> Dict[str, Any]:
        """Generate large payloads for testing"""
        try:
            data = request.get_json()
            
            payload_type = data.get('type', 'random')
            size = data.get('size', 1000)
            encoding = data.get('encoding', 'utf-8')
            
            if size > 1000000:  # 1MB limit
                return jsonify({"error": "Payload size too large (max 1MB)"}), 400
            
            payload = self._generate_payload_content(payload_type, size)
            
            logger.info(f"🎯 Generated {payload_type} payload: {size} bytes")
            
            return jsonify({
                "success": True,
                "payload": payload,
                "type": payload_type,
                "size": len(payload),
                "encoding": encoding
            })
            
        except Exception as e:
            logger.error(f"💥 Error generating payload: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def _generate_payload_content(self, payload_type: str, size: int) -> str:
        """Generate payload content based on type"""
        if payload_type == 'random':
            return ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        elif payload_type == 'xss':
            base_payload = "<script>alert('XSS')</script>"
            return (base_payload * (size // len(base_payload) + 1))[:size]
        elif payload_type == 'sqli':
            base_payload = "' OR 1=1 --"
            return (base_payload * (size // len(base_payload) + 1))[:size]
        elif payload_type == 'buffer_overflow':
            return 'A' * size
        else:
            return ''.join(random.choices(string.printable, k=size))
