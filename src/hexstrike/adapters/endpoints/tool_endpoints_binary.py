"""
Binary analysis and exploitation tool endpoint handlers.

This module handles endpoints for binary analysis and exploitation tools.
"""

from typing import Dict, Any
from flask import request, jsonify
import logging
from ...services.tool_execution_service import ToolExecutionService

logger = logging.getLogger(__name__)

class BinaryToolEndpoints:
    """Binary analysis and exploitation tool endpoint handlers"""
    
    def __init__(self):
        self.tool_executor = ToolExecutionService()
    
    def _execute_tool_endpoint(self, tool_name: str) -> Dict[str, Any]:
        """Generic tool execution endpoint"""
        try:
            data = request.get_json() or {}
            
            result = self.tool_executor.execute_tool(tool_name, data)
            
            if result.success:
                logger.info(f"✅ {tool_name} executed successfully")
                return jsonify({
                    "success": True,
                    "tool": tool_name,
                    "result": result.stdout,
                    "execution_time": result.execution_time,
                    "message": f"{tool_name} execution completed"
                })
            else:
                logger.error(f"❌ {tool_name} execution failed: {result.stderr}")
                return jsonify({
                    "success": False,
                    "tool": tool_name,
                    "error": result.stderr,
                    "message": f"{tool_name} execution failed"
                }), 500
                
        except Exception as e:
            logger.error(f"💥 Error in {tool_name} endpoint: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    def gdb(self):
        """Execute GDB debugger"""
        return self._execute_tool_endpoint("gdb")
    
    def radare2(self):
        """Execute Radare2 reverse engineering"""
        return self._execute_tool_endpoint("radare2")
    
    def binwalk(self):
        """Execute Binwalk firmware analysis"""
        return self._execute_tool_endpoint("binwalk")
    
    def ropgadget(self):
        """Execute ROPgadget ROP chain builder"""
        return self._execute_tool_endpoint("ropgadget")
    
    def checksec(self):
        """Execute checksec binary security checker"""
        return self._execute_tool_endpoint("checksec")
    
    def xxd(self):
        """Execute xxd hex dump utility"""
        return self._execute_tool_endpoint("xxd")
    
    def strings(self):
        """Execute strings binary analysis"""
        return self._execute_tool_endpoint("strings")
    
    def objdump(self):
        """Execute objdump binary analysis"""
        return self._execute_tool_endpoint("objdump")
    
    def ghidra(self):
        """Execute Ghidra reverse engineering"""
        return self._execute_tool_endpoint("ghidra")
    
    def pwntools(self):
        """Execute Pwntools exploit development"""
        return self._execute_tool_endpoint("pwntools")
    
    def one_gadget(self):
        """Execute one_gadget RCE finder"""
        return self._execute_tool_endpoint("one-gadget")
    
    def libc_database(self):
        """Execute libc-database lookup"""
        return self._execute_tool_endpoint("libc-database")
    
    def gdb_peda(self):
        """Execute GDB with PEDA"""
        return self._execute_tool_endpoint("gdb-peda")
    
    def angr(self):
        """Execute angr symbolic execution"""
        return self._execute_tool_endpoint("angr")
    
    def ropper(self):
        """Execute ropper ROP gadget finder"""
        return self._execute_tool_endpoint("ropper")
    
    def pwninit(self):
        """Execute pwninit CTF setup"""
        return self._execute_tool_endpoint("pwninit")
    
    def volatility(self):
        """Execute Volatility memory forensics"""
        return self._execute_tool_endpoint("volatility")
    
    def volatility3(self):
        """Execute Volatility3 memory forensics"""
        return self._execute_tool_endpoint("volatility3")
    
    def msfvenom(self):
        """Execute MSFVenom payload generator"""
        return self._execute_tool_endpoint("msfvenom")
    
    def foremost(self):
        """Execute Foremost file carving"""
        return self._execute_tool_endpoint("foremost")
    
    def steghide(self):
        """Execute Steghide steganography"""
        return self._execute_tool_endpoint("steghide")
    
    def exiftool(self):
        """Execute ExifTool metadata extraction"""
        return self._execute_tool_endpoint("exiftool")
