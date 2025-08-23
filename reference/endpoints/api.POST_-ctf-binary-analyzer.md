---
title: POST /api/ctf/binary-analyzer
group: api
handler: ctf_binary_analyzer
module: __main__
line_range: [14635, 14809]
discovered_in_chunk: 14
---

# POST /api/ctf/binary-analyzer

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced binary analysis for reverse engineering and pwn challenges

## Complete Signature & Definition
```python
@app.route("/api/ctf/binary-analyzer", methods=["POST"])
def ctf_binary_analyzer():
    """Advanced binary analysis for reverse engineering and pwn challenges"""
```

## Purpose & Behavior
Binary analysis endpoint providing:
- **Security Analysis:** Check binary security protections and vulnerabilities
- **Reverse Engineering:** Analyze binary structure and functions
- **Exploit Development:** Identify ROP gadgets and exploitation vectors
- **Enhanced Logging:** Detailed logging of binary analysis process

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ctf/binary-analyzer
- **Content-Type:** application/json

### Request Body
```json
{
    "binary_path": "string",         // Required: Path to binary file
    "analysis_depth": "string",      // Optional: "basic", "comprehensive", "deep" (default: "comprehensive")
    "check_protections": boolean,    // Optional: Check security protections (default: true)
    "find_gadgets": boolean          // Optional: Find ROP gadgets (default: true)
}
```

### Parameters
- **binary_path:** Path to the binary file to analyze (required)
- **analysis_depth:** Depth of analysis - "basic", "comprehensive", or "deep" (optional, default: "comprehensive")
- **check_protections:** Whether to check security protections (optional, default: true)
- **find_gadgets:** Whether to find ROP gadgets (optional, default: true)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "analysis": {
        "binary_path": "/path/to/binary",
        "analysis_depth": "comprehensive",
        "file_info": {
            "type": "ELF 64-bit LSB executable, x86-64",
            "architecture": "x86_64"
        },
        "security_protections": {
            "checksec": "RELRO: Partial RELRO\nStack: No canary found\nNX: NX enabled\nPIE: No PIE"
        },
        "interesting_functions": ["main", "vulnerable_function", "system"],
        "strings_analysis": {
            "functions": ["printf", "gets", "system"],
            "format_strings": ["%s", "%d"],
            "potential_flags": ["flag{hidden_here}"],
            "system_calls": ["/bin/sh"]
        },
        "gadgets": ["0x401234: pop rdi; ret", "0x401567: pop rsi; ret"],
        "recommended_tools": ["gdb-peda", "radare2", "ghidra", "pwntools"],
        "exploitation_hints": [
            "Stack canary disabled - buffer overflow exploitation possible",
            "PIE disabled - fixed addresses, ROP/ret2libc easier",
            "Dangerous functions found: gets - potential buffer overflow"
        ]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Response (400 Bad Request)
```json
{
    "error": "Binary path is required"
}
```

### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Code Reproduction
```python
@app.route("/api/ctf/binary-analyzer", methods=["POST"])
def ctf_binary_analyzer():
    """Advanced binary analysis for reverse engineering and pwn challenges"""
    try:
        params = request.json
        binary_path = params.get("binary_path", "")
        analysis_depth = params.get("analysis_depth", "comprehensive")  # basic, comprehensive, deep
        check_protections = params.get("check_protections", True)
        find_gadgets = params.get("find_gadgets", True)
        
        if not binary_path:
            return jsonify({"error": "Binary path is required"}), 400
        
        results = {
            "binary_path": binary_path,
            "analysis_depth": analysis_depth,
            "file_info": {},
            "security_protections": {},
            "interesting_functions": [],
            "strings_analysis": {},
            "gadgets": [],
            "recommended_tools": [],
            "exploitation_hints": []
        }
        
        # Basic file information
        try:
            file_result = subprocess.run(['file', binary_path], capture_output=True, text=True, timeout=30)
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()
                
                # Determine architecture and suggest tools
                file_output = file_result.stdout.lower()
                if "x86-64" in file_output or "x86_64" in file_output:
                    results["file_info"]["architecture"] = "x86_64"
                elif "i386" in file_output or "80386" in file_output:
                    results["file_info"]["architecture"] = "i386"
                elif "arm" in file_output:
                    results["file_info"]["architecture"] = "ARM"
                
                results["recommended_tools"].extend(["gdb-peda", "radare2", "ghidra"])
        except Exception as e:
            results["file_info"]["error"] = str(e)
        
        # Security protections check
        if check_protections:
            try:
                checksec_result = subprocess.run(['checksec', '--file', binary_path], capture_output=True, text=True, timeout=30)
                if checksec_result.returncode == 0:
                    results["security_protections"]["checksec"] = checksec_result.stdout
                    
                    # Parse protections and provide exploitation hints
                    output = checksec_result.stdout.lower()
                    if "no canary found" in output:
                        results["exploitation_hints"].append("Stack canary disabled - buffer overflow exploitation possible")
                    if "nx disabled" in output:
                        results["exploitation_hints"].append("NX disabled - shellcode execution on stack possible")
                    if "no pie" in output:
                        results["exploitation_hints"].append("PIE disabled - fixed addresses, ROP/ret2libc easier")
                    if "no relro" in output:
                        results["exploitation_hints"].append("RELRO disabled - GOT overwrite attacks possible")
            except Exception as e:
                results["security_protections"]["error"] = str(e)
        
        # Strings analysis
        try:
            strings_result = subprocess.run(['strings', binary_path], capture_output=True, text=True, timeout=30)
            if strings_result.returncode == 0:
                strings_output = strings_result.stdout.split('\n')
                
                # Categorize interesting strings
                interesting_categories = {
                    "functions": [],
                    "format_strings": [],
                    "file_paths": [],
                    "potential_flags": [],
                    "system_calls": []
                }
                
                for string in strings_output:
                    string = string.strip()
                    if not string:
                        continue
                    
                    # Look for function names
                    if any(func in string for func in ['printf', 'scanf', 'gets', 'strcpy', 'system', 'execve']):
                        interesting_categories["functions"].append(string)
                    
                    # Look for format strings
                    if '%' in string and any(fmt in string for fmt in ['%s', '%d', '%x', '%n']):
                        interesting_categories["format_strings"].append(string)
                    
                    # Look for file paths
                    if string.startswith('/') or '\\' in string:
                        interesting_categories["file_paths"].append(string)
                    
                    # Look for potential flags
                    if any(keyword in string.lower() for keyword in ['flag', 'ctf', 'key', 'password']):
                        interesting_categories["potential_flags"].append(string)
                    
                    # Look for system calls
                    if string in ['sh', 'bash', '/bin/sh', '/bin/bash', 'cmd.exe']:
                        interesting_categories["system_calls"].append(string)
                
                results["strings_analysis"] = interesting_categories
                
                # Add exploitation hints based on strings
                if interesting_categories["functions"]:
                    dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf']
                    found_dangerous = [f for f in dangerous_funcs if any(f in s for s in interesting_categories["functions"])]
                    if found_dangerous:
                        results["exploitation_hints"].append(f"Dangerous functions found: {', '.join(found_dangerous)} - potential buffer overflow")
                
                if interesting_categories["format_strings"]:
                    if any('%n' in s for s in interesting_categories["format_strings"]):
                        results["exploitation_hints"].append("Format string with %n found - potential format string vulnerability")
        
        except Exception as e:
            results["strings_analysis"]["error"] = str(e)
        
        # ROP gadgets search
        if find_gadgets and analysis_depth in ["comprehensive", "deep"]:
            try:
                ropgadget_result = subprocess.run(['ROPgadget', '--binary', binary_path, '--only', 'pop|ret'], capture_output=True, text=True, timeout=60)
                if ropgadget_result.returncode == 0:
                    gadget_lines = ropgadget_result.stdout.split('\n')
                    useful_gadgets = []
                    
                    for line in gadget_lines:
                        if 'pop' in line and 'ret' in line:
                            useful_gadgets.append(line.strip())
                    
                    results["gadgets"] = useful_gadgets[:20]  # Limit to first 20 gadgets
                    
                    if useful_gadgets:
                        results["exploitation_hints"].append(f"Found {len(useful_gadgets)} ROP gadgets - ROP chain exploitation possible")
                        results["recommended_tools"].append("ropper")
            
            except Exception as e:
                results["gadgets"] = [f"Error finding gadgets: {str(e)}"]
        
        # Function analysis with objdump
        if analysis_depth in ["comprehensive", "deep"]:
            try:
                objdump_result = subprocess.run(['objdump', '-t', binary_path], capture_output=True, text=True, timeout=30)
                if objdump_result.returncode == 0:
                    functions = []
                    for line in objdump_result.stdout.split('\n'):
                        if 'F .text' in line:  # Function in text section
                            parts = line.split()
                            if len(parts) >= 6:
                                func_name = parts[-1]
                                functions.append(func_name)
                    
                    results["interesting_functions"] = functions[:50]  # Limit to first 50 functions
            except Exception as e:
                results["interesting_functions"] = [f"Error analyzing functions: {str(e)}"]
        
        # Add tool recommendations based on findings
        if results["exploitation_hints"]:
            results["recommended_tools"].extend(["pwntools", "gdb-peda", "one-gadget"])
        
        if "format string" in str(results["exploitation_hints"]).lower():
            results["recommended_tools"].append("format-string-exploiter")
        
        logger.info(f"🔬 CTF binary analysis completed | Binary: {binary_path} | Hints: {len(results['exploitation_hints'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error in CTF binary analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
