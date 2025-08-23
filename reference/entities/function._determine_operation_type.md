---
title: function._determine_operation_type
kind: function
scope: module
module: __main__
line_range: [7036, 7057]
discovered_in_chunk: 7
---

# Function: _determine_operation_type

## Entity Classification & Context
- **Kind:** Module-level function
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Determine operation type based on tool name

## Complete Signature & Definition
```python
def _determine_operation_type(tool_name: str) -> str:
    """Determine operation type based on tool name"""
    operation_mapping = {
        "nmap": "network_discovery",
        "rustscan": "network_discovery", 
        "masscan": "network_discovery",
        "gobuster": "web_discovery",
        "feroxbuster": "web_discovery",
        "dirsearch": "web_discovery",
        "ffuf": "web_discovery",
        "nuclei": "vulnerability_scanning",
        "jaeles": "vulnerability_scanning",
        "nikto": "vulnerability_scanning",
        "subfinder": "subdomain_enumeration",
        "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration",
        "arjun": "parameter_discovery",
        "paramspider": "parameter_discovery",
        "x8": "parameter_discovery"
    }
    
    return operation_mapping.get(tool_name, "unknown_operation")
```

## Purpose & Behavior
Tool classification utility providing:
- **Operation Type Mapping:** Map security tools to their primary operation types
- **Tool Categorization:** Categorize tools by their functional purpose
- **Fallback Handling:** Return "unknown_operation" for unmapped tools
- **Graceful Degradation Support:** Enable operation-specific graceful degradation

## Dependencies & Usage
- **Used by:**
  - execute_command_with_recovery function for graceful degradation
  - Degradation manager for operation-specific fallback strategies
  - Tool classification and workflow management

## Implementation Details

### Tool Operation Mapping (15 Tools, 5 Operation Types)

#### Network Discovery (3 Tools)
- **nmap:** Network mapping and port scanning
- **rustscan:** Fast port scanner
- **masscan:** High-speed port scanner

#### Web Discovery (4 Tools)
- **gobuster:** Directory and file brute-forcing
- **feroxbuster:** Fast content discovery
- **dirsearch:** Web path scanner
- **ffuf:** Fast web fuzzer

#### Vulnerability Scanning (3 Tools)
- **nuclei:** Vulnerability scanner with templates
- **jaeles:** Web application scanner
- **nikto:** Web server scanner

#### Subdomain Enumeration (3 Tools)
- **subfinder:** Subdomain discovery tool
- **amass:** Attack surface mapping
- **assetfinder:** Asset discovery tool

#### Parameter Discovery (3 Tools)
- **arjun:** HTTP parameter discovery
- **paramspider:** Parameter mining tool
- **x8:** Hidden parameter discovery

### Mapping Logic
- **Direct Lookup:** Use dictionary mapping for known tools
- **Fallback Value:** Return "unknown_operation" for unmapped tools
- **Case Sensitivity:** Exact tool name matching required

## Testing & Validation
- Tool name mapping accuracy testing
- Operation type classification verification
- Fallback behavior validation

## Code Reproduction
```python
def _determine_operation_type(tool_name: str) -> str:
    """Determine operation type based on tool name"""
    operation_mapping = {
        "nmap": "network_discovery",
        "rustscan": "network_discovery", 
        "masscan": "network_discovery",
        "gobuster": "web_discovery",
        "feroxbuster": "web_discovery",
        "dirsearch": "web_discovery",
        "ffuf": "web_discovery",
        "nuclei": "vulnerability_scanning",
        "jaeles": "vulnerability_scanning",
        "nikto": "vulnerability_scanning",
        "subfinder": "subdomain_enumeration",
        "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration",
        "arjun": "parameter_discovery",
        "paramspider": "parameter_discovery",
        "x8": "parameter_discovery"
    }
    
    return operation_mapping.get(tool_name, "unknown_operation")
```
