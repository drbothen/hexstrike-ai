---
title: GET /health
group: root
handler: health_check
module: __main__
line_range: [7155, 7267]
discovered_in_chunk: 7
---

# GET /health

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Health check endpoint with comprehensive tool detection

## Complete Signature & Definition
```python
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint with comprehensive tool detection"""
```

## Purpose & Behavior
Comprehensive health check endpoint providing:
- **System Health Status:** Overall system operational status
- **Tool Availability Detection:** Check availability of 100+ security tools across 13 categories
- **Category Statistics:** Detailed statistics for each tool category
- **Performance Metrics:** Cache and telemetry statistics
- **System Information:** Version, uptime, and operational metrics

## Request

### HTTP Method
- **Method:** GET
- **Path:** /health
- **Parameters:** None required

### Headers
- **Content-Type:** Not required (GET request)
- **Authentication:** Not required (public health check)

## Response

### Success Response (200 OK)
```json
{
    "status": "healthy",
    "message": "HexStrike AI Tools API Server is operational",
    "version": "6.0.0",
    "tools_status": {
        "nmap": true,
        "gobuster": false,
        // ... status for all 100+ tools
    },
    "all_essential_tools_available": true,
    "total_tools_available": 85,
    "total_tools_count": 120,
    "category_stats": {
        "essential": {"total": 8, "available": 8},
        "network": {"total": 10, "available": 9},
        // ... stats for all 13 categories
    },
    "cache_stats": {
        "size": 150,
        "max_size": 1000,
        "hit_rate": "75.5%",
        "hits": 302,
        "misses": 98,
        "evictions": 5
    },
    "telemetry": {
        "uptime_seconds": 3600.5,
        "commands_executed": 245,
        "success_rate": "92.7%",
        "average_execution_time": "2.34s",
        "system_metrics": {
            "cpu_percent": 15.2,
            "memory_percent": 45.8,
            "disk_usage": 67.3,
            "network_io": {}
        }
    },
    "uptime": 3600.5
}
```

## Implementation Details

### Tool Categories (13 Categories, 100+ Tools)

#### Essential Tools (8 Tools)
- **Tools:** nmap, gobuster, dirb, nikto, sqlmap, hydra, john, hashcat
- **Purpose:** Core security testing tools required for basic operations

#### Network Tools (10 Tools)
- **Tools:** rustscan, masscan, autorecon, nbtscan, arp-scan, responder, nxc, enum4linux-ng, rpcclient, enum4linux
- **Purpose:** Network discovery and enumeration tools

#### Web Security Tools (24 Tools)
- **Tools:** ffuf, feroxbuster, dirsearch, dotdotpwn, xsser, wfuzz, gau, waybackurls, arjun, paramspider, x8, jaeles, dalfox, httpx, wafw00f, burpsuite, zaproxy, katana, hakrawler
- **Purpose:** Web application security testing tools

#### Vulnerability Scanning Tools (4 Tools)
- **Tools:** nuclei, wpscan, graphql-scanner, jwt-analyzer
- **Purpose:** Automated vulnerability scanning tools

#### Password Tools (5 Tools)
- **Tools:** medusa, patator, hash-identifier, ophcrack, hashcat-utils
- **Purpose:** Password cracking and hash analysis tools

#### Binary Tools (11 Tools)
- **Tools:** gdb, radare2, binwalk, ropgadget, checksec, objdump, ghidra, pwntools, one-gadget, ropper, angr, libc-database, pwninit
- **Purpose:** Binary analysis and reverse engineering tools

#### Forensics Tools (15 Tools)
- **Tools:** volatility3, vol, steghide, hashpump, foremost, exiftool, strings, xxd, file, photorec, testdisk, scalpel, bulk-extractor, stegsolve, zsteg, outguess
- **Purpose:** Digital forensics and steganography tools

#### Cloud Tools (10 Tools)
- **Tools:** prowler, scout-suite, trivy, kube-hunter, kube-bench, docker-bench-security, checkov, terrascan, falco, clair
- **Purpose:** Cloud security assessment tools

#### OSINT Tools (13 Tools)
- **Tools:** amass, subfinder, fierce, dnsenum, theharvester, sherlock, social-analyzer, recon-ng, maltego, spiderfoot, shodan-cli, censys-cli, have-i-been-pwned
- **Purpose:** Open source intelligence gathering tools

#### Exploitation Tools (3 Tools)
- **Tools:** metasploit, exploit-db, searchsploit
- **Purpose:** Exploitation frameworks and databases

#### API Tools (11 Tools)
- **Tools:** api-schema-analyzer, postman, insomnia, curl, httpie, anew, qsreplace, uro
- **Purpose:** API testing and analysis tools

#### Wireless Tools (4 Tools)
- **Tools:** kismet, wireshark, tshark, tcpdump
- **Purpose:** Wireless network analysis tools

#### Additional Tools (22 Tools)
- **Tools:** smbmap, volatility, sleuthkit, autopsy, evil-winrm, paramspider, airmon-ng, airodump-ng, aireplay-ng, aircrack-ng, msfvenom, msfconsole, graphql-scanner, jwt-analyzer
- **Purpose:** Additional specialized security tools

### Tool Detection Process

#### Detection Method
```python
for tool in all_tools:
    try:
        result = execute_command(f"which {tool}", use_cache=True)
        tools_status[tool] = result["success"]
    except:
        tools_status[tool] = False
```

#### Caching Integration
- **Cache Usage:** Use cached results for tool detection
- **Performance Optimization:** Avoid repeated tool detection calls
- **Reliability:** Graceful handling of detection failures

### Category Statistics Calculation

#### Statistics Structure
```python
{
    "total": int,                   # Total tools in category
    "available": int                # Available tools in category
}
```

#### Calculation Process
```python
category_stats = {
    "essential": {
        "total": len(essential_tools), 
        "available": sum(1 for tool in essential_tools if tools_status.get(tool, False))
    },
    // ... for all categories
}
```

### Performance Metrics Integration

#### Cache Statistics
- **Integration:** cache.get_stats() for cache performance metrics
- **Metrics:** Hit rate, cache size, evictions, and usage statistics

#### Telemetry Statistics
- **Integration:** telemetry.get_stats() for system telemetry
- **Metrics:** Uptime, command execution statistics, system resource usage

#### System Metrics
- **CPU Usage:** Real-time CPU utilization percentage
- **Memory Usage:** Current memory utilization percentage
- **Disk Usage:** Root filesystem usage percentage
- **Network I/O:** Network interface statistics

### Health Assessment Logic

#### Essential Tools Check
```python
all_essential_tools_available = all(tools_status[tool] for tool in essential_tools)
```

#### Overall Statistics
- **Total Available:** Count of all available tools across categories
- **Total Count:** Total number of tools checked
- **Availability Percentage:** Implicit calculation from totals

### Response Structure

#### Core Health Information
- **Status:** Always "healthy" (endpoint availability indicates health)
- **Message:** Descriptive operational status message
- **Version:** Application version (6.0.0)

#### Tool Information
- **Individual Status:** Boolean status for each tool
- **Category Statistics:** Detailed breakdown by tool category
- **Essential Tools Status:** Critical tools availability flag

#### Performance Information
- **Cache Performance:** Complete cache statistics
- **System Telemetry:** Comprehensive system metrics
- **Uptime:** System operational duration

## AuthN/AuthZ
- **Authentication:** Not required (public health check endpoint)
- **Authorization:** Not required (read-only system status)

## Error Handling
- **Tool Detection Errors:** Graceful handling with false status
- **Exception Safety:** Try-catch blocks prevent endpoint failure
- **Partial Results:** Return partial results if some tools fail detection

## Observability
- **Logging:** Tool detection results and performance metrics
- **Metrics:** Endpoint access and response time metrics
- **Monitoring:** System health and tool availability monitoring

## Use Cases and Applications

#### System Monitoring
- **Health Checks:** Automated system health monitoring
- **Tool Availability:** Monitor security tool availability
- **Performance Monitoring:** Track system performance metrics

#### Operational Readiness
- **Deployment Validation:** Validate tool availability after deployment
- **Environment Verification:** Verify environment setup and configuration
- **Capacity Planning:** Monitor system resource usage for planning

#### Integration Testing
- **API Testing:** Test API endpoint availability and response
- **Tool Integration:** Verify tool integration and availability
- **System Integration:** Validate overall system integration

## Testing & Validation
- Tool detection accuracy testing
- Category statistics calculation verification
- Performance metrics integration validation
- Response format and content verification

## Code Reproduction
Complete Flask endpoint implementation for comprehensive health checking with 100+ security tool detection across 13 categories, performance metrics integration, and detailed system status reporting. Essential for system monitoring and operational readiness validation.
