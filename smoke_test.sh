#!/bin/bash


set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

TEST_TIMEOUT=10

PASSED_TOOLS=()
FAILED_TOOLS=()
SKIPPED_TOOLS=()

log_test() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] [$level] $message"
}

test_tool() {
    local tool="$1"
    local version_cmd="$2"
    local description="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -n "Testing $tool... "
    
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo -e "${YELLOW}SKIPPED${NC} (not installed)"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        SKIPPED_TOOLS+=("$tool")
        return 0
    fi
    
    if timeout "$TEST_TIMEOUT" bash -c "$version_cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        PASSED_TOOLS+=("$tool")
        log_test "INFO" "$tool: $description - PASSED"
    else
        echo -e "${RED}FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TOOLS+=("$tool")
        log_test "ERROR" "$tool: $description - FAILED"
    fi
}

test_python_package() {
    local package="$1"
    local import_name="$2"
    local description="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -n "Testing Python package $package... "
    
    if timeout "$TEST_TIMEOUT" python3 -c "import ${import_name}" 2>/dev/null; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        PASSED_TOOLS+=("$package")
        log_test "INFO" "$package: $description - PASSED"
    else
        echo -e "${RED}FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TOOLS+=("$package")
        log_test "ERROR" "$package: $description - FAILED"
    fi
}

test_system_dependency() {
    local tool="$1"
    local test_cmd="$2"
    local description="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -n "Testing system dependency $tool... "
    
    if timeout "$TEST_TIMEOUT" bash -c "$test_cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        PASSED_TOOLS+=("$tool")
        log_test "INFO" "$tool: $description - PASSED"
    else
        echo -e "${RED}FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TOOLS+=("$tool")
        log_test "ERROR" "$tool: $description - FAILED"
    fi
}

echo -e "${CYAN}🧪 HexStrike AI - Smoke Test Suite${NC}"
echo -e "${CYAN}====================================${NC}"
echo ""

echo -e "${BLUE}🔧 Testing System Dependencies${NC}"
echo "--------------------------------"
test_system_dependency "gcc" "gcc --version" "GNU Compiler Collection"
test_system_dependency "make" "make --version" "Build automation tool"
test_system_dependency "python3" "python3 --version" "Python 3 interpreter"
test_system_dependency "pip3" "pip3 --version" "Python package installer"
test_system_dependency "go" "go version" "Go programming language"
test_system_dependency "git" "git --version" "Version control system"
test_system_dependency "curl" "curl --version" "Data transfer tool"
test_system_dependency "wget" "wget --version" "Network downloader"
test_system_dependency "unzip" "unzip -v" "Archive extraction utility"
test_system_dependency "pkg-config" "pkg-config --version" "Package configuration system"
echo ""

echo -e "${BLUE}🌐 Testing Network & Reconnaissance Tools${NC}"
echo "-------------------------------------------"
test_tool "nmap" "nmap --version" "Network discovery and security auditing"
test_tool "masscan" "masscan --version" "High-speed TCP port scanner"
test_tool "amass" "amass --version" "Attack surface mapping and asset discovery"
test_tool "subfinder" "subfinder -version" "Fast passive subdomain enumeration"
test_tool "nuclei" "nuclei -version" "Fast vulnerability scanner"
test_tool "fierce" "fierce --version" "Domain scanner for non-contiguous IP space"
test_tool "dnsenum" "dnsenum --version" "DNS information enumeration"
test_tool "theharvester" "theharvester --version" "OSINT email and subdomain harvester"
test_tool "responder" "responder --version" "LLMNR/NBT-NS/MDNS poisoner"
test_tool "rustscan" "rustscan --version" "Modern port scanner"
echo ""

echo -e "${BLUE}🌍 Testing Web Application Security Tools${NC}"
echo "------------------------------------------"
test_tool "gobuster" "gobuster --version" "Directory/file/DNS busting tool"
test_tool "ffuf" "ffuf -V" "Fast web fuzzer"
test_tool "dirb" "dirb -V" "Web content scanner"
test_tool "nikto" "nikto -Version" "Web server scanner"
test_tool "sqlmap" "sqlmap --version" "SQL injection testing tool"
test_tool "wpscan" "wpscan --version" "WordPress vulnerability scanner"
test_tool "wafw00f" "wafw00f --version" "Web Application Firewall detection"
test_tool "zaproxy" "zap.sh -version" "Web application security scanner"
test_tool "xsser" "xsser --version" "Cross-site scripting detection"
test_tool "wfuzz" "wfuzz --version" "Web application fuzzer"
echo ""

echo -e "${BLUE}🔐 Testing Authentication & Password Security Tools${NC}"
echo "----------------------------------------------------"
test_tool "hydra" "hydra --version" "Network logon cracker"
test_tool "john" "john --version" "Password cracker"
test_tool "hashcat" "hashcat --version" "Advanced password recovery"
test_tool "medusa" "medusa -V" "Speedy, parallel, modular login brute-forcer"
test_tool "patator" "patator --version" "Multi-purpose brute-forcer"
test_tool "evil-winrm" "evil-winrm --version" "Windows Remote Management shell"
test_tool "hash-identifier" "hash-identifier --version" "Hash type identifier"
test_tool "ophcrack" "ophcrack --version" "Windows password cracker"
echo ""

echo -e "${BLUE}🔬 Testing Binary Analysis & Reverse Engineering Tools${NC}"
echo "-------------------------------------------------------"
test_tool "gdb" "gdb --version" "GNU Debugger"
test_tool "radare2" "radare2 -v" "Reverse engineering framework"
test_tool "binwalk" "binwalk --version" "Firmware analysis tool"
test_tool "checksec" "checksec --version" "Binary security checker"
test_tool "objdump" "objdump --version" "Binary utilities"
test_tool "foremost" "foremost -V" "File carving tool"
test_tool "steghide" "steghide --version" "Steganography tool"
test_tool "exiftool" "exiftool -ver" "Metadata extraction tool"
test_tool "sleuthkit" "tsk_version" "Digital forensics toolkit"
test_tool "xxd" "xxd -v" "Hex dump utility"
echo ""

echo -e "${BLUE}🐍 Testing Python Packages${NC}"
echo "----------------------------"
test_python_package "autorecon" "autorecon" "Multi-threaded network reconnaissance"
test_python_package "ropgadget" "ropgadget" "ROP gadget finder"
test_python_package "arjun" "arjun" "HTTP parameter discovery"
test_python_package "crackmapexec" "crackmapexec" "Network service exploitation"
test_python_package "netexec" "netexec" "Network service exploitation (CME successor)"
test_python_package "volatility3" "volatility3" "Memory forensics framework"
test_python_package "smbmap" "smbmap" "SMB enumeration tool"
echo ""

echo -e "${BLUE}🐹 Testing Go Tools${NC}"
echo "-------------------"
test_tool "httpx" "httpx -version" "Fast HTTP probe"
test_tool "katana" "katana -version" "Web crawling framework"
test_tool "dalfox" "dalfox version" "XSS scanner"
test_tool "hakrawler" "hakrawler --version" "Web crawler"
test_tool "subjack" "subjack --version" "Subdomain takeover tool"
echo ""

echo -e "${BLUE}☁️ Testing Cloud & Container Security Tools${NC}"
echo "---------------------------------------------"
test_tool "trivy" "trivy --version" "Container vulnerability scanner"
test_tool "kube-bench" "kube-bench --version" "Kubernetes security checker"
echo ""

echo -e "${BLUE}🏆 Testing Advanced CTF & Forensics Tools${NC}"
echo "------------------------------------------"
test_tool "autopsy" "autopsy --version" "Digital forensics platform"
test_tool "hashpump" "hashpump --version" "Hash length extension attack tool"
test_wireshark() {
    log_info "Testing wireshark..."
    if command -v wireshark >/dev/null 2>&1; then
        wireshark --version >/dev/null 2>&1
        log_pass "wireshark"
    else
        log_fail "wireshark not found"
    fi
}

test_tshark() {
    log_info "Testing tshark..."
    if command -v tshark >/dev/null 2>&1; then
        tshark --version >/dev/null 2>&1
        log_pass "tshark"
    else
        log_fail "tshark not found"
    fi
}

test_tcpdump() {
    log_info "Testing tcpdump..."
    if command -v tcpdump >/dev/null 2>&1; then
        tcpdump --version >/dev/null 2>&1
        log_pass "tcpdump"
    else
        log_fail "tcpdump not found"
    fi
}

test_ngrep() {
    log_info "Testing ngrep..."
    if command -v ngrep >/dev/null 2>&1; then
        ngrep -V >/dev/null 2>&1
        log_pass "ngrep"
    else
        log_fail "ngrep not found"
    fi
}

test_aircrack_ng() {
    log_info "Testing aircrack-ng..."
    if command -v aircrack-ng >/dev/null 2>&1; then
        aircrack-ng --version >/dev/null 2>&1
        log_pass "aircrack-ng"
    else
        log_fail "aircrack-ng not found"
    fi
}

test_reaver() {
    log_info "Testing reaver..."
    if command -v reaver >/dev/null 2>&1; then
        reaver --version >/dev/null 2>&1
        log_pass "reaver"
    else
        log_fail "reaver not found"
    fi
}

test_kismet() {
    log_info "Testing kismet..."
    if command -v kismet >/dev/null 2>&1; then
        kismet --version >/dev/null 2>&1
        log_pass "kismet"
    else
        log_fail "kismet not found"
    fi
}

test_searchsploit() {
    log_info "Testing searchsploit..."
    if command -v searchsploit >/dev/null 2>&1; then
        searchsploit --version >/dev/null 2>&1
        log_pass "searchsploit"
    else
        log_fail "searchsploit not found"
    fi
}

test_shodan() {
    log_info "Testing shodan..."
    if command -v shodan >/dev/null 2>&1; then
        shodan --version >/dev/null 2>&1
        log_pass "shodan"
    else
        log_fail "shodan not found"
    fi
}

test_censys() {
    log_info "Testing censys..."
    if command -v censys >/dev/null 2>&1; then
        censys --version >/dev/null 2>&1
        log_pass "censys"
    else
        log_fail "censys not found"
    fi
}

test_ldapsearch() {
    log_info "Testing ldapsearch..."
    if command -v ldapsearch >/dev/null 2>&1; then
        ldapsearch -VV >/dev/null 2>&1
        log_pass "ldapsearch"
    else
        log_fail "ldapsearch not found"
    fi
}

test_snmpwalk() {
    log_info "Testing snmpwalk..."
    if command -v snmpwalk >/dev/null 2>&1; then
        snmpwalk -V >/dev/null 2>&1
        log_pass "snmpwalk"
    else
        log_fail "snmpwalk not found"
    fi
}

test_impacket() {
    log_info "Testing impacket..."
    if command -v impacket-smbclient >/dev/null 2>&1; then
        impacket-smbclient --version >/dev/null 2>&1
        log_pass "impacket"
    else
        log_fail "impacket not found"
    fi
}

echo ""

echo -e "${BLUE}📡 Testing Network Analysis & Monitoring Tools${NC}"
echo "-----------------------------------------------"
test_wireshark
test_tshark
test_tcpdump
test_ngrep
test_aircrack_ng
test_reaver
test_kismet
echo ""

echo -e "${BLUE}🔍 Testing Exploit & Vulnerability Research Tools${NC}"
echo "-------------------------------------------------"
test_searchsploit
echo ""

echo -e "${BLUE}🕵️ Testing OSINT & Information Gathering Tools${NC}"
echo "-----------------------------------------------"
test_shodan
test_censys
test_ldapsearch
test_snmpwalk
test_impacket
echo ""

echo -e "${CYAN}📊 Test Summary${NC}"
echo "==============="
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED_TESTS${NC}"
echo ""

if [ $TOTAL_TESTS -gt 0 ]; then
    SUCCESS_RATE=$(( (PASSED_TESTS * 100) / TOTAL_TESTS ))
    echo -e "Success Rate: $SUCCESS_RATE%"
else
    SUCCESS_RATE=0
    echo -e "Success Rate: N/A"
fi

echo ""

if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}❌ Failed Tools:${NC}"
    for tool in "${FAILED_TOOLS[@]}"; do
        echo -e "  - $tool"
    done
    echo ""
fi

if [ $SKIPPED_TESTS -gt 0 ]; then
    echo -e "${YELLOW}⏭️ Skipped Tools (not installed):${NC}"
    for tool in "${SKIPPED_TOOLS[@]}"; do
        echo -e "  - $tool"
    done
    echo ""
fi

echo -e "${CYAN}🤖 HexStrike AI Readiness Assessment${NC}"
echo "======================================"

if [ $SUCCESS_RATE -ge 90 ]; then
    echo -e "🔥 ${GREEN}ELITE SETUP! Your AI agents are ready for advanced autonomous pentesting!${NC}"
    echo -e "${GREEN}✅ Full HexStrike AI capabilities unlocked${NC}"
elif [ $SUCCESS_RATE -ge 80 ]; then
    echo -e "🚀 ${GREEN}EXCELLENT! AI agents can perform comprehensive security assessments${NC}"
    echo -e "${GREEN}✅ Most HexStrike AI features available${NC}"
elif [ $SUCCESS_RATE -ge 70 ]; then
    echo -e "👍 ${YELLOW}GOOD! AI agents have solid cybersecurity capabilities${NC}"
    echo -e "${YELLOW}⚠️ Some advanced features may be limited${NC}"
elif [ $SUCCESS_RATE -ge 50 ]; then
    echo -e "⚠️ ${YELLOW}MODERATE! Basic AI agent security testing possible${NC}"
    echo -e "${YELLOW}❌ Advanced HexStrike AI features unavailable${NC}"
else
    echo -e "❌ ${RED}INSUFFICIENT! Major limitations in AI agent capabilities${NC}"
    echo -e "${RED}🔧 Install more tools for meaningful HexStrike AI functionality${NC}"
fi

echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Check the output above for details.${NC}"
    exit 1
fi
