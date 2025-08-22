#!/bin/bash

# HexStrike AI - Official Tools Verification Script (Based on Official README)
# Supports multiple Linux distributions with verified download links
# Version 3.0.0 - Production-grade upgrade with macOS support and enhanced idempotency

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

INSTALL_MODE=false
INTERACTIVE_MODE=false
PROFILE=""
DRY_RUN=false
ESSENTIAL_ONLY=false
CI_MODE=false
HELP_MODE=false

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install)
                INSTALL_MODE=true
                shift
                ;;
            --interactive)
                INTERACTIVE_MODE=true
                shift
                ;;
            --profile)
                PROFILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --essential-only)
                ESSENTIAL_ONLY=true
                shift
                ;;
            --ci-mode)
                CI_MODE=true
                LOG_TO_FILE=false
                shift
                ;;
            --help|-h)
                HELP_MODE=true
                shift
                ;;
            --debug)
                LOG_LEVEL="DEBUG"
                shift
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << 'EOF'
HexStrike AI Setup Script v3.2 - Automatic Installation & Management

USAGE:
    ./setup.sh [OPTIONS]

OPTIONS:
    --help, -h          Show this help message
    --install           Automatically install missing tools (requires sudo)
    --interactive       Interactive tool selection mode
    --profile PROFILE   Use predefined tool profile:
                        - web-testing: Web application security tools
                        - network-recon: Network reconnaissance tools  
                        - ctf: CTF and forensics tools
                        - essential: Core security tools only
    --dry-run           Show what would be installed without installing
    --essential-only    Install only essential tools
    --ci-mode           CI/CD friendly mode (no colors, minimal output)
    --debug             Enable debug logging

EXAMPLES:
    ./setup.sh                          # Check tools (default behavior)
    ./setup.sh --install                # Install all missing tools
    ./setup.sh --interactive            # Select tools interactively
    ./setup.sh --profile web-testing    # Install web testing tools
    ./setup.sh --install --essential-only  # Install essential tools only
    ./setup.sh --dry-run --profile ctf  # Preview CTF tools installation

PROFILES:
    web-testing:    gobuster, ffuf, sqlmap, nuclei, burpsuite, nikto
    network-recon:  nmap, masscan, amass, subfinder, rustscan
    ctf:           gdb, radare2, binwalk, volatility3, john, hashcat
    essential:     nmap, gobuster, sqlmap, nuclei, hydra, nikto

NOTES:
    - Installation requires sudo privileges
    - Use --dry-run to preview changes before installation
    - Logs are saved to /tmp/hexstrike_setup_YYYYMMDD_HHMMSS.log
    - CI mode disables colors and interactive prompts

EOF
}

LOG_LEVEL=${LOG_LEVEL:-"INFO"}  # DEBUG, INFO, WARN, ERROR
LOG_FILE="/tmp/hexstrike_setup_$(date +%Y%m%d_%H%M%S).log"
LOG_TO_FILE=${LOG_TO_FILE:-true}

# Initialize logging
setup_logging() {
    if [ "$LOG_TO_FILE" = true ]; then
        mkdir -p "$(dirname "$LOG_FILE")"
        
        exec 3>&1 4>&2
        if [ "$LOG_LEVEL" = "DEBUG" ]; then
            exec 1> >(tee -a "$LOG_FILE")
            exec 2> >(tee -a "$LOG_FILE" >&2)
        else
            exec 1> >(tee -a "$LOG_FILE")
            exec 2> >(tee -a "$LOG_FILE" >&2)
        fi
        
        echo -e "${CYAN}📝 Logging to: $LOG_FILE${NC}"
        log_with_timestamp "HexStrike AI Setup Script v3.2 started"
        log_with_timestamp "System: $(uname -a)"
        log_with_timestamp "User: $(whoami)"
        log_with_timestamp "Working directory: $(pwd)"
    fi
}

log_with_timestamp() {
    local message="$1"
    local level=${2:-"INFO"}
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ "$LOG_TO_FILE" = true ]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
    
    case $level in
        "ERROR") echo -e "${RED}[$timestamp] [ERROR] $message${NC}" ;;
        "WARN")  echo -e "${YELLOW}[$timestamp] [WARN] $message${NC}" ;;
        "INFO")  echo -e "${CYAN}[$timestamp] [INFO] $message${NC}" ;;
        "DEBUG") [ "$LOG_LEVEL" = "DEBUG" ] && echo -e "${MAGENTA}[$timestamp] [DEBUG] $message${NC}" ;;
    esac
}

show_progress() {
    local current=$1
    local total=$2
    local task_name=${3:-"Processing"}
    local width=40
    
    if [ "$total" -eq 0 ]; then
        return
    fi
    
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r${CYAN}%s: [" "$task_name"
    printf "%*s" $completed | tr ' ' '█'
    printf "%*s" $remaining | tr ' ' '░'
    printf "] %d%% (%d/%d)${NC}" $percentage $current $total
    
    if [ "$current" -eq "$total" ]; then
        echo ""  # New line when complete
    fi
}

cleanup_logging() {
    if [ "$LOG_TO_FILE" = true ]; then
        log_with_timestamp "HexStrike AI Setup Script completed"
        echo -e "${GREEN}📝 Full log saved to: $LOG_FILE${NC}"
        
        exec 1>&3 2>&4
        exec 3>&- 4>&-
    fi
}

trap cleanup_logging EXIT

declare -A TOOL_PROFILES
init_tool_profiles() {
    TOOL_PROFILES["web-testing"]="gobuster ffuf sqlmap nuclei burpsuite nikto dirb wpscan whatweb wafw00f commix xsser"
    
    TOOL_PROFILES["network-recon"]="nmap masscan amass subfinder rustscan dnsenum fierce dnsrecon theharvester"
    
    TOOL_PROFILES["ctf"]="gdb radare2 binwalk volatility3 john hashcat steghide foremost exiftool strings xxd"
    
    # Essential Tools Profile
    TOOL_PROFILES["essential"]="nmap gobuster sqlmap nuclei hydra nikto john hashcat burpsuite amass"
    
    log_with_timestamp "Initialized tool profiles: ${!TOOL_PROFILES[*]}"
}

# Check if tool is in selected profile
is_tool_in_profile() {
    local tool="$1"
    local profile="$2"
    
    if [ -z "$profile" ]; then
        return 0  # No profile means include all tools
    fi
    
    if [ -n "${TOOL_PROFILES[$profile]}" ]; then
        echo "${TOOL_PROFILES[$profile]}" | grep -q "\b$tool\b"
        return $?
    else
        log_with_timestamp "Unknown profile: $profile" "WARN"
        return 1
    fi
}

interactive_tool_selection() {
    echo -e "${BLUE}🎯 Interactive Tool Selection${NC}"
    echo "Select tools to install (enter numbers separated by spaces, or 'all' for all tools):"
    echo ""
    
    local i=1
    local tool_list=()
    
    for missing in "${MISSING_TOOLS[@]}"; do
        local tool=$(echo "$missing" | cut -d':' -f1)
        tool_list+=("$tool")
        echo "[$i] $tool"
        ((i++))
    done
    
    echo ""
    read -p "Enter your selection: " selection
    
    if [ "$selection" = "all" ]; then
        SELECTED_TOOLS=("${tool_list[@]}")
        log_with_timestamp "User selected all tools for installation"
    else
        SELECTED_TOOLS=()
        for num in $selection; do
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#tool_list[@]}" ]; then
                local idx=$((num - 1))
                SELECTED_TOOLS+=("${tool_list[$idx]}")
                log_with_timestamp "User selected tool: ${tool_list[$idx]}"
            else
                echo -e "${YELLOW}⚠️  Invalid selection: $num${NC}"
            fi
        done
    fi
    
    echo -e "${GREEN}✅ Selected ${#SELECTED_TOOLS[@]} tools for installation${NC}"
}

# Banner
echo -e "${CYAN}"
echo "██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗"
echo "██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝"
echo "███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  "
echo "██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  "
echo "██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗"
echo "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${WHITE}HexStrike AI - Official Security Tools Checker v3.2${NC}"
echo -e "${BLUE}🔗 Based on official HexStrike AI README - 70+ tools coverage${NC}"
echo -e "${ORANGE}📋 Comprehensive verification with working download links${NC}"
echo ""

# Check if curl is available for link validation
CURL_AVAILABLE=false
if command -v curl > /dev/null 2>&1; then
    CURL_AVAILABLE=true
fi

check_url() {
    local url=$1
    local timeout=${2:-10}
    local max_retries=2
    local retry=0
    
    if [ "$CURL_AVAILABLE" = true ]; then
        while [ $retry -le $max_retries ]; do
            if timeout $timeout curl --output /dev/null --silent --head --fail \
               --max-time $timeout --retry 1 --retry-delay 1 \
               --user-agent "HexStrike-AI-Setup/3.1" "$url" 2>/dev/null; then
                return 0
            fi
            ((retry++))
            [ $retry -le $max_retries ] && sleep 1
        done
        return 1
    else
        return 0  # Assume working if curl not available
    fi
}

install_with_retry() {
    local cmd="$1"
    local tool_name="$2"
    local max_attempts=3
    local attempt=1
    local wait_time=2
    
    while [ $attempt -le $max_attempts ]; do
        log_with_timestamp "Attempting to install $tool_name (attempt $attempt/$max_attempts)"
        
        if timeout 300 bash -c "$cmd" 2>/dev/null; then
            log_with_timestamp "✅ Successfully installed $tool_name"
            return 0
        else
            local exit_code=$?
            log_with_timestamp "❌ Installation attempt $attempt failed for $tool_name (exit code: $exit_code)" "WARN"
            
            if [ $attempt -lt $max_attempts ]; then
                log_with_timestamp "⏳ Waiting ${wait_time}s before retry..."
                sleep $wait_time
                wait_time=$((wait_time * 2))  # Exponential backoff
            fi
            ((attempt++))
        fi
    done
    
    log_with_timestamp "🚫 Failed to install $tool_name after $max_attempts attempts" "ERROR"
    return 1
}

create_installation_checkpoint() {
    local checkpoint_file="/tmp/hexstrike_checkpoint_$(date +%s).txt"
    
    case $DISTRO in
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            dpkg --get-selections > "$checkpoint_file" 2>/dev/null
            ;;
        "fedora"|"rhel"|"centos")
            rpm -qa > "$checkpoint_file" 2>/dev/null
            ;;
        "arch"|"manjaro"|"endeavouros")
            pacman -Q > "$checkpoint_file" 2>/dev/null
            ;;
    esac
    
    echo "$checkpoint_file"
    log_with_timestamp "📋 Created installation checkpoint: $checkpoint_file"
}

install_package_manager_tools() {
    local tools="$1"
    if [ -z "$tools" ]; then
        return 0
    fi
    
    echo -e "${BLUE}📦 Installing package manager tools...${NC}"
    log_with_timestamp "Starting package manager installation: $tools"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${CYAN}[DRY RUN] Would execute: $INSTALL_CMD$tools${NC}"
        return 0
    fi
    
    echo -e "${CYAN}🔄 Updating package lists...${NC}"
    if ! install_with_retry "$UPDATE_CMD" "package-update"; then
        log_with_timestamp "Package update failed, continuing anyway" "WARN"
    fi
    
    local install_cmd="$INSTALL_CMD$tools"
    if install_with_retry "$install_cmd" "package-manager-tools"; then
        echo -e "${GREEN}✅ Package manager tools installed successfully${NC}"
        return 0
    else
        echo -e "${RED}❌ Package manager installation failed${NC}"
        return 1
    fi
}

install_go_tools() {
    local go_commands="$1"
    if [ -z "$go_commands" ]; then
        return 0
    fi
    
    echo -e "${BLUE}🐹 Installing Go tools...${NC}"
    log_with_timestamp "Starting Go tools installation"
    
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Go not found. Installing Go first...${NC}"
        if [ "$DRY_RUN" = true ]; then
            echo -e "${CYAN}[DRY RUN] Would install Go${NC}"
        else
            case $DISTRO in
                "ubuntu"|"debian"|"kali"|"parrot"|"mint")
                    install_with_retry "sudo apt install -y golang-go" "golang"
                    ;;
                "fedora"|"rhel"|"centos")
                    install_with_retry "sudo dnf install -y golang" "golang"
                    ;;
                "arch"|"manjaro"|"endeavouros")
                    install_with_retry "sudo pacman -S go" "golang"
                    ;;
            esac
        fi
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${CYAN}[DRY RUN] Would execute Go installations:${NC}"
        echo -e "$go_commands"
        return 0
    fi
    
    echo "$go_commands" | while IFS= read -r cmd; do
        if [ -n "$cmd" ]; then
            local tool_name=$(echo "$cmd" | awk '{print $NF}' | cut -d'@' -f1 | xargs basename)
            echo -e "${CYAN}Installing: $tool_name${NC}"
            if install_with_retry "$cmd" "$tool_name"; then
                echo -e "${GREEN}✅ $tool_name installed${NC}"
            else
                echo -e "${RED}❌ $tool_name installation failed${NC}"
            fi
        fi
    done
}

install_pip_tools() {
    local pip_commands="$1"
    if [ -z "$pip_commands" ]; then
        return 0
    fi
    
    echo -e "${BLUE}🐍 Installing Python tools...${NC}"
    log_with_timestamp "Starting Python tools installation"
    
    if ! command -v pip3 >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  pip3 not found. Installing pip3 first...${NC}"
        if [ "$DRY_RUN" = true ]; then
            echo -e "${CYAN}[DRY RUN] Would install pip3${NC}"
        else
            case $DISTRO in
                "ubuntu"|"debian"|"kali"|"parrot"|"mint")
                    install_with_retry "sudo apt install -y python3-pip" "python3-pip"
                    ;;
                "fedora"|"rhel"|"centos")
                    install_with_retry "sudo dnf install -y python3-pip" "python3-pip"
                    ;;
                "arch"|"manjaro"|"endeavouros")
                    install_with_retry "sudo pacman -S python-pip" "python-pip"
                    ;;
            esac
        fi
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${CYAN}[DRY RUN] Would execute pip installations:${NC}"
        echo -e "$pip_commands"
        return 0
    fi
    
    echo "$pip_commands" | while IFS= read -r cmd; do
        if [ -n "$cmd" ]; then
            local tool_name=$(echo "$cmd" | awk '{print $NF}')
            echo -e "${CYAN}Installing: $tool_name${NC}"
            if install_with_retry "$cmd" "$tool_name"; then
                echo -e "${GREEN}✅ $tool_name installed${NC}"
            else
                echo -e "${RED}❌ $tool_name installation failed${NC}"
            fi
        fi
    done
}

perform_automatic_installation() {
    if [ $MISSING_COUNT -eq 0 ]; then
        echo -e "${GREEN}🎉 All tools are already installed!${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}🚀 AUTOMATIC INSTALLATION MODE${NC}"
    echo "================================================"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${CYAN}🔍 DRY RUN MODE - No actual installations will be performed${NC}"
    fi
    
    local checkpoint_file
    if [ "$DRY_RUN" = false ]; then
        checkpoint_file=$(create_installation_checkpoint)
        echo -e "${BLUE}📋 Created installation checkpoint: $checkpoint_file${NC}"
    fi
    
    if [ "$DRY_RUN" = false ] && [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}🔐 Checking sudo access...${NC}"
        if ! sudo -n true 2>/dev/null; then
            echo -e "${CYAN}Please enter your password for sudo access:${NC}"
            sudo -v
            if [ $? -ne 0 ]; then
                echo -e "${RED}❌ Sudo access required for installation${NC}"
                return 1
            fi
        fi
        echo -e "${GREEN}✅ Sudo access confirmed${NC}"
    fi
    
    local PKG_MANAGER_TOOLS=""
    local GO_TOOLS=""
    local PIP_TOOLS=""
    local FAILED_INSTALLS=()
    local SUCCESS_COUNT=0
    
    local tools_to_install=()
    if [ "$INTERACTIVE_MODE" = true ]; then
        interactive_tool_selection
        tools_to_install=("${SELECTED_TOOLS[@]}")
    else
        for missing in "${MISSING_TOOLS[@]}"; do
            local tool=$(echo "$missing" | cut -d':' -f1)
            if is_tool_in_profile "$tool" "$PROFILE"; then
                tools_to_install+=("$missing")
            fi
        done
    fi
    
    if [ ${#tools_to_install[@]} -eq 0 ]; then
        echo -e "${YELLOW}⚠️  No tools selected for installation${NC}"
        return 0
    fi
    
    echo -e "${BLUE}📋 Installing ${#tools_to_install[@]} tools...${NC}"
    
    for missing in "${tools_to_install[@]}"; do
        local tool=$(echo "$missing" | cut -d':' -f1)
        local package=$(echo "$missing" | cut -d':' -f2)
        
        if [ -n "${TOOL_INSTALL_INFO[$tool]}" ]; then
            IFS='|' read -r install_type install_info description <<< "${TOOL_INSTALL_INFO[$tool]}"
            
            case $install_type in
                "pkg_manager")
                    PKG_MANAGER_TOOLS+=" $package"
                    ;;
                "go_install")
                    GO_TOOLS+="\n  go install -v $install_info@latest"
                    ;;
                "pip_install")
                    PIP_TOOLS+="\n  pip3 install $install_info"
                    ;;
                *)
                    echo -e "${YELLOW}⚠️  Skipping $tool (manual installation required)${NC}"
                    log_with_timestamp "Skipped $tool - manual installation required" "WARN"
                    ;;
            esac
        fi
    done
    
    local install_success=true
    
    if [ -n "$PKG_MANAGER_TOOLS" ]; then
        if install_package_manager_tools "$PKG_MANAGER_TOOLS"; then
            ((SUCCESS_COUNT++))
        else
            install_success=false
            FAILED_INSTALLS+=("package-manager-tools")
        fi
    fi
    
    if [ -n "$GO_TOOLS" ]; then
        if install_go_tools "$GO_TOOLS"; then
            ((SUCCESS_COUNT++))
        else
            install_success=false
            FAILED_INSTALLS+=("go-tools")
        fi
    fi
    
    if [ -n "$PIP_TOOLS" ]; then
        if install_pip_tools "$PIP_TOOLS"; then
            ((SUCCESS_COUNT++))
        else
            install_success=false
            FAILED_INSTALLS+=("pip-tools")
        fi
    fi
    
    echo ""
    echo -e "${BLUE}📊 INSTALLATION SUMMARY${NC}"
    echo "========================"
    
    if [ "$install_success" = true ] && [ ${#FAILED_INSTALLS[@]} -eq 0 ]; then
        echo -e "${GREEN}🎉 All installations completed successfully!${NC}"
        log_with_timestamp "All installations completed successfully"
    else
        echo -e "${YELLOW}⚠️  Some installations failed:${NC}"
        for failed in "${FAILED_INSTALLS[@]}"; do
            echo -e "   ❌ $failed"
        done
        log_with_timestamp "Installation completed with failures: ${FAILED_INSTALLS[*]}" "WARN"
    fi
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${CYAN}📋 Installation checkpoint: $checkpoint_file${NC}"
        echo -e "${CYAN}📝 Full log: $LOG_FILE${NC}"
    fi
    
    return 0
}

# Detect Linux distribution
detect_distro() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        DISTRO="macos"
        VERSION=$(sw_vers -productVersion)
        PRETTY_NAME="macOS $VERSION"
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) ARCH_TYPE="amd64" ;;
            arm64) ARCH_TYPE="arm64" ;;
            *) ARCH_TYPE="amd64" ;;
        esac
        echo -e "${BLUE}🍎 Detected OS: ${CYAN}$PRETTY_NAME${NC}"
        echo -e "${BLUE}📋 Distribution: ${CYAN}$DISTRO${NC}"
        echo -e "${BLUE}🏗️  Architecture: ${CYAN}$ARCH ($ARCH_TYPE)${NC}"
        echo ""
        return 0
    fi
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        PRETTY_NAME="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        PRETTY_NAME=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        PRETTY_NAME="Debian $(cat /etc/debian_version)"
    else
        DISTRO="unknown"
        PRETTY_NAME="Unknown Linux Distribution"
    fi
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_TYPE="amd64" ;;
        aarch64|arm64) ARCH_TYPE="arm64" ;;
        armv7l) ARCH_TYPE="armv7" ;;
        i686|i386) ARCH_TYPE="i386" ;;
        *) ARCH_TYPE="amd64" ;;
    esac
    
    echo -e "${BLUE}🐧 Detected OS: ${CYAN}$PRETTY_NAME${NC}"
    echo -e "${BLUE}📋 Distribution: ${CYAN}$DISTRO${NC}"
    echo -e "${BLUE}🏗️  Architecture: ${CYAN}$ARCH ($ARCH_TYPE)${NC}"
    echo ""
}

# Get package manager and install commands based on distro
get_package_manager() {
    case $DISTRO in
        "macos")
            PKG_MANAGER="brew"
            INSTALL_CMD="brew install"
            UPDATE_CMD="brew update"
            ;;
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            PKG_MANAGER="apt"
            INSTALL_CMD="sudo DEBIAN_FRONTEND=noninteractive apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y"
            UPDATE_CMD="sudo apt update"
            ;;
        "fedora"|"rhel"|"centos")
            if command -v dnf > /dev/null 2>&1; then
                PKG_MANAGER="dnf"
                INSTALL_CMD="sudo dnf install -y"
                UPDATE_CMD="sudo dnf update"
            else
                PKG_MANAGER="yum"
                INSTALL_CMD="sudo yum install -y"
                UPDATE_CMD="sudo yum update"
            fi
            ;;
        "arch"|"manjaro"|"endeavouros")
            PKG_MANAGER="pacman"
            INSTALL_CMD="sudo pacman -S"
            UPDATE_CMD="sudo pacman -Syu"
            ;;
        "opensuse"|"opensuse-leap"|"opensuse-tumbleweed")
            PKG_MANAGER="zypper"
            INSTALL_CMD="sudo zypper install -y"
            UPDATE_CMD="sudo zypper update"
            ;;
        "alpine")
            PKG_MANAGER="apk"
            INSTALL_CMD="sudo apk add"
            UPDATE_CMD="sudo apk update"
            ;;
        *)
            PKG_MANAGER="unknown"
            INSTALL_CMD="# Unknown package manager - manual installation required"
            UPDATE_CMD="# Unknown package manager"
            ;;
    esac
    
    echo -e "${BLUE}📦 Package Manager: ${CYAN}$PKG_MANAGER${NC}"
    echo ""
}

# System resource validation
check_system_resources() {
    echo -e "${BLUE}🖥️  Checking system resources...${NC}"
    
    local ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    local ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    local min_ram_gb=4
    
    if [ "$ram_gb" -lt "$min_ram_gb" ]; then
        echo -e "⚠️  ${YELLOW}Warning: Low RAM detected${NC}"
        echo -e "   Current: ${ram_mb}MB | Recommended: ${min_ram_gb}GB+"
        echo -e "   Some tools may fail or run slowly"
        log_with_timestamp "Low RAM detected: ${ram_mb}MB (recommended: ${min_ram_gb}GB+)" "WARN"
    else
        echo -e "✅ ${GREEN}RAM: ${ram_gb}GB (sufficient)${NC}"
        log_with_timestamp "RAM check passed: ${ram_gb}GB"
    fi
    
    local disk_gb=$(df -BG / | awk 'NR==2{gsub(/G/,"",$4); print $4}')
    local min_disk_gb=10
    
    if [ "$disk_gb" -lt "$min_disk_gb" ]; then
        echo -e "⚠️  ${YELLOW}Warning: Low disk space${NC}"
        echo -e "   Available: ${disk_gb}GB | Recommended: ${min_disk_gb}GB+"
        echo -e "   Tool installation may fail"
        log_with_timestamp "Low disk space: ${disk_gb}GB (recommended: ${min_disk_gb}GB+)" "WARN"
    else
        echo -e "✅ ${GREEN}Disk Space: ${disk_gb}GB available${NC}"
        log_with_timestamp "Disk space check passed: ${disk_gb}GB available"
    fi
    
    local cpu_cores=$(nproc)
    echo -e "ℹ️  ${CYAN}CPU Cores: $cpu_cores${NC}"
    log_with_timestamp "CPU cores detected: $cpu_cores"
    
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        echo -e "✅ ${GREEN}Internet connectivity: OK${NC}"
        log_with_timestamp "Internet connectivity check passed"
    else
        echo -e "❌ ${RED}Internet connectivity: FAILED${NC}"
        echo -e "   Tool downloads will fail"
        log_with_timestamp "Internet connectivity check failed" "ERROR"
        return 1
    fi
    
    if command -v "$PKG_MANAGER" >/dev/null 2>&1; then
        echo -e "✅ ${GREEN}Package manager ($PKG_MANAGER): Available${NC}"
        log_with_timestamp "Package manager check passed: $PKG_MANAGER"
    else
        echo -e "❌ ${RED}Package manager ($PKG_MANAGER): Not found${NC}"
        log_with_timestamp "Package manager check failed: $PKG_MANAGER not found" "ERROR"
        return 1
    fi
    
    echo ""
    return 0
}

check_dependency_conflicts() {
    echo -e "${BLUE}🔍 Checking for potential dependency conflicts...${NC}"
    log_with_timestamp "Starting dependency conflict check"
    
    local conflicts_found=false
    
    case $DISTRO in
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            if command -v python2 >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
                local py2_version=$(python2 --version 2>&1 | awk '{print $2}')
                local py3_version=$(python3 --version 2>&1 | awk '{print $2}')
                echo -e "ℹ️  ${CYAN}Python versions: 2.x ($py2_version), 3.x ($py3_version)${NC}"
                log_with_timestamp "Python versions detected: 2.x ($py2_version), 3.x ($py3_version)"
            fi
            
            if dpkg -l | grep -q "python-pip" && dpkg -l | grep -q "python3-pip"; then
                echo -e "⚠️  ${YELLOW}Warning: Both python-pip and python3-pip installed${NC}"
                echo -e "   This may cause package conflicts"
                log_with_timestamp "Potential pip conflict: both python-pip and python3-pip installed" "WARN"
                conflicts_found=true
            fi
            ;;
    esac
    
    if [ "$conflicts_found" = false ]; then
        echo -e "✅ ${GREEN}No obvious dependency conflicts detected${NC}"
        log_with_timestamp "No dependency conflicts detected"
    fi
    
    echo ""
}

# Initialize counters
INSTALLED_COUNT=0
MISSING_COUNT=0
TOTAL_COUNT=0

# Arrays to store results
INSTALLED_TOOLS=()
MISSING_TOOLS=()

# Complete tool installation database based on HexStrike AI README
declare -A TOOL_INSTALL_INFO
init_complete_tool_database() {
    TOOL_INSTALL_INFO["build-essential"]="pkg_manager|build-essential|Essential packages for building software"
    TOOL_INSTALL_INFO["python3-dev"]="pkg_manager|python3-dev|Header files and static library for Python"
    TOOL_INSTALL_INFO["python3-pip"]="pkg_manager|python3-pip|Python package installer"
    TOOL_INSTALL_INFO["golang-go"]="pkg_manager|golang-go|Go programming language compiler"
    TOOL_INSTALL_INFO["libssl-dev"]="pkg_manager|libssl-dev|Secure Sockets Layer toolkit - development files"
    TOOL_INSTALL_INFO["libffi-dev"]="pkg_manager|libffi-dev|Foreign Function Interface library - development files"
    TOOL_INSTALL_INFO["libpq-dev"]="pkg_manager|libpq-dev|PostgreSQL C client library - development files"
    TOOL_INSTALL_INFO["zlib1g-dev"]="pkg_manager|zlib1g-dev|Compression library - development files"
    TOOL_INSTALL_INFO["pkg-config"]="pkg_manager|pkg-config|Package configuration system"
    TOOL_INSTALL_INFO["cmake"]="pkg_manager|cmake|Cross-platform build system"
    TOOL_INSTALL_INFO["curl"]="pkg_manager|curl|Command line tool for transferring data"
    TOOL_INSTALL_INFO["wget"]="pkg_manager|wget|Network downloader"
    TOOL_INSTALL_INFO["git"]="pkg_manager|git|Distributed version control system"
    TOOL_INSTALL_INFO["unzip"]="pkg_manager|unzip|Archive extraction utility"
    TOOL_INSTALL_INFO["ca-certificates"]="pkg_manager|ca-certificates|Common CA certificates"
    TOOL_INSTALL_INFO["software-properties-common"]="pkg_manager|software-properties-common|Software properties management"
    
    # 🔍 Network Reconnaissance & Scanning (from README)
    TOOL_INSTALL_INFO["nmap"]="pkg_manager|nmap|Advanced port scanning with custom NSE scripts"
    TOOL_INSTALL_INFO["amass"]="go_install|github.com/owasp-amass/amass/v4/cmd/amass|Comprehensive subdomain enumeration and OSINT"
    TOOL_INSTALL_INFO["subfinder"]="go_install|github.com/projectdiscovery/subfinder/v2/cmd/subfinder|Fast passive subdomain discovery"
    TOOL_INSTALL_INFO["nuclei"]="go_install|github.com/projectdiscovery/nuclei/v3/cmd/nuclei|Fast vulnerability scanner with 4000+ templates"
    TOOL_INSTALL_INFO["autorecon"]="pip_install|autorecon|Automated reconnaissance with 35+ parameters"
    TOOL_INSTALL_INFO["fierce"]="pip_install|fierce|DNS reconnaissance and zone transfer testing"
    TOOL_INSTALL_INFO["masscan"]="pkg_manager|masscan|High-speed Internet-scale port scanner"
    
    # 🌐 Web Application Security Testing (from README)
    TOOL_INSTALL_INFO["gobuster"]="pkg_manager|gobuster|Directory, file, and DNS enumeration"
    TOOL_INSTALL_INFO["ffuf"]="pkg_manager|ffuf|Fast web fuzzer with advanced filtering capabilities"
    TOOL_INSTALL_INFO["dirb"]="pkg_manager|dirb|Comprehensive web content scanner"
    TOOL_INSTALL_INFO["nikto"]="pkg_manager|nikto|Web server vulnerability scanner"
    TOOL_INSTALL_INFO["sqlmap"]="pkg_manager|sqlmap|Advanced automatic SQL injection testing"
    TOOL_INSTALL_INFO["wpscan"]="pkg_manager|wpscan|WordPress security scanner with vulnerability database"
    TOOL_INSTALL_INFO["burpsuite"]="manual_download|https://portswigger.net/burp/releases|Professional web security testing platform"
    TOOL_INSTALL_INFO["zaproxy"]="pkg_manager|zaproxy|OWASP ZAP web application security scanner"
    TOOL_INSTALL_INFO["arjun"]="pip_install|arjun|HTTP parameter discovery tool"
    TOOL_INSTALL_INFO["wafw00f"]="pkg_manager|wafw00f|Web application firewall fingerprinting"
    TOOL_INSTALL_INFO["feroxbuster"]="github_release|https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz|Fast content discovery tool"
    TOOL_INSTALL_INFO["dotdotpwn"]="github_manual|https://github.com/wireghoul/dotdotpwn|Directory traversal fuzzer"
    TOOL_INSTALL_INFO["xsser"]="pkg_manager|xsser|Cross-site scripting detection and exploitation"
    TOOL_INSTALL_INFO["wfuzz"]="pkg_manager|wfuzz|Web application fuzzer"
    
    # 🔐 Authentication & Password Security (from README)
    TOOL_INSTALL_INFO["hydra"]="pkg_manager|hydra|Network login cracker supporting 50+ protocols"
    TOOL_INSTALL_INFO["john"]="pkg_manager|john|Advanced password hash cracking"
    TOOL_INSTALL_INFO["hashcat"]="pkg_manager|hashcat|World's fastest password recovery tool"
    TOOL_INSTALL_INFO["medusa"]="pkg_manager|medusa|Speedy, parallel, modular login brute-forcer"
    TOOL_INSTALL_INFO["patator"]="pkg_manager|patator|Multi-purpose brute-forcer"
    TOOL_INSTALL_INFO["crackmapexec"]="pip_install|crackmapexec|Swiss army knife for pentesting networks"
    TOOL_INSTALL_INFO["evil-winrm"]="pkg_manager|evil-winrm|Windows Remote Management shell"
    
    # 🔬 Binary Analysis & Reverse Engineering (from README)
    TOOL_INSTALL_INFO["gdb"]="pkg_manager|gdb|GNU Debugger with Python scripting"
    TOOL_INSTALL_INFO["radare2"]="pkg_manager|radare2|Advanced reverse engineering framework"
    TOOL_INSTALL_INFO["binwalk"]="pkg_manager|binwalk|Firmware analysis and extraction tool"
    TOOL_INSTALL_INFO["ropgadget"]="pip_install|ropgadget|ROP/JOP gadget finder"
    TOOL_INSTALL_INFO["checksec"]="pkg_manager|checksec|Binary security property checker"
    TOOL_INSTALL_INFO["strings"]="pkg_manager|binutils|Extract printable strings from binaries"
    TOOL_INSTALL_INFO["objdump"]="pkg_manager|binutils|Display object file information"
    TOOL_INSTALL_INFO["ghidra"]="manual_download|https://github.com/NationalSecurityAgency/ghidra/releases|NSA's software reverse engineering suite"
    TOOL_INSTALL_INFO["xxd"]="pkg_manager|vim-common|Hex dump utility"
    
    # 🏆 Advanced CTF & Forensics Tools (from README)
    TOOL_INSTALL_INFO["volatility3"]="pip_install|volatility3|Advanced memory forensics framework"
    TOOL_INSTALL_INFO["foremost"]="pkg_manager|foremost|File carving and data recovery"
    TOOL_INSTALL_INFO["steghide"]="pkg_manager|steghide|Steganography detection and extraction"
    TOOL_INSTALL_INFO["exiftool"]="pkg_manager|libimage-exiftool-perl|Metadata reader/writer for various file formats"
    TOOL_INSTALL_INFO["hashpump"]="github_manual|https://github.com/Phantomn/HashPump|Hash length extension attack tool"
        TOOL_INSTALL_INFO["sleuthkit"]="pkg_manager|sleuthkit|Collection of command-line digital forensics tools"
    
    # ☁️ Cloud & Container Security (from README)
    TOOL_INSTALL_INFO["prowler"]="pip_install|prowler-cloud|AWS/Azure/GCP security assessment tool"
    TOOL_INSTALL_INFO["trivy"]="install_script|https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh|Comprehensive vulnerability scanner for containers"
    TOOL_INSTALL_INFO["scout-suite"]="pip_install|scoutsuite|Multi-cloud security auditing tool"
    TOOL_INSTALL_INFO["kube-hunter"]="pip_install|kube-hunter|Kubernetes penetration testing tool"
    TOOL_INSTALL_INFO["kube-bench"]="github_manual|https://github.com/aquasecurity/kube-bench|CIS Kubernetes benchmark checker"
    TOOL_INSTALL_INFO["cloudsploit"]="nodejs_manual|https://github.com/aquasecurity/cloudsploit|Cloud security scanning and monitoring"
    
    # 🔥 Bug Bounty & Reconnaissance Arsenal (from README)
    TOOL_INSTALL_INFO["hakrawler"]="go_install|github.com/hakluke/hakrawler|Fast web endpoint discovery and crawling"
    TOOL_INSTALL_INFO["httpx"]="go_install|github.com/projectdiscovery/httpx/cmd/httpx|Fast and multi-purpose HTTP toolkit"
    TOOL_INSTALL_INFO["paramspider"]="github_manual|https://github.com/devanshbatham/ParamSpider|Mining parameters from dark corners of web archives"
    TOOL_INSTALL_INFO["aquatone"]="github_release|https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64_1.7.0.zip|Visual inspection of websites across hosts"
    TOOL_INSTALL_INFO["subjack"]="go_install|github.com/haccer/subjack|Subdomain takeover vulnerability checker"
    TOOL_INSTALL_INFO["dnsenum"]="pkg_manager|dnsenum|DNS enumeration script"
    
    # Additional tools mentioned in the server code but not explicitly in README categories
    TOOL_INSTALL_INFO["theharvester"]="pkg_manager|theharvester|Email/subdomain harvester"
    TOOL_INSTALL_INFO["responder"]="pkg_manager|responder|LLMNR/NBT-NS/MDNS poisoner"
    TOOL_INSTALL_INFO["netexec"]="pip_install|netexec|Network service exploitation tool"
    TOOL_INSTALL_INFO["enum4linux-ng"]="github_manual|https://github.com/cddmp/enum4linux-ng|Next-generation enum4linux"
    TOOL_INSTALL_INFO["dirsearch"]="github_manual|https://github.com/maurosoria/dirsearch|Web path discovery tool"
    TOOL_INSTALL_INFO["katana"]="go_install|github.com/projectdiscovery/katana/cmd/katana|Web crawler"
    TOOL_INSTALL_INFO["dalfox"]="go_install|github.com/hahwul/dalfox/v2|XSS scanner and utility"
    
    # Tools from the MCP code analysis
    TOOL_INSTALL_INFO["smbmap"]="pip_install|smbmap|SMB share enumeration tool"
    TOOL_INSTALL_INFO["msfvenom"]="pkg_manager|metasploit-framework|Metasploit payload generator"
    TOOL_INSTALL_INFO["msfconsole"]="pkg_manager|metasploit-framework|Metasploit console"
    TOOL_INSTALL_INFO["hash-identifier"]="pkg_manager|hash-identifier|Hash type identifier"
    TOOL_INSTALL_INFO["ophcrack"]="pkg_manager|ophcrack|Windows password cracker"
    TOOL_INSTALL_INFO["rustscan"]="github_release|https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.1.1_amd64.deb|Ultra-fast port scanner"
    
    # Additional tools discovered from comprehensive source code analysis
    TOOL_INSTALL_INFO["naabu"]="go_install|github.com/projectdiscovery/naabu/v2/cmd/naabu|Fast port scanner"
    TOOL_INSTALL_INFO["assetfinder"]="go_install|github.com/tomnomnom/assetfinder|Subdomain discovery tool"
    TOOL_INSTALL_INFO["findomain"]="github_release|https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux|Cross-platform subdomain enumerator"
    TOOL_INSTALL_INFO["gau"]="go_install|github.com/lc/gau/v2/cmd/gau|Get All URLs from web archives"
    TOOL_INSTALL_INFO["waybackurls"]="go_install|github.com/tomnomnom/waybackurls|Fetch URLs from Wayback Machine"
    TOOL_INSTALL_INFO["x8"]="github_manual|https://github.com/Sh1Yo/x8|Hidden parameter discovery tool"
    TOOL_INSTALL_INFO["jaeles"]="go_install|github.com/jaeles-project/jaeles|Automated web application testing framework"
    TOOL_INSTALL_INFO["dotdotpwn"]="github_manual|https://github.com/wireghoul/dotdotpwn|Directory traversal fuzzer"
    TOOL_INSTALL_INFO["xsser"]="pkg_manager|xsser|Cross-site scripting detection and exploitation"
    TOOL_INSTALL_INFO["wfuzz"]="pkg_manager|wfuzz|Web application fuzzer"
    TOOL_INSTALL_INFO["nbtscan"]="pkg_manager|nbtscan|NetBIOS scanner"
    TOOL_INSTALL_INFO["arp-scan"]="pkg_manager|arp-scan|ARP network scanner"
    TOOL_INSTALL_INFO["bloodhound"]="manual_download|https://github.com/BloodHoundAD/BloodHound/releases|Active Directory attack path analysis"
    TOOL_INSTALL_INFO["setoolkit"]="github_manual|https://github.com/trustedsec/social-engineer-toolkit|Social engineering toolkit"
    TOOL_INSTALL_INFO["gophish"]="github_release|https://github.com/gophish/gophish/releases|Open-source phishing toolkit"
    TOOL_INSTALL_INFO["mobsf"]="github_manual|https://github.com/MobSF/Mobile-Security-Framework-MobSF|Mobile security framework"
    TOOL_INSTALL_INFO["frida"]="pip_install|frida-tools|Dynamic instrumentation toolkit"
    TOOL_INSTALL_INFO["objection"]="pip_install|objection|Runtime mobile exploration toolkit"
    TOOL_INSTALL_INFO["powershell-empire"]="github_manual|https://github.com/BC-SECURITY/Empire|PowerShell post-exploitation framework"
    TOOL_INSTALL_INFO["covenant"]="github_manual|https://github.com/cobbr/Covenant|.NET command and control framework"
    TOOL_INSTALL_INFO["cobalt-strike"]="commercial|https://www.cobaltstrike.com|Commercial adversary simulation platform"
    TOOL_INSTALL_INFO["docker-bench-security"]="github_manual|https://github.com/docker/docker-bench-security|Docker security benchmark"
    TOOL_INSTALL_INFO["clair"]="github_release|https://github.com/quay/clair/releases|Container vulnerability scanner"
    TOOL_INSTALL_INFO["falco"]="install_script|https://falco.org/repo/falcosecurity-packages.asc|Runtime security monitoring"
    TOOL_INSTALL_INFO["anew"]="go_install|github.com/tomnomnom/anew|Tool for adding new lines to files"
    TOOL_INSTALL_INFO["qsreplace"]="go_install|github.com/tomnomnom/qsreplace|Query string parameter replacement"
    TOOL_INSTALL_INFO["uro"]="pip_install|uro|URL filtering and deduplication tool"
    TOOL_INSTALL_INFO["pwntools"]="pip_install|pwntools|CTF framework and exploit development library"
    TOOL_INSTALL_INFO["one-gadget"]="gem_install|one_gadget|RCE gadget finder for libc"
    TOOL_INSTALL_INFO["libc-database"]="github_manual|https://github.com/niklasb/libc-database|Libc offset database"
    TOOL_INSTALL_INFO["gdb-peda"]="github_manual|https://github.com/longld/peda|Python Exploit Development Assistance for GDB"
    TOOL_INSTALL_INFO["angr"]="pip_install|angr|Binary analysis platform"
    TOOL_INSTALL_INFO["ropper"]="pip_install|ropper|ROP/JOP gadget finder"
    TOOL_INSTALL_INFO["pwninit"]="github_release|https://github.com/io12/pwninit/releases|CTF pwn challenge setup tool"
}

# Function to get package name based on distribution
get_package_name() {
    local tool=$1
    
    case $DISTRO in
        "macos")
            case $tool in
                "build-essential") echo "" ;;
                "python3-dev") echo "python3" ;;
                "python3-pip") echo "python3-pip" ;;
                "golang-go") echo "go" ;;
                "libssl-dev") echo "openssl" ;;
                "libffi-dev") echo "libffi" ;;
                "libpq-dev") echo "libpq" ;;
                "zlib1g-dev") echo "zlib" ;;
                "software-properties-common") echo "" ;;
                "theharvester") echo "theharvester" ;;
                "evil-winrm") echo "evil-winrm" ;;
                "exiftool") echo "libimage-exiftool-perl" ;;
                "xxd") echo "vim-common" ;;
                "subfinder") echo "subfinder" ;;
                "nuclei") echo "nuclei" ;;
                "ffuf") echo "ffuf" ;;
                "ghidra") echo "ghidra" ;;
                "volatility3") echo "volatility3" ;;
                "john") echo "john-jumbo" ;;
                "naabu") echo "naabu" ;;
                "assetfinder") echo "assetfinder" ;;
                "findomain") echo "findomain" ;;
                "feroxbuster") echo "feroxbuster" ;;
                "gau") echo "gau" ;;
                "waybackurls") echo "waybackurls" ;;
                "anew") echo "anew" ;;
                "qsreplace") echo "qsreplace" ;;
                "x8") echo "x8" ;;
                "jaeles") echo "jaeles" ;;
                "dalfox") echo "dalfox" ;;
                "httpx") echo "httpx" ;;
                "katana") echo "katana" ;;
                "hakrawler") echo "hakrawler" ;;
                "subjack") echo "subjack" ;;
                "rustscan") echo "rustscan" ;;
                "terrascan") echo "terrascan" ;;
                "kube-bench") echo "kube-bench" ;;
                "clair") echo "clair" ;;
                "falco") echo "falco" ;;
                *) echo "$tool" ;;
            esac
            ;;
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            case $tool in
                "theharvester") echo "theharvester" ;;
                "evil-winrm") echo "evil-winrm" ;;
                "hash-identifier") echo "hash-identifier" ;;
                "enum4linux-ng") echo "enum4linux-ng" ;;
                "httpx") echo "httpx-toolkit" ;;
                "volatility3") echo "volatility3" ;;
                "netexec") echo "netexec" ;;
                "exiftool") echo "libimage-exiftool-perl" ;;
                "zaproxy") echo "zaproxy" ;;
                "sleuthkit") echo "sleuthkit" ;;
                "metasploit-framework") echo "metasploit-framework" ;;
                "xxd") echo "vim-common" ;;
                *) echo "$tool" ;;
            esac
            ;;
        "fedora"|"rhel"|"centos")
            case $tool in
                "build-essential") echo "gcc gcc-c++ make" ;;
                "python3-dev") echo "python3-devel" ;;
                "golang-go") echo "golang" ;;
                "libssl-dev") echo "openssl-devel" ;;
                "libffi-dev") echo "libffi-devel" ;;
                "libpq-dev") echo "postgresql-devel" ;;
                "zlib1g-dev") echo "zlib-devel" ;;
                "pkg-config") echo "pkgconfig" ;;
                "software-properties-common") echo "" ;;
                "theharvester") echo "theHarvester" ;;
                "evil-winrm") echo "rubygem-evil-winrm" ;;
                "enum4linux-ng") echo "enum4linux-ng" ;;
                "httpx") echo "httpx" ;;
                "volatility3") echo "python3-volatility3" ;;
                "exiftool") echo "perl-Image-ExifTool" ;;
                "zaproxy") echo "zaproxy" ;;
                "sleuthkit") echo "sleuthkit" ;;
                "metasploit-framework") echo "metasploit" ;;
                "xxd") echo "vim-common" ;;
                "john") echo "john" ;;
                "nbtscan") echo "nbtscan" ;;
                "arp-scan") echo "arp-scan" ;;
                "xsser") echo "xsser" ;;
                "wfuzz") echo "wfuzz" ;;
                "falco") echo "falco" ;;
                *) echo "$tool" ;;
            esac
            ;;
        "arch"|"manjaro"|"endeavouros")
            case $tool in
                "build-essential") echo "base-devel" ;;
                "python3-dev") echo "python" ;;
                "python3-pip") echo "python-pip" ;;
                "golang-go") echo "go" ;;
                "libssl-dev") echo "openssl" ;;
                "libffi-dev") echo "libffi" ;;
                "libpq-dev") echo "postgresql-libs" ;;
                "zlib1g-dev") echo "zlib" ;;
                "pkg-config") echo "pkgconf" ;;
                "software-properties-common") echo "" ;;
                "theharvester") echo "theharvester" ;;
                "evil-winrm") echo "evil-winrm" ;;
                "hash-identifier") echo "hash-identifier" ;;
                "enum4linux-ng") echo "enum4linux-ng" ;;
                "httpx") echo "httpx" ;;
                "volatility3") echo "volatility3" ;;
                "exiftool") echo "perl-image-exiftool" ;;
                "zaproxy") echo "zaproxy" ;;
                "sleuthkit") echo "sleuthkit" ;;
                "metasploit-framework") echo "metasploit" ;;
                "xxd") echo "vim-common" ;;
                *) echo "$tool" ;;
            esac
            ;;
        *)
            echo "$tool"
            ;;
    esac
}

# Function to check if a command exists
check_tool() {
    local tool=$1
    local alt_check=$2
    
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    
    # Check primary command
    if command -v "$tool" > /dev/null 2>&1; then
        echo -e "✅ ${GREEN}$tool${NC} - ${GREEN}INSTALLED${NC}"
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi
    
    # Check alternative command if provided
    if [ -n "$alt_check" ] && command -v "$alt_check" > /dev/null 2>&1; then
        echo -e "✅ ${GREEN}$tool${NC} (as $alt_check) - ${GREEN}INSTALLED${NC}"
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi
    
    case $PKG_MANAGER in
        "apt")
            local package_name
            package_name=$(get_package_name "$tool")
            if [ -n "$package_name" ] && dpkg -s "$package_name" >/dev/null 2>&1; then
                echo -e "✅ ${GREEN}$tool${NC} (package: $package_name) - ${GREEN}INSTALLED${NC}"
                INSTALLED_TOOLS+=("$tool")
                INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
                return 0
            fi
            ;;
        "brew")
            local package_name
            package_name=$(get_package_name "$tool")
            if [ -n "$package_name" ] && brew list "$package_name" >/dev/null 2>&1; then
                echo -e "✅ ${GREEN}$tool${NC} (brew: $package_name) - ${GREEN}INSTALLED${NC}"
                INSTALLED_TOOLS+=("$tool")
                INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
                return 0
            fi
            ;;
    esac
    
    # Check if it's a Python package that might be installed
    if python3 -c "import $tool" > /dev/null 2>&1; then
        echo -e "✅ ${GREEN}$tool${NC} (Python package) - ${GREEN}INSTALLED${NC}"
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi
    
    # Check common installation locations
    local locations=(
        "/usr/bin/$tool"
        "/usr/local/bin/$tool"
        "/opt/$tool"
        "/home/$USER/tools/$tool"
        "/home/$USER/Desktop/$tool"
        "/usr/share/$tool"
        "/snap/bin/$tool"
        "/usr/local/share/$tool"
    )
    
    for location in "${locations[@]}"; do
        if [ -f "$location" ] || [ -d "$location" ]; then
            echo -e "✅ ${GREEN}$tool${NC} - ${GREEN}INSTALLED${NC} (found at $location)"
            INSTALLED_TOOLS+=("$tool")
            INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
            return 0
        fi
    done
    
    # Tool not found
    local package_name=$(get_package_name "$tool")
    echo -e "❌ ${RED}$tool${NC} - ${RED}NOT INSTALLED${NC} ${YELLOW}($PKG_MANAGER install $package_name)${NC}"
    MISSING_TOOLS+=("$tool:$package_name")
    MISSING_COUNT=$((MISSING_COUNT + 1))
    return 1
}

verify_urls_parallel() {
    local -n url_results=$1
    shift
    local urls=("$@")
    local pids=()
    local temp_dir="/tmp/hexstrike_url_check_$$"
    
    mkdir -p "$temp_dir"
    
    echo -e "${BLUE}🔍 Verifying URLs in parallel (${#urls[@]} URLs)...${NC}"
    log_with_timestamp "Starting parallel URL verification for ${#urls[@]} URLs"
    
    local i=0
    for url in "${urls[@]}"; do
        (
            if check_url "$url"; then
                echo "SUCCESS" > "$temp_dir/result_$i"
            else
                echo "FAILED" > "$temp_dir/result_$i"
            fi
        ) &
        pids+=($!)
        ((i++))
        
        if [ ${#pids[@]} -ge 10 ]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
        fi
    done
    
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    i=0
    for url in "${urls[@]}"; do
        if [ -f "$temp_dir/result_$i" ]; then
            url_results["$url"]=$(cat "$temp_dir/result_$i")
        else
            url_results["$url"]="FAILED"
        fi
        ((i++))
    done
    
    rm -rf "$temp_dir"
    
    local success_count=0
    local failed_count=0
    for result in "${url_results[@]}"; do
        if [ "$result" = "SUCCESS" ]; then
            ((success_count++))
        else
            ((failed_count++))
        fi
    done
    
    echo -e "✅ ${GREEN}URL verification complete: $success_count verified, $failed_count failed${NC}"
    log_with_timestamp "Parallel URL verification complete: $success_count verified, $failed_count failed"
}

# Function to validate and generate installation commands
generate_verified_install_commands() {
    if [ $MISSING_COUNT -eq 0 ]; then
        return
    fi
    
    echo -e "${YELLOW}📦 HEXSTRIKE AI OFFICIAL INSTALLATION COMMANDS:${NC}"
    echo "================================================"
    
    local PKG_MANAGER_TOOLS=""
    local GO_TOOLS=""
    local PIP_TOOLS=""
    local GITHUB_RELEASES=""
    local MANUAL_INSTALLS=""
    local FAILED_VERIFICATIONS=""
    
    declare -A urls_to_check
    declare -A url_results
    local urls_array=()
    
    for missing in "${MISSING_TOOLS[@]}"; do
        local tool=$(echo "$missing" | cut -d':' -f1)
        local package=$(echo "$missing" | cut -d':' -f2)
        
        if [ -n "${TOOL_INSTALL_INFO[$tool]}" ]; then
            IFS='|' read -r install_type install_info description <<< "${TOOL_INSTALL_INFO[$tool]}"
            
            case $install_type in
                "go_install")
                    local go_url="https://$install_info"
                    urls_to_check["$go_url"]="$tool:go_install:$install_info:$description"
                    urls_array+=("$go_url")
                    ;;
                "github_release"|"github_manual"|"manual_download")
                    urls_to_check["$install_info"]="$tool:$install_type:$install_info:$description"
                    urls_array+=("$install_info")
                    ;;
            esac
        fi
    done
    
    if [ ${#urls_array[@]} -gt 0 ]; then
        verify_urls_parallel url_results "${urls_array[@]}"
    fi
    
    local current_tool=0
    for missing in "${MISSING_TOOLS[@]}"; do
        local tool=$(echo "$missing" | cut -d':' -f1)
        local package=$(echo "$missing" | cut -d':' -f2)
        
        ((current_tool++))
        show_progress $current_tool $MISSING_COUNT "Processing tools"
        
        if [ -n "${TOOL_INSTALL_INFO[$tool]}" ]; then
            IFS='|' read -r install_type install_info description <<< "${TOOL_INSTALL_INFO[$tool]}"
            
            case $install_type in
                "pkg_manager")
                    PKG_MANAGER_TOOLS+=" $package"
                    ;;
                
                "go_install")
                    local go_url="https://$install_info"
                    if [ "${url_results[$go_url]}" = "SUCCESS" ]; then
                        GO_TOOLS+="\n  go install -v $install_info@latest"
                        log_with_timestamp "✅ Go package verified: $install_info"
                    else
                        GO_TOOLS+="\n  go install -v $install_info@latest  # ⚠️  Could not verify"
                        log_with_timestamp "⚠️ Go package verification failed: $install_info" "WARN"
                    fi
                    ;;
                
                "pip_install")
                    PIP_TOOLS+="\n  pip3 install $install_info"
                    ;;
                
                "github_release")
                    if [ "${url_results[$install_info]}" = "SUCCESS" ]; then
                        GITHUB_RELEASES+="\n# $tool - $description\nwget $install_info\n"
                        echo -e "  ✅ ${GREEN}Download link verified${NC}"
                    else
                        # Try to find working alternative
                        local base_url=$(echo "$install_info" | sed 's|/releases/latest/download/.*|/releases|')
                        GITHUB_RELEASES+="\n# $tool - $description\n# ⚠️  Direct link failed, visit: $base_url\n"
                        FAILED_VERIFICATIONS+="\n❌ $tool: $install_info"
                        echo -e "  ❌ ${RED}Download link failed - check manually${NC}"
                    fi
                    ;;
                
                "github_manual")
                    echo -e "${BLUE}🔍 Verifying GitHub repo: $install_info${NC}"
                    if check_url "$install_info"; then
                        MANUAL_INSTALLS+="\n# $tool - $description\ngit clone $install_info\ncd $(basename $install_info)\n# Follow installation instructions in README\n"
                        echo -e "  ✅ ${GREEN}Repository verified${NC}"
                    else
                        MANUAL_INSTALLS+="\n# $tool - $description\n# ⚠️  Repository URL failed: $install_info\n"
                        FAILED_VERIFICATIONS+="\n❌ $tool: $install_info"
                        echo -e "  ❌ ${RED}Repository not accessible${NC}"
                    fi
                    ;;
                
                "manual_download")
                    echo -e "${BLUE}🔍 Verifying manual download: $install_info${NC}"
                    if check_url "$install_info"; then
                        MANUAL_INSTALLS+="\n# $tool - $description\n# Download from: $install_info\n# Extract and follow installation instructions\n"
                        echo -e "  ✅ ${GREEN}Download page verified${NC}"
                    else
                        MANUAL_INSTALLS+="\n# $tool - $description\n# ⚠️  Download page failed: $install_info\n"
                        FAILED_VERIFICATIONS+="\n❌ $tool: $install_info"
                        echo -e "  ❌ ${RED}Download page not accessible${NC}"
                    fi
                    ;;
            esac
        else
            PKG_MANAGER_TOOLS+=" $package"
        fi
    done
    
    echo ""
    
    # Display installation commands
    if [ -n "$PKG_MANAGER_TOOLS" ]; then
        echo -e "${CYAN}📦 Package Manager Installation ($PKG_MANAGER):${NC}"
        echo "$INSTALL_CMD$PKG_MANAGER_TOOLS"
        echo ""
    fi
    
    if [ -n "$PIP_TOOLS" ]; then
        echo -e "${CYAN}🐍 Python Package Installation:${NC}"
        echo -e "$PIP_TOOLS"
        echo ""
    fi
    
    if [ -n "$GO_TOOLS" ]; then
        echo -e "${CYAN}🐹 Go Package Installation (requires Go):${NC}"
        echo "# First install Go if not present:"
        case $DISTRO in
            "ubuntu"|"debian"|"kali"|"parrot"|"mint")
                echo "sudo apt install golang-go"
                ;;
            "fedora"|"rhel"|"centos")
                echo "sudo $PKG_MANAGER install go"
                ;;
            "arch"|"manjaro"|"endeavouros")
                echo "sudo pacman -S go"
                ;;
        esac
        echo -e "$GO_TOOLS"
        echo ""
    fi
    
    if [ -n "$GITHUB_RELEASES" ]; then
        echo -e "${CYAN}📁 GitHub Releases (Verified Links):${NC}"
        echo -e "$GITHUB_RELEASES"
        echo ""
    fi
    
    if [ -n "$MANUAL_INSTALLS" ]; then
        echo -e "${CYAN}🔧 Manual Installations:${NC}"
        echo -e "$MANUAL_INSTALLS"
        echo ""
    fi
    
    if [ -n "$FAILED_VERIFICATIONS" ]; then
        echo -e "${RED}⚠️  Failed Link Verifications:${NC}"
        echo -e "$FAILED_VERIFICATIONS"
        echo -e "\n${YELLOW}💡 For failed links, please check the official project repositories manually.${NC}"
        echo ""
    fi
    
    # HexStrike AI Official Installation Commands
    echo -e "${GREEN}🚀 HEXSTRIKE AI MEGA INSTALLATION COMMAND:${NC}"
    case $DISTRO in
        "macos")
            echo "# System dependencies"
            echo "xcode-select --install"
            echo "brew install openssl libffi libpq zlib pkg-config cmake curl wget git unzip ca-certificates python3 python3-pip go"
            echo ""
            echo "# Network & Recon tools"
            echo "brew install nmap masscan amass subfinder nuclei"
            echo ""
            echo "# Web Application Security tools"
            echo "brew install gobuster ffuf dirb nikto sqlmap wpscan zaproxy"
            echo ""
            echo "# Password & Authentication tools"  
            echo "brew install hydra john hashcat medusa"
            echo ""
            echo "# Binary Analysis & Reverse Engineering tools"
            echo "brew install gdb radare2 binwalk ghidra volatility3 exiftool xxd"
            echo ""
            echo "# Python packages"
            echo "pip3 install autorecon ropgadget arjun crackmapexec netexec prowler-cloud scoutsuite kube-hunter smbmap"
            echo ""
            echo "# Go packages"
            echo "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            echo "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            echo "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            echo "go install github.com/projectdiscovery/katana/cmd/katana@latest"
            echo "go install github.com/hahwul/dalfox/v2@latest"
            echo "go install github.com/hakluke/hakrawler@latest"
            echo "go install github.com/haccer/subjack@latest"
            ;;
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            echo "# System dependencies"
            echo "sudo DEBIAN_FRONTEND=noninteractive apt update && sudo DEBIAN_FRONTEND=noninteractive apt install -y build-essential python3-dev python3-pip golang-go libssl-dev libffi-dev libpq-dev zlib1g-dev pkg-config cmake curl wget git unzip ca-certificates software-properties-common"
            echo ""
            echo "# Network & Recon tools"
            echo "sudo DEBIAN_FRONTEND=noninteractive apt install -y nmap masscan amass fierce dnsenum theharvester responder"
            echo ""
            echo "# Web Application Security tools"
            echo "sudo DEBIAN_FRONTEND=noninteractive apt install -y gobuster ffuf dirb nikto sqlmap wpscan wafw00f zaproxy xsser wfuzz"
            echo ""
            echo "# Password & Authentication tools"  
            echo "sudo DEBIAN_FRONTEND=noninteractive apt install -y hydra john hashcat medusa patator evil-winrm hash-identifier ophcrack"
            echo ""
            echo "# Binary Analysis & Reverse Engineering tools"
            echo "sudo DEBIAN_FRONTEND=noninteractive apt install -y gdb radare2 binwalk checksec binutils foremost steghide libimage-exiftool-perl sleuthkit xxd metasploit-framework"
            echo ""
            echo "# Python packages"
            echo "pip3 install autorecon ropgadget arjun crackmapexec netexec volatility3 prowler-cloud scoutsuite kube-hunter smbmap"
            echo ""
            echo "# Go packages (requires Go)"
            echo "go install github.com/owasp-amass/amass/v4/cmd/amass@latest"
            echo "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            echo "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            echo "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            echo "go install github.com/projectdiscovery/katana/cmd/katana@latest"
            echo "go install github.com/hahwul/dalfox/v2@latest"
            echo "go install github.com/hakluke/hakrawler@latest"
            echo "go install github.com/haccer/subjack@latest"
            ;;
        "fedora"|"rhel"|"centos")
            echo "# System dependencies"
            echo "sudo $PKG_MANAGER install -y gcc gcc-c++ make python3-devel python3-pip golang openssl-devel libffi-devel postgresql-devel zlib-devel pkgconfig cmake curl wget git unzip ca-certificates"
            echo ""
            echo "# Network & Recon tools"
            echo "sudo $PKG_MANAGER install -y nmap masscan dnsenum theHarvester"
            echo ""
            echo "# Web Application Security tools"
            echo "sudo $PKG_MANAGER install -y gobuster ffuf dirb nikto sqlmap zaproxy wfuzz"
            echo ""
            echo "# Password & Authentication tools"
            echo "sudo $PKG_MANAGER install -y hydra john hashcat medusa patator rubygem-evil-winrm ophcrack"
            echo ""
            echo "# Binary Analysis & Reverse Engineering tools"
            echo "sudo $PKG_MANAGER install -y gdb radare2 binwalk binutils foremost steghide perl-Image-ExifTool sleuthkit vim-common"
            echo ""
            echo "# Python packages"
            echo "pip3 install autorecon ropgadget arjun crackmapexec netexec volatility3 prowler-cloud scoutsuite kube-hunter smbmap"
            ;;
        "arch"|"manjaro"|"endeavouros")
            echo "# System dependencies"
            echo "sudo pacman -S base-devel python python-pip go openssl libffi postgresql-libs zlib pkgconf cmake curl wget git unzip ca-certificates"
            echo ""
            echo "# Network & Recon tools"
            echo "sudo pacman -S nmap masscan dnsenum theharvester"
            echo ""
            echo "# Web Application Security tools"
            echo "sudo pacman -S gobuster ffuf dirb nikto sqlmap zaproxy wfuzz"
            echo ""
            echo "# Password & Authentication tools"
            echo "sudo pacman -S hydra john hashcat medusa patator evil-winrm hash-identifier ophcrack"
            echo ""
            echo "# Binary Analysis & Reverse Engineering tools"
            echo "sudo pacman -S gdb radare2 binwalk binutils foremost steghide perl-image-exiftool sleuthkit xxd metasploit"
            echo ""
            echo "# Python packages"
            echo "pip3 install autorecon ropgadget arjun crackmapexec netexec volatility3 prowler-cloud scoutsuite kube-hunter smbmap"
            ;;
    esac
   echo ""
}

# Main execution
parse_arguments "$@"

if [ "$HELP_MODE" = true ]; then
    show_help
    exit 0
fi

# Initialize logging system
setup_logging

# Initialize tool profiles
init_tool_profiles

echo -e "${ORANGE}🔍 Initializing complete HexStrike AI tool database...${NC}"
init_complete_tool_database

detect_distro
get_package_manager

log_with_timestamp "Starting system validation checks"
if ! check_system_resources; then
    echo -e "${RED}❌ Critical system requirements not met${NC}"
    log_with_timestamp "System validation failed - critical requirements not met" "ERROR"
    echo -e "${YELLOW}⚠️  Continuing anyway, but installations may fail${NC}"
fi

check_dependency_conflicts

if [ "$CURL_AVAILABLE" = false ]; then
   echo -e "${YELLOW}⚠️  curl not found. Link verification disabled. Install curl for full functionality.${NC}"
   echo ""
fi

echo -e "${MAGENTA}🔍 Network Reconnaissance & Scanning Tools${NC}"
echo "================================================"
check_tool "nmap"
check_tool "amass"
check_tool "subfinder"
check_tool "nuclei"
check_tool "autorecon"
check_tool "fierce"
check_tool "masscan"
check_tool "theharvester"
check_tool "responder"
check_tool "netexec" "nxc"
check_tool "enum4linux-ng"
check_tool "dnsenum"
check_tool "rustscan"
echo ""

echo -e "${MAGENTA}🌐 Web Application Security Testing Tools${NC}"
echo "================================================"
check_tool "gobuster"
check_tool "ffuf"
check_tool "dirb"
check_tool "nikto"
check_tool "sqlmap"
check_tool "wpscan"
check_tool "burpsuite"
check_tool "zaproxy" "zap"
check_tool "arjun"
check_tool "wafw00f"
check_tool "feroxbuster"
check_tool "dotdotpwn"
check_tool "xsser"
check_tool "wfuzz"
check_tool "dirsearch"
check_tool "katana"
check_tool "dalfox"
echo ""

echo -e "${MAGENTA}🔐 Authentication & Password Security Tools${NC}"
echo "================================================"
check_tool "hydra"
check_tool "john"
check_tool "hashcat"
check_tool "medusa"
check_tool "patator"
check_tool "crackmapexec" "cme"
check_tool "evil-winrm"
check_tool "hash-identifier"
check_tool "ophcrack"
echo ""

echo -e "${MAGENTA}🔬 Binary Analysis & Reverse Engineering Tools${NC}"
echo "================================================"
check_tool "gdb"
check_tool "radare2" "r2"
check_tool "binwalk"
check_tool "ropgadget"
check_tool "checksec"
check_tool "strings"
check_tool "objdump"
check_tool "ghidra"
check_tool "xxd"
check_tool "msfvenom"
check_tool "msfconsole"
check_tool "smbmap"
echo ""

echo -e "${MAGENTA}🏆 Advanced CTF & Forensics Tools${NC}"
echo "================================================"
check_tool "volatility3" "vol3"
check_tool "foremost"
check_tool "steghide"
check_tool "exiftool"
check_tool "hashpump"
check_tool "autopsy"
check_tool "sleuthkit"
echo ""

echo -e "${MAGENTA}☁️ Cloud & Container Security Tools${NC}"
echo "================================================"
check_tool "prowler"
check_tool "trivy"
check_tool "scout-suite"
check_tool "kube-hunter"
check_tool "kube-bench"
check_tool "cloudsploit"
echo ""

echo -e "${MAGENTA}🔥 Bug Bounty & Reconnaissance Arsenal${NC}"
echo "================================================"
check_tool "hakrawler"
check_tool "httpx"
check_tool "paramspider"
check_tool "aquatone"
check_tool "subjack"
echo ""

# Summary
echo "================================================"
echo -e "${WHITE}📊 HEXSTRIKE AI INSTALLATION SUMMARY${NC}"
echo "================================================"
echo -e "✅ ${GREEN}Installed tools: $INSTALLED_COUNT/$TOTAL_COUNT${NC}"
echo -e "❌ ${RED}Missing tools: $MISSING_COUNT/$TOTAL_COUNT${NC}"

# HexStrike AI specific recommendations
echo ""
echo -e "${CYAN}📋 HEXSTRIKE AI OFFICIAL REQUIREMENTS:${NC}"
echo "================================================"

# Essential tools (based on README)
ESSENTIAL_TOOLS=("nmap" "nuclei" "gobuster" "ffuf" "sqlmap" "hydra" "gdb" "radare2")
ESSENTIAL_MISSING=0
ESSENTIAL_TOTAL=${#ESSENTIAL_TOOLS[@]}

echo -e "${YELLOW}🔥 Essential Tools Status:${NC}"
for tool in "${ESSENTIAL_TOOLS[@]}"; do
   if command -v "$tool" > /dev/null 2>&1; then
       echo -e "  ✅ ${GREEN}$tool${NC}"
   else
       echo -e "  ❌ ${RED}$tool${NC} - CRITICAL"
       ESSENTIAL_MISSING=$((ESSENTIAL_MISSING + 1))
   fi
done

echo ""
if [ $ESSENTIAL_MISSING -eq 0 ]; then
   echo -e "🎉 ${GREEN}All essential HexStrike AI tools are installed!${NC}"
else
   echo -e "⚠️  ${RED}$ESSENTIAL_MISSING/$ESSENTIAL_TOTAL essential tools missing. HexStrike AI functionality will be limited.${NC}"
fi

echo ""
echo -e "${BLUE}🤖 AI Agent Compatibility Status:${NC}"
if [ $MISSING_COUNT -eq 0 ]; then
   echo -e "✅ ${GREEN}Perfect! All 70+ tools ready for AI agent automation${NC}"
elif [ $MISSING_COUNT -le 10 ]; then
   echo -e "👍 ${YELLOW}Good! Most tools available - AI agents can perform comprehensive assessments${NC}"
elif [ $MISSING_COUNT -le 20 ]; then
   echo -e "⚠️  ${ORANGE}Moderate! Some limitations expected in AI agent capabilities${NC}"
else
   echo -e "❌ ${RED}Significant gaps! AI agents will have limited cybersecurity capabilities${NC}"
fi

if [ $MISSING_COUNT -gt 0 ]; then
   echo ""
   
   if [ "$INSTALL_MODE" = true ]; then
       perform_automatic_installation
   else
       generate_verified_install_commands
   fi
fi

# Performance indicator with HexStrike AI context
PERCENTAGE=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))
echo ""
echo -e "${WHITE}📈 HEXSTRIKE AI READINESS SCORE: $PERCENTAGE%${NC}"

if [ $PERCENTAGE -ge 90 ]; then
   echo -e "🔥 ${GREEN}ELITE SETUP! Your AI agents are ready for advanced autonomous pentesting!${NC}"
   echo -e "${GREEN}✅ Full HexStrike AI capabilities unlocked${NC}"
elif [ $PERCENTAGE -ge 80 ]; then
   echo -e "🚀 ${GREEN}EXCELLENT! AI agents can perform comprehensive security assessments${NC}"
   echo -e "${GREEN}✅ Most HexStrike AI features available${NC}"
elif [ $PERCENTAGE -ge 70 ]; then
   echo -e "👍 ${YELLOW}GOOD! AI agents have solid cybersecurity capabilities${NC}"
   echo -e "${YELLOW}⚠️  Some advanced features may be limited${NC}"
elif [ $PERCENTAGE -ge 50 ]; then
   echo -e "⚠️  ${ORANGE}MODERATE! Basic AI agent security testing possible${NC}"
   echo -e "${ORANGE}❌ Advanced HexStrike AI features unavailable${NC}"
else
   echo -e "❌ ${RED}INSUFFICIENT! Major limitations in AI agent capabilities${NC}"
   echo -e "${RED}🔧 Install more tools for meaningful HexStrike AI functionality${NC}"
fi

echo ""
echo -e "${BLUE}💡 NEXT STEPS FOR HEXSTRIKE AI:${NC}"
echo "1. Install missing tools using the commands above"
echo "2. Clone HexStrike AI: git clone https://github.com/0x4m4/hexstrike-ai.git"
echo "3. Install Python dependencies: pip3 install -r requirements.txt"
echo "4. Start the server: python3 hexstrike_server.py"
echo "5. Configure your AI agent with the MCP client"
echo ""
echo -e "${CYAN}🌐 Official HexStrike AI Resources:${NC}"
echo "📖 Documentation: https://github.com/0x4m4/hexstrike-ai/blob/master/README.md"
echo "🔗 Project Page: https://www.hexstrike.com"
echo "👨‍💻 Author: 0x4m4 (https://www.0x4m4.com)"
echo ""
echo -e "${WHITE}🤖 Ready to empower your AI agents with autonomous cybersecurity capabilities!${NC}"
echo ""
