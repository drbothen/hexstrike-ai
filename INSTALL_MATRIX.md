# HexStrike AI - Installation Matrix

This document provides comprehensive installation information for all security tools supported by HexStrike AI across different operating systems.

## System Dependencies

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Purpose |
|------|----------------------|----------------|-----------------|--------------|---------|
| build-essential | build-essential | xcode-select --install | `sudo apt install -y build-essential` / `xcode-select --install` | `gcc --version` | Essential build tools (gcc, make, etc.) |
| python3-dev | python3-dev | python3 | `sudo apt install -y python3-dev` | `python3-config --includes` | Python development headers |
| python3-pip | python3-pip | python3-pip | `sudo apt install -y python3-pip` | `pip3 --version` | Python package installer |
| golang-go | golang-go | go | `sudo apt install -y golang-go` | `go version` | Go programming language |
| libssl-dev | libssl-dev | openssl | `sudo apt install -y libssl-dev` | `pkg-config --modversion openssl` | SSL/TLS development libraries |
| libffi-dev | libffi-dev | libffi | `sudo apt install -y libffi-dev` | `pkg-config --modversion libffi` | Foreign Function Interface library |
| libpq-dev | libpq-dev | libpq | `sudo apt install -y libpq-dev` | `pg_config --version` | PostgreSQL client library |
| zlib1g-dev | zlib1g-dev | zlib | `sudo apt install -y zlib1g-dev` | `pkg-config --modversion zlib` | Compression library |
| pkg-config | pkg-config | pkg-config | `sudo apt install -y pkg-config` | `pkg-config --version` | Package configuration system |
| cmake | cmake | cmake | `sudo apt install -y cmake` | `cmake --version` | Cross-platform build system |
| curl | curl | curl | `sudo apt install -y curl` | `curl --version` | Data transfer tool |
| wget | wget | wget | `sudo apt install -y wget` | `wget --version` | Network downloader |
| git | git | git | `sudo apt install -y git` | `git --version` | Version control system |
| unzip | unzip | unzip | `sudo apt install -y unzip` | `unzip -v` | Archive extraction utility |
| ca-certificates | ca-certificates | ca-certificates | `sudo apt install -y ca-certificates` | `ls /etc/ssl/certs/` | SSL certificate bundle |

## Network & Reconnaissance Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| nmap | nmap | nmap | `sudo apt install -y nmap` | `nmap --version` | Network discovery and security auditing |
| masscan | masscan | masscan | `sudo apt install -y masscan` | `masscan --version` | High-speed TCP port scanner |
| amass | amass | amass | `sudo apt install -y amass` | `amass --version` | Attack surface mapping and asset discovery |
| subfinder | N/A (Go install) | subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` / `brew install subfinder` | `subfinder -version` | Fast passive subdomain enumeration |
| nuclei | N/A (Go install) | nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` / `brew install nuclei` | `nuclei -version` | Fast vulnerability scanner |
| fierce | fierce | N/A | `sudo apt install -y fierce` | `fierce --version` | Domain scanner for non-contiguous IP space |
| dnsenum | dnsenum | dnsenum | `sudo apt install -y dnsenum` | `dnsenum --version` | DNS information enumeration |
| theharvester | theharvester | theharvester | `sudo apt install -y theharvester` | `theharvester --version` | OSINT email and subdomain harvester |
| responder | responder | N/A | `sudo apt install -y responder` | `responder --version` | LLMNR/NBT-NS/MDNS poisoner |
| rustscan | N/A (GitHub release) | rustscan | Download from GitHub releases | `rustscan --version` | Modern port scanner |

## Web Application Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| gobuster | gobuster | gobuster | `sudo apt install -y gobuster` | `gobuster --version` | Directory/file/DNS busting tool |
| ffuf | N/A (Go install) | ffuf | `go install github.com/ffuf/ffuf@latest` / `brew install ffuf` | `ffuf -V` | Fast web fuzzer |
| dirb | dirb | dirb | `sudo apt install -y dirb` | `dirb -V` | Web content scanner |
| nikto | nikto | nikto | `sudo apt install -y nikto` | `nikto -Version` | Web server scanner |
| sqlmap | sqlmap | sqlmap | `sudo apt install -y sqlmap` | `sqlmap --version` | SQL injection testing tool |
| wpscan | wpscan | wpscan | `sudo apt install -y wpscan` | `wpscan --version` | WordPress vulnerability scanner |
| wafw00f | wafw00f | N/A | `sudo apt install -y wafw00f` | `wafw00f --version` | Web Application Firewall detection |
| zaproxy | zaproxy | zaproxy | `sudo apt install -y zaproxy` | `zap.sh -version` | Web application security scanner |
| xsser | xsser | N/A | `sudo apt install -y xsser` | `xsser --version` | Cross-site scripting detection |
| wfuzz | wfuzz | N/A | `sudo apt install -y wfuzz` | `wfuzz --version` | Web application fuzzer |

## Authentication & Password Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| hydra | hydra | hydra | `sudo apt install -y hydra` | `hydra --version` | Network logon cracker |
| john | john | john-jumbo | `sudo apt install -y john` / `brew install john-jumbo` | `john --version` | Password cracker |
| hashcat | hashcat | hashcat | `sudo apt install -y hashcat` | `hashcat --version` | Advanced password recovery |
| medusa | medusa | medusa | `sudo apt install -y medusa` | `medusa -V` | Speedy, parallel, modular login brute-forcer |
| patator | patator | patator | `sudo apt install -y patator` | `patator --version` | Multi-purpose brute-forcer |
| evil-winrm | evil-winrm | N/A | `sudo apt install -y evil-winrm` | `evil-winrm --version` | Windows Remote Management shell |
| hash-identifier | hash-identifier | N/A | `sudo apt install -y hash-identifier` | `hash-identifier --version` | Hash type identifier |
| ophcrack | ophcrack | N/A | `sudo apt install -y ophcrack` | `ophcrack --version` | Windows password cracker |

## Binary Analysis & Reverse Engineering Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| gdb | gdb | gdb | `sudo apt install -y gdb` | `gdb --version` | GNU Debugger |
| radare2 | radare2 | radare2 | `sudo apt install -y radare2` | `radare2 -v` | Reverse engineering framework |
| binwalk | binwalk | binwalk | `sudo apt install -y binwalk` | `binwalk --version` | Firmware analysis tool |
| checksec | checksec | N/A | `sudo apt install -y checksec` | `checksec --version` | Binary security checker |
| binutils | binutils | binutils | `sudo apt install -y binutils` | `objdump --version` | Binary utilities |
| foremost | foremost | N/A | `sudo apt install -y foremost` | `foremost -V` | File carving tool |
| steghide | steghide | N/A | `sudo apt install -y steghide` | `steghide --version` | Steganography tool |
| exiftool | libimage-exiftool-perl | exiftool | `sudo apt install -y libimage-exiftool-perl` / `brew install exiftool` | `exiftool -ver` | Metadata extraction tool |
| sleuthkit | sleuthkit | sleuthkit | `sudo apt install -y sleuthkit` | `tsk_version` | Digital forensics toolkit |
| xxd | vim-common | xxd | `sudo apt install -y vim-common` / `brew install xxd` | `xxd -v` | Hex dump utility |
| ghidra | N/A (Manual install) | ghidra | Download from NSA GitHub / `brew install --cask ghidra` | `ghidraRun` | Software reverse engineering suite |

## Advanced CTF & Forensics Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| volatility3 | N/A (pip install) | volatility3 | `pip3 install volatility3` / `brew install volatility3` | `volatility3 --version` | Memory forensics framework |
| autopsy | autopsy | N/A (Manual install) | `sudo apt install -y autopsy` / Manual download from GitHub | `autopsy --version` | Digital forensics platform |
| hashpump | hashpump | N/A | `sudo apt install -y hashpump` | `hashpump --version` | Hash length extension attack tool |

## Cloud & Container Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| trivy | N/A (Install script) | trivy | Install script from GitHub / `brew install aquasecurity/trivy/trivy` | `trivy --version` | Container vulnerability scanner |
| kube-bench | N/A (Manual install) | kube-bench | Manual download from GitHub / `brew install kube-bench` | `kube-bench --version` | Kubernetes security checker |
| cloudsploit | N/A (Manual install) | N/A (Manual install) | `git clone https://github.com/aquasecurity/cloudsploit.git && cd cloudsploit && npm install` | `node index.js --version` | Cloud security scanner |

## Python Packages (pip install)

| Tool | Package Name | Install Command | Verification | Description |
|------|--------------|-----------------|--------------|-------------|
| autorecon | autorecon | `pip3 install autorecon` | `autorecon --version` | Multi-threaded network reconnaissance |
| ropgadget | ropgadget | `pip3 install ropgadget` | `ROPgadget --version` | ROP gadget finder |
| arjun | arjun | `pip3 install arjun` | `arjun --version` | HTTP parameter discovery |
| crackmapexec | crackmapexec | `pip3 install crackmapexec` | `crackmapexec --version` | Network service exploitation |
| netexec | netexec | `pip3 install netexec` | `netexec --version` | Network service exploitation (CME successor) |
| prowler | prowler-cloud | `pip3 install prowler-cloud` / `brew install prowler` | `prowler --version` | Cloud security assessment |
| scoutsuite | scoutsuite | `pip3 install scoutsuite` | `scout --version` | Multi-cloud security auditing |
| kube-hunter | kube-hunter | `pip3 install kube-hunter` / Homebrew tap available | `kube-hunter --version` | Kubernetes penetration testing |
| smbmap | smbmap | `pip3 install smbmap` | `smbmap --version` | SMB enumeration tool |

## Go Packages (go install)

| Tool | Package Path | Install Command | Verification | Description |
|------|--------------|-----------------|--------------|-------------|
| httpx | github.com/projectdiscovery/httpx/cmd/httpx@latest | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` / `brew install projectdiscovery/tap/httpx` | `httpx -version` | Fast HTTP probe |
| katana | github.com/projectdiscovery/katana/cmd/katana@latest | `go install github.com/projectdiscovery/katana/cmd/katana@latest` / `brew install projectdiscovery/tap/katana` | `katana -version` | Web crawling framework |
| dalfox | github.com/hahwul/dalfox/v2@latest | `go install github.com/hahwul/dalfox/v2@latest` / `brew install dalfox` | `dalfox version` | XSS scanner |
| hakrawler | github.com/hakluke/hakrawler@latest | `go install github.com/hakluke/hakrawler@latest` / `brew install hakluke/haktools/hakrawler` | `hakrawler --version` | Web crawler |
| subjack | github.com/haccer/subjack@latest | `go install github.com/haccer/subjack@latest` / `brew install subjack` | `subjack --version` | Subdomain takeover tool |

## Installation Notes

### Prerequisites
- **Ubuntu/Debian**: Ensure `sudo` access and run `sudo apt update` before installation
- **macOS**: Install Homebrew first: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
- **Go tools**: Require Go to be installed first
- **Python tools**: Require Python 3 and pip3

### Special Cases
- **Xcode Command Line Tools (macOS)**: Required for build-essential equivalent
- **GitHub Releases**: Some tools require manual download from GitHub releases
- **Manual Installs**: Ghidra and some specialized tools require manual installation

### Installation Notes

#### System Dependencies
- **Ubuntu/Debian**: Use `build-essential` package for build tools
- **Fedora/RHEL**: Use `@development-tools` group: `sudo dnf groupinstall 'Development Tools'`
- **Arch Linux**: Use `base-devel` group: `sudo pacman -S base-devel`
- **macOS**: Use `xcode-select --install` for build tools

#### Package Manager Variations
- **Arch Linux**: Many security tools are available in AUR (Arch User Repository) and require AUR helpers like `yay` or `paru`
- **Fedora/RHEL**: Some packages may require EPEL repository
- **macOS**: ProjectDiscovery tools available via custom Homebrew tap: `brew tap projectdiscovery/tap`

#### Alternative Installation Methods
- **Go Tools**: Most ProjectDiscovery and modern Go-based tools use `go install` commands
- **Python Tools**: Many security tools require pip installation rather than system packages
- **Manual Installation**: Some tools like Ghidra, trivy, and cloudsploit require manual installation from GitHub releases

### Sources
- [Perplexity AI Research](https://www.perplexity.ai/) - Package name verification
- [Ubuntu Packages](https://packages.ubuntu.com/)
- [Debian Packages](https://packages.debian.org/)
- [Homebrew Formulae](https://formulae.brew.sh/)
- [Fedora Package Database](https://packages.fedoraproject.org/)
- [Arch Package Search](https://archlinux.org/packages/)
- [Arch User Repository (AUR)](https://aur.archlinux.org/)
- [Go Package Index](https://pkg.go.dev/)
- [PyPI](https://pypi.org/)
- [ProjectDiscovery Documentation](https://docs.projectdiscovery.io/)
- Tool-specific GitHub repositories and official documentation

## Network Analysis & Monitoring Tools

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description |
|------|---------------|-------|-----------------|--------------|-------------|
| **wireshark** | wireshark | wireshark | `apt install wireshark` / `brew install wireshark` | `wireshark --version` | Network protocol analyzer |
| **tshark** | tshark | wireshark | `apt install tshark` / `brew install wireshark` | `tshark --version` | Network protocol analyzer (command line) |
| **tcpdump** | tcpdump | tcpdump | `apt install tcpdump` / `brew install tcpdump` | `tcpdump --version` | Network packet analyzer |
| **ngrep** | ngrep | ngrep | `apt install ngrep` / `brew install ngrep` | `ngrep -V` | Network packet analyzer with grep-like functionality |
| **aircrack-ng** | aircrack-ng | aircrack-ng | `apt install aircrack-ng` / `brew install aircrack-ng` | `aircrack-ng --version` | Wireless network security assessment tool |
| **reaver** | reaver | reaver | `apt install reaver` / `brew install reaver` | `reaver --version` | WPS brute force attack tool |
| **kismet** | kismet | kismet | `apt install kismet` / `brew install kismet` | `kismet --version` | Wireless network detector and intrusion detection system |

## Exploit & Vulnerability Research Tools

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description |
|------|---------------|-------|-----------------|--------------|-------------|
| **searchsploit** | exploitdb | exploitdb | `apt install exploitdb` / `brew install exploitdb` | `searchsploit --version` | Exploit database search tool |
| **exploit-db** | exploitdb | exploitdb | `apt install exploitdb` / `brew install exploitdb` | `searchsploit --version` | Exploit database |

## Information Gathering & OSINT Tools

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description |
|------|---------------|-------|-----------------|--------------|-------------|
| **shodan** | pip install | shodan | `pip install shodan` / `brew install shodan` | `shodan --version` | Search engine for Internet-connected devices |
| **censys** | pip install | censys | `pip install censys` / `brew install censys` | `censys --version` | Internet-wide scanning and analysis platform |
| **ldapsearch** | ldap-utils | openldap | `apt install ldap-utils` / `brew install openldap` | `ldapsearch -VV` | LDAP search utility |
| **snmpwalk** | snmp | net-snmp | `apt install snmp` / `brew install net-snmp` | `snmpwalk -V` | SNMP network monitoring tool |
| **impacket** | impacket | impacket | `apt install impacket` / `brew install impacket` | `impacket-smbclient --version` | Collection of Python classes for network protocols |

**Additional Sources:**
- Wireshark: [Official site](https://www.wireshark.org/), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=wireshark)
- Tcpdump: [Official site](https://www.tcpdump.org/), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=tcpdump)
- Aircrack-ng: [Official site](https://www.aircrack-ng.org/), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=aircrack-ng)
- Searchsploit: [Exploit-DB](https://www.exploit-db.com/searchsploit), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=exploitdb)
- Shodan: [Official site](https://shodan.io/), [PyPI](https://pypi.org/project/shodan/)
- Censys: [Official site](https://censys.io/), [PyPI](https://pypi.org/project/censys/)
- Impacket: [GitHub](https://github.com/SecureAuthCorp/impacket), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=impacket)

Last Updated: 2025-08-22 (Verified via Perplexity Research)
