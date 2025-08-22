# HexStrike AI - Installation Matrix

This document provides comprehensive installation information for all security tools supported by HexStrike AI across different operating systems.

## System Dependencies

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Purpose |
|------|----------------------|----------------|-----------------|--------------|---------|
| build-essential | build-essential | xcode-select --install | `sudo apt install -y build-essential` | `gcc --version` | Essential build tools (gcc, make, etc.) |
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
| subfinder | N/A (Go install) | subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `subfinder -version` | Fast passive subdomain enumeration |
| nuclei | N/A (Go install) | nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `nuclei -version` | Fast vulnerability scanner |
| fierce | fierce | N/A | `sudo apt install -y fierce` | `fierce --version` | Domain scanner for non-contiguous IP space |
| dnsenum | dnsenum | dnsenum | `sudo apt install -y dnsenum` | `dnsenum --version` | DNS information enumeration |
| theharvester | theharvester | theharvester | `sudo apt install -y theharvester` | `theharvester --version` | OSINT email and subdomain harvester |
| responder | responder | N/A | `sudo apt install -y responder` | `responder --version` | LLMNR/NBT-NS/MDNS poisoner |
| rustscan | N/A (GitHub release) | rustscan | Download from GitHub releases | `rustscan --version` | Modern port scanner |

## Web Application Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| gobuster | gobuster | gobuster | `sudo apt install -y gobuster` | `gobuster --version` | Directory/file/DNS busting tool |
| ffuf | N/A (Go install) | ffuf | `go install github.com/ffuf/ffuf@latest` | `ffuf -V` | Fast web fuzzer |
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
| john | john | john | `sudo apt install -y john` | `john --version` | Password cracker |
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
| exiftool | libimage-exiftool-perl | exiftool | `sudo apt install -y libimage-exiftool-perl` | `exiftool -ver` | Metadata extraction tool |
| sleuthkit | sleuthkit | sleuthkit | `sudo apt install -y sleuthkit` | `tsk_version` | Digital forensics toolkit |
| xxd | xxd | xxd | `sudo apt install -y xxd` | `xxd -v` | Hex dump utility |
| ghidra | N/A (Manual install) | ghidra | Download from NSA GitHub | `ghidraRun` | Software reverse engineering suite |

## Advanced CTF & Forensics Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| volatility3 | N/A (pip install) | volatility3 | `pip3 install volatility3` | `volatility3 --version` | Memory forensics framework |
| autopsy | autopsy | N/A | `sudo apt install -y autopsy` | `autopsy --version` | Digital forensics platform |
| hashpump | hashpump | N/A | `sudo apt install -y hashpump` | `hashpump --version` | Hash length extension attack tool |

## Cloud & Container Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description |
|------|----------------------|----------------|-----------------|--------------|-------------|
| trivy | N/A (GitHub release) | trivy | Download from GitHub releases | `trivy --version` | Container vulnerability scanner |
| kube-bench | N/A (GitHub release) | N/A | Download from GitHub releases | `kube-bench --version` | Kubernetes security checker |
| cloudsploit | N/A (npm install) | N/A | `npm install -g cloudsploit` | `cloudsploit --version` | Cloud security scanner |

## Python Packages (pip install)

| Tool | Package Name | Install Command | Verification | Description |
|------|--------------|-----------------|--------------|-------------|
| autorecon | autorecon | `pip3 install autorecon` | `autorecon --version` | Multi-threaded network reconnaissance |
| ropgadget | ropgadget | `pip3 install ropgadget` | `ROPgadget --version` | ROP gadget finder |
| arjun | arjun | `pip3 install arjun` | `arjun --version` | HTTP parameter discovery |
| crackmapexec | crackmapexec | `pip3 install crackmapexec` | `crackmapexec --version` | Network service exploitation |
| netexec | netexec | `pip3 install netexec` | `netexec --version` | Network service exploitation (CME successor) |
| prowler | prowler-cloud | `pip3 install prowler-cloud` | `prowler --version` | Cloud security assessment |
| scoutsuite | scoutsuite | `pip3 install scoutsuite` | `scout --version` | Multi-cloud security auditing |
| kube-hunter | kube-hunter | `pip3 install kube-hunter` | `kube-hunter --version` | Kubernetes penetration testing |
| smbmap | smbmap | `pip3 install smbmap` | `smbmap --version` | SMB enumeration tool |

## Go Packages (go install)

| Tool | Package Path | Install Command | Verification | Description |
|------|--------------|-----------------|--------------|-------------|
| httpx | github.com/projectdiscovery/httpx/cmd/httpx@latest | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | `httpx -version` | Fast HTTP probe |
| katana | github.com/projectdiscovery/katana/cmd/katana@latest | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | `katana -version` | Web crawling framework |
| dalfox | github.com/hahwul/dalfox/v2@latest | `go install github.com/hahwul/dalfox/v2@latest` | `dalfox version` | XSS scanner |
| hakrawler | github.com/hakluke/hakrawler@latest | `go install github.com/hakluke/hakrawler@latest` | `hakrawler --version` | Web crawler |
| subjack | github.com/haccer/subjack@latest | `go install github.com/haccer/subjack@latest` | `subjack --version` | Subdomain takeover tool |

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

### Sources
- [Ubuntu Packages](https://packages.ubuntu.com/)
- [Debian Packages](https://packages.debian.org/)
- [Homebrew Formulae](https://formulae.brew.sh/)
- [Go Package Index](https://pkg.go.dev/)
- [PyPI](https://pypi.org/)
- Tool-specific GitHub repositories and official documentation

Last Updated: 2025-08-22
