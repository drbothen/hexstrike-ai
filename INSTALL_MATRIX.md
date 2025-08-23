# HexStrike AI - Installation Matrix

This document provides comprehensive installation information for all security tools supported by HexStrike AI across different operating systems.

## System Dependencies

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Purpose | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|---------|--------------|
| build-essential | build-essential | xcode-select --install | `sudo apt install -y build-essential` / `xcode-select --install` | `gcc --version` | Essential build tools (gcc, make, etc.) | N/A |
| python3-dev | python3-dev | python3 | `sudo apt install -y python3-dev` | `python3-config --includes` | Python development headers | N/A |
| python3-pip | python3-pip | python3-pip | `sudo apt install -y python3-pip` | `pip3 --version` | Python package installer | N/A |
| golang-go | golang-go | go | `sudo apt install -y golang-go` | `go version` | Go programming language | N/A |
| libssl-dev | libssl-dev | openssl | `sudo apt install -y libssl-dev` | `pkg-config --modversion openssl` | SSL/TLS development libraries | N/A |
| libffi-dev | libffi-dev | libffi | `sudo apt install -y libffi-dev` | `pkg-config --modversion libffi` | Foreign Function Interface library | N/A |
| libpq-dev | libpq-dev | libpq | `sudo apt install -y libpq-dev` | `pg_config --version` | PostgreSQL client library | N/A |
| zlib1g-dev | zlib1g-dev | zlib | `sudo apt install -y zlib1g-dev` | `pkg-config --modversion zlib` | Compression library | N/A |
| pkg-config | pkg-config | pkg-config | `sudo apt install -y pkg-config` | `pkg-config --version` | Package configuration system | N/A |
| cmake | cmake | cmake | `sudo apt install -y cmake` | `cmake --version` | Cross-platform build system | N/A |
| curl | curl | curl | `sudo apt install -y curl` | `curl --version` | Data transfer tool | N/A |
| wget | wget | wget | `sudo apt install -y wget` | `wget --version` | Network downloader | N/A |
| git | git | git | `sudo apt install -y git` | `git --version` | Version control system | N/A |
| unzip | unzip | unzip | `sudo apt install -y unzip` | `unzip -v` | Archive extraction utility | N/A |
| ca-certificates | ca-certificates | ca-certificates | `sudo apt install -y ca-certificates` | `ls /etc/ssl/certs/` | SSL certificate bundle | N/A |

## Network & Reconnaissance Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|-------------|--------------|
| nmap | nmap | nmap | `sudo apt install -y nmap` | `nmap --version` | Network discovery and security auditing | `/api/tools/nmap` |
| masscan | masscan | masscan | `sudo apt install -y masscan` | `masscan --version` | High-speed TCP port scanner | `/api/tools/masscan` |
| amass | amass | amass | `sudo apt install -y amass` | `amass --version` | Attack surface mapping and asset discovery | `/api/tools/amass` |
| subfinder | N/A (Go install) | subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` / `brew install subfinder` | `subfinder -version` | Fast passive subdomain enumeration | `/api/tools/subfinder` |
| nuclei | N/A (Go install) | nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` / `brew install nuclei` | `nuclei -version` | Fast vulnerability scanner | `/api/tools/nuclei` |
| fierce | fierce | N/A | `sudo apt install -y fierce` | `fierce --version` | Domain scanner for non-contiguous IP space | `/api/tools/fierce` |
| dnsenum | dnsenum | dnsenum | `sudo apt install -y dnsenum` | `dnsenum --version` | DNS information enumeration | `/api/tools/dnsenum` |
| theharvester | theharvester | theharvester | `sudo apt install -y theharvester` | `theharvester --version` | OSINT email and subdomain harvester | N/A |
| responder | responder | N/A | `sudo apt install -y responder` | `responder --version` | LLMNR/NBT-NS/MDNS poisoner | `/api/tools/responder` |
| rustscan | N/A (GitHub release) | rustscan | Download from GitHub releases | `rustscan --version` | Modern port scanner | `/api/tools/rustscan` |

## Web Application Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|-------------|--------------|
| gobuster | gobuster | gobuster | `sudo apt install -y gobuster` | `gobuster --version` | Directory/file/DNS busting tool | `/api/tools/gobuster` |
| ffuf | N/A (Go install) | ffuf | `go install github.com/ffuf/ffuf@latest` / `brew install ffuf` | `ffuf -V` | Fast web fuzzer | `/api/tools/ffuf` |
| dirb | dirb | dirb | `sudo apt install -y dirb` | `dirb -V` | Web content scanner | `/api/tools/dirb` |
| nikto | nikto | nikto | `sudo apt install -y nikto` | `nikto -Version` | Web server scanner | `/api/tools/nikto` |
| sqlmap | sqlmap | sqlmap | `sudo apt install -y sqlmap` | `sqlmap --version` | SQL injection testing tool | `/api/tools/sqlmap` |
| wpscan | wpscan | wpscan | `sudo apt install -y wpscan` | `wpscan --version` | WordPress vulnerability scanner | `/api/tools/wpscan` |
| wafw00f | wafw00f | N/A | `sudo apt install -y wafw00f` | `wafw00f --version` | Web Application Firewall detection | `/api/tools/wafw00f` |
| zaproxy | zaproxy | zaproxy | `sudo apt install -y zaproxy` | `zap.sh -version` | Web application security scanner | `/api/tools/zap` |
| xsser | xsser | N/A | `sudo apt install -y xsser` | `xsser --version` | Cross-site scripting detection | N/A |
| wfuzz | wfuzz | N/A | `sudo apt install -y wfuzz` | `wfuzz --version` | Web application fuzzer | `/api/tools/wfuzz` |

## Authentication & Password Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|-------------|--------------|
| hydra | hydra | hydra | `sudo apt install -y hydra` | `hydra --version` | Network logon cracker | `/api/tools/hydra` |
| john | john | john-jumbo | `sudo apt install -y john` / `brew install john-jumbo` | `john --version` | Password cracker | `/api/tools/john` |
| hashcat | hashcat | hashcat | `sudo apt install -y hashcat` | `hashcat --version` | Advanced password recovery | `/api/tools/hashcat` |
| medusa | medusa | medusa | `sudo apt install -y medusa` | `medusa -V` | Speedy, parallel, modular login brute-forcer | N/A |
| patator | patator | patator | `sudo apt install -y patator` | `patator --version` | Multi-purpose brute-forcer | N/A |
| evil-winrm | evil-winrm | N/A | `sudo apt install -y evil-winrm` | `evil-winrm --version` | Windows Remote Management shell | N/A |
| hash-identifier | hash-identifier | N/A | `sudo apt install -y hash-identifier` | `hash-identifier --version` | Hash type identifier | N/A |
| ophcrack | ophcrack | N/A | `sudo apt install -y ophcrack` | `ophcrack --version` | Windows password cracker | N/A |

## Binary Analysis & Reverse Engineering Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|-------------|--------------|
| gdb | gdb | gdb | `sudo apt install -y gdb` | `gdb --version` | GNU Debugger | `/api/tools/gdb` |
| radare2 | radare2 | radare2 | `sudo apt install -y radare2` | `radare2 -v` | Reverse engineering framework | `/api/tools/radare2` |
| binwalk | binwalk | binwalk | `sudo apt install -y binwalk` | `binwalk --version` | Firmware analysis tool | `/api/tools/binwalk` |
| checksec | checksec | N/A | `sudo apt install -y checksec` | `checksec --version` | Binary security checker | `/api/tools/checksec` |
| binutils | binutils | binutils | `sudo apt install -y binutils` | `objdump --version` | Binary utilities | `/api/tools/objdump` |
| foremost | foremost | N/A | `sudo apt install -y foremost` | `foremost -V` | File carving tool | `/api/tools/foremost` |
| steghide | steghide | N/A | `sudo apt install -y steghide` | `steghide --version` | Steganography tool | `/api/tools/steghide` |
| exiftool | libimage-exiftool-perl | exiftool | `sudo apt install -y libimage-exiftool-perl` / `brew install exiftool` | `exiftool -ver` | Metadata extraction tool | `/api/tools/exiftool` |
| sleuthkit | sleuthkit | sleuthkit | `sudo apt install -y sleuthkit` | `tsk_version` | Digital forensics toolkit | N/A |
| xxd | vim-common | xxd | `sudo apt install -y vim-common` / `brew install xxd` | `xxd -v` | Hex dump utility | `/api/tools/xxd` |
| ghidra | N/A (Manual install) | ghidra | Download from NSA GitHub / `brew install --cask ghidra` | `ghidraRun` | Software reverse engineering suite | `/api/tools/ghidra` |

## Advanced CTF & Forensics Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|-------------|--------------|
| volatility3 | N/A (pip install) | volatility3 | `pip3 install volatility3` / `brew install volatility3` | `volatility3 --version` | Memory forensics framework | `/api/tools/volatility3` |
| autopsy | autopsy | N/A (Manual install) | `sudo apt install -y autopsy` / Manual download from GitHub | `autopsy --version` | Digital forensics platform | N/A |
| hashpump | hashpump | N/A | `sudo apt install -y hashpump` | `hashpump --version` | Hash length extension attack tool | `/api/tools/hashpump` |

## Cloud & Container Security Tools

| Tool | Ubuntu/Debian Package | macOS Homebrew | Install Command | Verification | Description | API Endpoint |
|------|----------------------|----------------|-----------------|--------------|-------------|--------------|
| trivy | N/A (Install script) | trivy | Install script from GitHub / `brew install aquasecurity/trivy/trivy` | `trivy --version` | Container vulnerability scanner | `/api/tools/trivy` |
| kube-bench | N/A (Manual install) | kube-bench | Manual download from GitHub / `brew install kube-bench` | `kube-bench --version` | Kubernetes security checker | `/api/tools/kube-bench` |
| cloudsploit | N/A (Manual install) | N/A (Manual install) | `git clone https://github.com/aquasecurity/cloudsploit.git && cd cloudsploit && npm install` | `node index.js --version` | Cloud security scanner | N/A |

## Python Packages (pip install)

| Tool | Package Name | Install Command | Verification | Description | API Endpoint |
|------|--------------|-----------------|--------------|-------------|--------------|
| autorecon | autorecon | `pip3 install autorecon` | `autorecon --version` | Multi-threaded network reconnaissance | `/api/tools/autorecon` |
| ropgadget | ropgadget | `pip3 install ropgadget` | `ROPgadget --version` | ROP gadget finder | `/api/tools/ropgadget` |
| arjun | arjun | `pip3 install arjun` | `arjun --version` | HTTP parameter discovery | `/api/tools/arjun` |
| crackmapexec | crackmapexec | `pip3 install crackmapexec` | `crackmapexec --version` | Network service exploitation | N/A |
| netexec | netexec | `pip3 install netexec` | `netexec --version` | Network service exploitation (CME successor) | `/api/tools/netexec` |
| prowler | prowler-cloud | `pip3 install prowler-cloud` / `brew install prowler` | `prowler --version` | Cloud security assessment | `/api/tools/prowler` |
| scoutsuite | scoutsuite | `pip3 install scoutsuite` | `scout --version` | Multi-cloud security auditing | `/api/tools/scout-suite` |
| kube-hunter | kube-hunter | `pip3 install kube-hunter` / Homebrew tap available | `kube-hunter --version` | Kubernetes penetration testing | `/api/tools/kube-hunter` |
| smbmap | smbmap | `pip3 install smbmap` | `smbmap --version` | SMB enumeration tool | `/api/tools/smbmap` |

## Go Packages (go install)

| Tool | Package Path | Install Command | Verification | Description | API Endpoint |
|------|--------------|-----------------|--------------|-------------|--------------|
| httpx | github.com/projectdiscovery/httpx/cmd/httpx@latest | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` / `brew install projectdiscovery/tap/httpx` | `httpx -version` | Fast HTTP probe | `/api/tools/httpx` |
| katana | github.com/projectdiscovery/katana/cmd/katana@latest | `go install github.com/projectdiscovery/katana/cmd/katana@latest` / `brew install projectdiscovery/tap/katana` | `katana -version` | Web crawling framework | `/api/tools/katana` |
| dalfox | github.com/hahwul/dalfox/v2@latest | `go install github.com/hahwul/dalfox/v2@latest` / `brew install dalfox` | `dalfox version` | XSS scanner | `/api/tools/dalfox` |
| hakrawler | github.com/hakluke/hakrawler@latest | `go install github.com/hakluke/hakrawler@latest` / `brew install hakluke/haktools/hakrawler` | `hakrawler --version` | Web crawler | `/api/tools/hakrawler` |
| subjack | github.com/haccer/subjack@latest | `go install github.com/haccer/subjack@latest` / `brew install subjack` | `subjack --version` | Subdomain takeover tool | N/A |

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

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description | API Endpoint |
|------|---------------|-------|-----------------|--------------|-------------|--------------|
| **wireshark** | wireshark | wireshark | `apt install wireshark` / `brew install wireshark` | `wireshark --version` | Network protocol analyzer | N/A |
| **tshark** | tshark | wireshark | `apt install tshark` / `brew install wireshark` | `tshark --version` | Network protocol analyzer (command line) | N/A |
| **tcpdump** | tcpdump | tcpdump | `apt install tcpdump` / `brew install tcpdump` | `tcpdump --version` | Network packet analyzer | N/A |
| **ngrep** | ngrep | ngrep | `apt install ngrep` / `brew install ngrep` | `ngrep -V` | Network packet analyzer with grep-like functionality | N/A |
| **aircrack-ng** | aircrack-ng | aircrack-ng | `apt install aircrack-ng` / `brew install aircrack-ng` | `aircrack-ng --version` | Wireless network security assessment tool | N/A |
| **reaver** | reaver | reaver | `apt install reaver` / `brew install reaver` | `reaver --version` | WPS brute force attack tool | N/A |
| **kismet** | kismet | kismet | `apt install kismet` / `brew install kismet` | `kismet --version` | Wireless network detector and intrusion detection system | N/A |

## Exploit & Vulnerability Research Tools

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description | API Endpoint |
|------|---------------|-------|-----------------|--------------|-------------|--------------|
| **searchsploit** | exploitdb | exploitdb | `apt install exploitdb` / `brew install exploitdb` | `searchsploit --version` | Exploit database search tool | N/A |
| **exploit-db** | exploitdb | exploitdb | `apt install exploitdb` / `brew install exploitdb` | `searchsploit --version` | Exploit database | N/A |

## Information Gathering & OSINT Tools

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description | API Endpoint |
|------|---------------|-------|-----------------|--------------|-------------|--------------|
| **shodan** | pip install | shodan | `pip install shodan` / `brew install shodan` | `shodan --version` | Search engine for Internet-connected devices | N/A |
| **censys** | pip install | censys | `pip install censys` / `brew install censys` | `censys --version` | Internet-wide scanning and analysis platform | N/A |
| **ldapsearch** | ldap-utils | openldap | `apt install ldap-utils` / `brew install openldap` | `ldapsearch -VV` | LDAP search utility | N/A |
| **snmpwalk** | snmp | net-snmp | `apt install snmp` / `brew install net-snmp` | `snmpwalk -V` | SNMP network monitoring tool | N/A |
| **impacket** | impacket | impacket | `apt install impacket` / `brew install impacket` | `impacket-smbclient --version` | Collection of Python classes for network protocols | N/A |
| **gau** | N/A (Go install) | gau | `go install github.com/lc/gau/v2/cmd/gau@latest` | `gau --version` | Get All URLs - fetch known URLs from AlienVault's Open Threat Exchange | `/api/tools/gau` |
| **waybackurls** | N/A (Go install) | waybackurls | `go install github.com/tomnomnom/waybackurls@latest` | `waybackurls --version` | Fetch all URLs from Wayback Machine | `/api/tools/waybackurls` |
| **paramspider** | N/A (pip install) | paramspider | `pip3 install paramspider` | `paramspider --version` | Parameter discovery tool | `/api/tools/paramspider` |

## Additional Security Tools with API Endpoints

| Tool | Ubuntu/Debian | macOS | Install Command | Verification | Description | API Endpoint |
|------|---------------|-------|-----------------|--------------|-------------|--------------|
| **anew** | N/A (Go install) | anew | `go install github.com/tomnomnom/anew@latest` | `anew --version` | Append lines from stdin to a file, but only if they don't already appear in the file | `/api/tools/anew` |
| **angr** | N/A (pip install) | angr | `pip3 install angr` | `python3 -c "import angr; print('angr installed')"` | Binary analysis platform | `/api/tools/angr` |
| **arp-scan** | arp-scan | arp-scan | `sudo apt install -y arp-scan` / `brew install arp-scan` | `arp-scan --version` | ARP network scanner | `/api/tools/arp-scan` |
| **checkov** | N/A (pip install) | checkov | `pip3 install checkov` | `checkov --version` | Static code analysis tool for infrastructure-as-code | `/api/tools/checkov` |
| **clair** | N/A (Docker) | clair | Docker installation required | `docker run --rm clair:latest --version` | Container vulnerability scanner | `/api/tools/clair` |
| **cloudmapper** | N/A (pip install) | cloudmapper | `pip3 install cloudmapper` | `cloudmapper --version` | AWS security auditing tool | `/api/tools/cloudmapper` |
| **dirsearch** | N/A (pip install) | dirsearch | `pip3 install dirsearch` | `dirsearch --version` | Web path scanner | `/api/tools/dirsearch` |
| **docker-bench-security** | N/A (GitHub) | docker-bench-security | `git clone https://github.com/docker/docker-bench-security.git` | `./docker-bench-security.sh --version` | Docker security benchmark | `/api/tools/docker-bench-security` |
| **dotdotpwn** | dotdotpwn | N/A | `sudo apt install -y dotdotpwn` | `dotdotpwn.pl --version` | Directory traversal fuzzer | `/api/tools/dotdotpwn` |
| **enum4linux** | enum4linux | enum4linux | `sudo apt install -y enum4linux` | `enum4linux --version` | SMB enumeration tool | `/api/tools/enum4linux` |
| **enum4linux-ng** | N/A (pip install) | enum4linux-ng | `pip3 install enum4linux-ng` | `enum4linux-ng --version` | Next generation SMB enumeration tool | `/api/tools/enum4linux-ng` |
| **falco** | N/A (Install script) | falco | Install from Falco website | `falco --version` | Runtime security monitoring | `/api/tools/falco` |
| **feroxbuster** | N/A (GitHub release) | feroxbuster | Download from GitHub releases | `feroxbuster --version` | Fast content discovery tool | `/api/tools/feroxbuster` |
| **jaeles** | N/A (Go install) | jaeles | `go install github.com/jaeles-project/jaeles@latest` | `jaeles --version` | Web application security scanner | `/api/tools/jaeles` |
| **metasploit** | metasploit-framework | metasploit | `sudo apt install -y metasploit-framework` / `brew install metasploit` | `msfconsole --version` | Penetration testing framework | `/api/tools/metasploit` |
| **msfvenom** | metasploit-framework | metasploit | `sudo apt install -y metasploit-framework` / `brew install metasploit` | `msfvenom --version` | Payload generator | `/api/tools/msfvenom` |
| **nbtscan** | nbtscan | nbtscan | `sudo apt install -y nbtscan` | `nbtscan --version` | NetBIOS name scanner | `/api/tools/nbtscan` |
| **one-gadget** | N/A (gem install) | one-gadget | `gem install one_gadget` | `one_gadget --version` | ROP gadget finder for libc | `/api/tools/one-gadget` |
| **pacu** | N/A (pip install) | pacu | `pip3 install pacu` | `pacu --version` | AWS exploitation framework | `/api/tools/pacu` |
| **pwninit** | N/A (GitHub release) | pwninit | Download from GitHub releases | `pwninit --version` | CTF binary exploitation setup tool | `/api/tools/pwninit` |
| **pwntools** | N/A (pip install) | pwntools | `pip3 install pwntools` | `python3 -c "import pwn; print('pwntools installed')"` | CTF framework and exploit development library | `/api/tools/pwntools` |
| **qsreplace** | N/A (Go install) | qsreplace | `go install github.com/tomnomnom/qsreplace@latest` | `qsreplace --version` | Query string parameter replacement tool | `/api/tools/qsreplace` |
| **ropper** | N/A (pip install) | ropper | `pip3 install ropper` | `ropper --version` | ROP gadget finder | `/api/tools/ropper` |
| **rpcclient** | samba-common-bin | samba | `sudo apt install -y samba-common-bin` / `brew install samba` | `rpcclient --version` | SMB/CIFS client for RPC calls | `/api/tools/rpcclient` |
| **strings** | binutils | binutils | `sudo apt install -y binutils` / `brew install binutils` | `strings --version` | Extract printable strings from files | `/api/tools/strings` |
| **terrascan** | N/A (GitHub release) | terrascan | Download from GitHub releases | `terrascan version` | Infrastructure as Code security scanner | `/api/tools/terrascan` |
| **uro** | N/A (pip install) | uro | `pip3 install uro` | `uro --version` | URL filtering and manipulation tool | `/api/tools/uro` |
| **volatility** | N/A (pip install) | volatility | `pip3 install volatility` | `volatility --version` | Memory forensics framework (legacy) | `/api/tools/volatility` |
| **x8** | N/A (GitHub release) | x8 | Download from GitHub releases | `x8 --version` | Hidden parameter discovery suite | `/api/tools/x8` |

**Additional Sources:**
- Wireshark: [Official site](https://www.wireshark.org/), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=wireshark)
- Tcpdump: [Official site](https://www.tcpdump.org/), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=tcpdump)
- Aircrack-ng: [Official site](https://www.aircrack-ng.org/), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=aircrack-ng)
- Searchsploit: [Exploit-DB](https://www.exploit-db.com/searchsploit), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=exploitdb)
- Shodan: [Official site](https://shodan.io/), [PyPI](https://pypi.org/project/shodan/)
- Censys: [Official site](https://censys.io/), [PyPI](https://pypi.org/project/censys/)
- Impacket: [GitHub](https://github.com/SecureAuthCorp/impacket), [Ubuntu packages](https://packages.ubuntu.com/search?keywords=impacket)

Last Updated: 2025-08-22 (Verified via Perplexity Research)
