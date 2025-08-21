"""
CTF tool management with comprehensive tool arsenal.

This module changes when CTF tools or command configurations change.
"""

from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class CTFToolManager:
    """Advanced tool manager for CTF challenges with comprehensive tool arsenal"""
    
    def __init__(self):
        self.tool_commands = {
            "httpx": "httpx -probe -tech-detect -status-code -title -content-length",
            "katana": "katana -depth 3 -js-crawl -form-extraction -headless",
            "sqlmap": "sqlmap --batch --level 3 --risk 2 --threads 5",
            "dalfox": "dalfox url --mining-dom --mining-dict --deep-domxss",
            "gobuster": "gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js",
            "dirsearch": "dirsearch -u {} -e php,html,js,txt,xml,json -t 50",
            "feroxbuster": "feroxbuster -u {} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt",
            "arjun": "arjun -u {} --get --post",
            "paramspider": "paramspider -d {}",
            "wpscan": "wpscan --url {} --enumerate ap,at,cb,dbe",
            "nikto": "nikto -h {} -C all",
            "whatweb": "whatweb -v -a 3",
            
            "hashcat": "hashcat -m 0 -a 0 --potfile-disable --quiet",
            "john": "john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5",
            "hash-identifier": "hash-identifier",
            "hashid": "hashid -m",
            "cipher-identifier": "python3 /opt/cipher-identifier/cipher_identifier.py",
            "factordb": "python3 /opt/factordb/factordb.py",
            "rsatool": "python3 /opt/rsatool/rsatool.py",
            "yafu": "yafu",
            "sage": "sage -python",
            "openssl": "openssl",
            "gpg": "gpg --decrypt",
            "steganography": "stegcracker",
            "frequency-analysis": "python3 /opt/frequency-analysis/freq_analysis.py",
            "substitution-solver": "python3 /opt/substitution-solver/solve.py",
            "vigenere-solver": "python3 /opt/vigenere-solver/vigenere.py",
            "base64": "base64 -d",
            "base32": "base32 -d",
            "hex": "xxd -r -p",
            "rot13": "tr 'A-Za-z' 'N-ZA-Mn-za-m'",
            
            "checksec": "checksec --file",
            "pwntools": "python3 -c 'from pwn import *; context.log_level = \"debug\"'",
            "ropper": "ropper --file {} --search",
            "ropgadget": "ROPgadget --binary",
            "one-gadget": "one_gadget",
            "gdb-peda": "gdb -ex 'source /opt/peda/peda.py'",
            "gdb-gef": "gdb -ex 'source /opt/gef/gef.py'",
            "gdb-pwngdb": "gdb -ex 'source /opt/Pwngdb/pwngdb.py'",
            "angr": "python3 -c 'import angr'",
            "radare2": "r2 -A",
            "ghidra": "analyzeHeadless /tmp ghidra_project -import",
            "binary-ninja": "binaryninja",
            "ltrace": "ltrace",
            "strace": "strace -f",
            "objdump": "objdump -d -M intel",
            "readelf": "readelf -a",
            "nm": "nm -D",
            "ldd": "ldd",
            "file": "file",
            "strings": "strings -n 8",
            "hexdump": "hexdump -C",
            "pwninit": "pwninit",
            "libc-database": "python3 /opt/libc-database/find.py",
            
            "binwalk": "binwalk -e --dd='.*'",
            "foremost": "foremost -i {} -o /tmp/foremost_output",
            "photorec": "photorec /log /cmd",
            "testdisk": "testdisk /log",
            "exiftool": "exiftool -all",
            "steghide": "steghide extract -sf {} -p ''",
            "stegsolve": "java -jar /opt/stegsolve/stegsolve.jar",
            "zsteg": "zsteg -a",
            "outguess": "outguess -r",
            "jsteg": "jsteg reveal",
            "volatility": "volatility -f {} imageinfo",
            "volatility3": "python3 /opt/volatility3/vol.py -f",
            "rekall": "rekall -f",
            "wireshark": "tshark -r",
            "tcpdump": "tcpdump -r",
            "networkminer": "mono /opt/NetworkMiner/NetworkMiner.exe",
            "autopsy": "autopsy",
            "sleuthkit": "fls -r",
            "scalpel": "scalpel -c /etc/scalpel/scalpel.conf",
            "bulk-extractor": "bulk_extractor -o /tmp/bulk_output",
            "ddrescue": "ddrescue",
            "dc3dd": "dc3dd",
            
            "ida": "ida64",
            "x64dbg": "x64dbg",
            "ollydbg": "ollydbg",
            "hex-rays": "ida64 -A",
            "retdec": "retdec-decompiler",
            "upx": "upx -d",
            "peid": "peid",
            "detect-it-easy": "die",
            "apktool": "apktool d",
            "jadx": "jadx",
            "dex2jar": "d2j-dex2jar",
            "jd-gui": "jd-gui",
            "frida": "frida",
            "mobsf": "mobsf",
            
            "zip": "unzip",
            "tar": "tar -xf",
            "gzip": "gunzip",
            "7zip": "7z x",
            "rar": "unrar x",
            "qr-decoder": "zbarimg",
            "zbar": "zbarimg",
            "audacity": "audacity",
            "sonic-visualizer": "sonic-visualiser",
            "brainfuck": "python3 /opt/brainfuck/bf.py",
            "whitespace": "python3 /opt/whitespace/ws.py",
            "piet": "python3 /opt/piet/piet.py",
            
            "google-dorking": "python3 /opt/google-dorking/gdork.py",
            "shodan": "shodan",
            "censys": "censys",
            "sherlock": "sherlock",
            "social-analyzer": "social-analyzer",
            "reverse-image-search": "python3 /opt/reverse-image/search.py",
            "exif-analysis": "exiftool",
            "whois": "whois",
            "dns-analysis": "dig",
            "certificate-transparency": "python3 /opt/ct-logs/ct.py",
            "geoint": "python3 /opt/geoint/geo.py",
            "osm-analysis": "python3 /opt/osm/osm.py",
            "satellite-imagery": "python3 /opt/satellite/sat.py",
            
            "nmap": "nmap -sS -sV -O --script=default",
            "rustscan": "rustscan -a {} -- -sV -sC",
            "masscan": "masscan -p1-65535 --rate=1000",
            "zmap": "zmap -p 80",
            "nuclei": "nuclei -t /opt/nuclei-templates/",
            "subfinder": "subfinder -d {}",
            "amass": "amass enum -d {}",
            "assetfinder": "assetfinder {}",
            "findomain": "findomain -t {}",
            "ffuf": "ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u {}/FUZZ",
            "wfuzz": "wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt {}/FUZZ",
            "hydra": "hydra -l admin -P /usr/share/wordlists/rockyou.txt",
            "medusa": "medusa -h {} -u admin -P /usr/share/wordlists/rockyou.txt",
            "ncrack": "ncrack -p ssh {}",
            "patator": "patator ssh_login host={} user=admin password=FILE0 0=/usr/share/wordlists/rockyou.txt",
            "burpsuite": "burpsuite",
            "zap": "zap.sh",
            "w3af": "w3af_console",
            "metasploit": "msfconsole",
            "sqlninja": "sqlninja",
            "commix": "commix --url={}",
            "xsser": "xsser --url={}",
            "beef": "beef",
            "social-engineer-toolkit": "setoolkit",
            "maltego": "maltego",
            "recon-ng": "recon-ng",
            "theharvester": "theHarvester -d {} -b all",
            "dmitry": "dmitry -winsepo {}",
            "fierce": "fierce -dns {}",
            "dnsrecon": "dnsrecon -d {}",
            "dnsenum": "dnsenum {}",
            "wafw00f": "wafw00f {}",
            "whatwaf": "whatwaf -u {}",
            "dirb": "dirb {} /usr/share/wordlists/dirb/common.txt",
            "dirbuster": "dirbuster",
            "wapiti": "wapiti -u {}",
            "skipfish": "skipfish -o /tmp/skipfish {}",
            "arachni": "arachni {}",
            "openvas": "openvas",
            "nessus": "nessus",
            "nexpose": "nexpose",
            "qualys": "qualys",
            "acunetix": "acunetix",
            "appscan": "appscan",
            "veracode": "veracode",
            "checkmarx": "checkmarx",
            "fortify": "fortify",
            "sonarqube": "sonarqube"
        }
    
    def get_tool_command(self, tool_name: str, target: str = None, 
                        parameters: Dict[str, Any] = None) -> str:
        """Get command for specific tool with target and parameters"""
        base_command = self.tool_commands.get(tool_name, tool_name)
        
        if target and '{}' in base_command:
            base_command = base_command.format(target)
        elif target:
            base_command = f"{base_command} {target}"
        
        if parameters:
            for key, value in parameters.items():
                if isinstance(value, bool):
                    if value:
                        base_command += f" --{key}"
                else:
                    base_command += f" --{key} {value}"
        
        return base_command
    
    def get_category_tools(self, category: str) -> List[str]:
        """Get tools for specific CTF category"""
        category_mapping = {
            "web": ["httpx", "katana", "sqlmap", "dalfox", "gobuster", "dirsearch", "feroxbuster", 
                   "arjun", "paramspider", "wpscan", "nikto", "whatweb", "burpsuite", "zap", "w3af"],
            "crypto": ["hashcat", "john", "hash-identifier", "hashid", "cipher-identifier", 
                      "factordb", "rsatool", "yafu", "sage", "openssl", "gpg", "frequency-analysis", 
                      "substitution-solver", "vigenere-solver", "base64", "base32", "hex", "rot13"],
            "pwn": ["checksec", "pwntools", "ropper", "ropgadget", "one-gadget", "gdb-peda", 
                   "gdb-gef", "gdb-pwngdb", "angr", "radare2", "ghidra", "binary-ninja", "ltrace", 
                   "strace", "objdump", "readelf", "nm", "ldd", "file", "strings", "hexdump"],
            "forensics": ["binwalk", "foremost", "photorec", "testdisk", "exiftool", "steghide", 
                         "stegsolve", "zsteg", "outguess", "jsteg", "volatility", "volatility3", 
                         "rekall", "wireshark", "tcpdump", "networkminer", "autopsy", "sleuthkit"],
            "rev": ["ghidra", "ida", "radare2", "binary-ninja", "x64dbg", "ollydbg", "hex-rays", 
                   "retdec", "upx", "peid", "detect-it-easy", "strings", "ltrace", "strace", "objdump"],
            "misc": ["base64", "base32", "hex", "rot13", "zip", "tar", "gzip", "7zip", "rar", 
                    "qr-decoder", "zbar", "audacity", "sonic-visualizer", "brainfuck", "whitespace", "piet"],
            "osint": ["google-dorking", "shodan", "censys", "sherlock", "social-analyzer", 
                     "reverse-image-search", "exif-analysis", "whois", "dns-analysis", 
                     "certificate-transparency", "geoint", "osm-analysis", "satellite-imagery"]
        }
        
        return category_mapping.get(category.lower(), [])
    
    def suggest_tools_for_challenge(self, challenge_description: str, 
                                   category: str = None) -> List[str]:
        """Suggest optimal tools based on challenge description and category"""
        description_lower = challenge_description.lower()
        suggested_tools = []
        
        if category:
            category_tools = self.get_category_tools(category)
            suggested_tools.extend(category_tools[:5])
        
        if any(keyword in description_lower for keyword in ["sql", "injection", "database"]):
            suggested_tools.extend(["sqlmap", "nuclei", "w3af"])
        if any(keyword in description_lower for keyword in ["xss", "cross-site", "script"]):
            suggested_tools.extend(["dalfox", "nuclei", "xsser"])
        if any(keyword in description_lower for keyword in ["directory", "path", "file"]):
            suggested_tools.extend(["gobuster", "feroxbuster", "dirsearch"])
        if any(keyword in description_lower for keyword in ["parameter", "param", "input"]):
            suggested_tools.extend(["arjun", "paramspider", "ffuf"])
        if any(keyword in description_lower for keyword in ["subdomain", "dns", "domain"]):
            suggested_tools.extend(["subfinder", "amass", "assetfinder"])
        if any(keyword in description_lower for keyword in ["port", "scan", "service"]):
            suggested_tools.extend(["nmap", "rustscan", "masscan"])
        if any(keyword in description_lower for keyword in ["hash", "md5", "sha", "password"]):
            suggested_tools.extend(["hashcat", "john", "hash-identifier"])
        if any(keyword in description_lower for keyword in ["cipher", "encrypt", "decode"]):
            suggested_tools.extend(["cipher-identifier", "frequency-analysis", "substitution-solver"])
        if any(keyword in description_lower for keyword in ["rsa", "public key", "private key"]):
            suggested_tools.extend(["rsatool", "factordb", "yafu"])
        if any(keyword in description_lower for keyword in ["base64", "base32", "encoding"]):
            suggested_tools.extend(["base64", "base32", "hex"])
        if any(keyword in description_lower for keyword in ["binary", "executable", "elf"]):
            suggested_tools.extend(["ghidra", "radare2", "checksec", "strings"])
        if any(keyword in description_lower for keyword in ["buffer", "overflow", "pwn"]):
            suggested_tools.extend(["pwntools", "gdb-peda", "ropper", "ropgadget"])
        if any(keyword in description_lower for keyword in ["reverse", "disassemble", "decompile"]):
            suggested_tools.extend(["ghidra", "ida", "radare2", "binary-ninja"])
        if any(keyword in description_lower for keyword in ["forensics", "memory", "dump"]):
            suggested_tools.extend(["volatility", "volatility3", "binwalk", "foremost"])
        if any(keyword in description_lower for keyword in ["image", "picture", "photo", "steganography"]):
            suggested_tools.extend(["exiftool", "steghide", "stegsolve", "zsteg"])
        if any(keyword in description_lower for keyword in ["network", "pcap", "wireshark"]):
            suggested_tools.extend(["wireshark", "tcpdump", "networkminer"])
        if any(keyword in description_lower for keyword in ["zip", "archive", "compressed"]):
            suggested_tools.extend(["zip", "tar", "7zip", "binwalk"])
        if any(keyword in description_lower for keyword in ["qr", "barcode", "code"]):
            suggested_tools.extend(["qr-decoder", "zbar"])
        if any(keyword in description_lower for keyword in ["audio", "sound", "wav", "mp3"]):
            suggested_tools.extend(["audacity", "sonic-visualizer"])
        if any(keyword in description_lower for keyword in ["osint", "intelligence", "information"]):
            suggested_tools.extend(["sherlock", "shodan", "whois", "theharvester"])
        if any(keyword in description_lower for keyword in ["social", "media", "profile"]):
            suggested_tools.extend(["sherlock", "social-analyzer"])
        if any(keyword in description_lower for keyword in ["google", "search", "dork"]):
            suggested_tools.extend(["google-dorking", "shodan", "censys"])
        if any(keyword in description_lower for keyword in ["certificate", "ssl", "tls"]):
            suggested_tools.extend(["certificate-transparency", "openssl"])
        if any(keyword in description_lower for keyword in ["location", "geo", "gps"]):
            suggested_tools.extend(["geoint", "exif-analysis"])
        if any(keyword in description_lower for keyword in ["mobile", "android", "apk"]):
            suggested_tools.extend(["apktool", "jadx", "dex2jar", "mobsf"])
        if any(keyword in description_lower for keyword in ["javascript", "js", "node"]):
            suggested_tools.extend(["katana", "nuclei", "whatweb"])
        if any(keyword in description_lower for keyword in ["wordpress", "wp", "cms"]):
            suggested_tools.extend(["wpscan", "nuclei", "whatweb"])
        if any(keyword in description_lower for keyword in ["brainfuck", "bf", "esoteric"]):
            suggested_tools.append("brainfuck")
        if any(keyword in description_lower for keyword in ["whitespace", "ws"]):
            suggested_tools.append("whitespace")
        if any(keyword in description_lower for keyword in ["piet", "image", "program"]):
            suggested_tools.append("piet")
        
        return list(dict.fromkeys(suggested_tools))
