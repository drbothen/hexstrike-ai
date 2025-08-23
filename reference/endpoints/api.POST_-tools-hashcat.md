---
title: POST /api/tools/hashcat
group: api
handler: hashcat
module: __main__
line_range: [9494, 9537]
discovered_in_chunk: 9
---

# POST /api/tools/hashcat

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute Hashcat for password cracking with enhanced logging

## Complete Signature & Definition
```python
@app.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute Hashcat for password cracking with enhanced logging"""
```

## Purpose & Behavior
Advanced password cracking endpoint providing:
- **GPU-Accelerated Cracking:** Utilize GPU acceleration for password cracking
- **Multiple Attack Modes:** Support various attack modes (dictionary, brute force, hybrid)
- **Hash Format Support:** Support for numerous hash formats
- **Enhanced Logging:** Detailed logging of cracking progress and results

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/hashcat
- **Content-Type:** application/json

### Request Body
```json
{
    "hash_file": "string",            // Required: Path to file containing hashes
    "attack_mode": integer,           // Optional: Attack mode (default: 0)
    "hash_type": integer,             // Optional: Hash type (default: 0)
    "wordlist": "string",             // Optional: Path to wordlist file
    "rules": "string",                // Optional: Path to rules file
    "mask": "string",                 // Optional: Mask for brute force attack
    "increment": boolean,             // Optional: Enable increment mode (default: false)
    "optimized": boolean,             // Optional: Enable optimized kernels (default: true)
    "additional_args": "string"       // Optional: Additional hashcat arguments
}
```

### Parameters
- **hash_file:** Path to file containing hashes (required)
- **attack_mode:** Attack mode (optional, default: 0) - 0: Dictionary, 1: Combinator, 3: Brute force, 6: Hybrid Wordlist + Mask, 7: Hybrid Mask + Wordlist
- **hash_type:** Hash type (optional, default: 0) - 0: MD5, 100: SHA1, 1000: NTLM, etc.
- **wordlist:** Path to wordlist file (optional)
- **rules:** Path to rules file (optional)
- **mask:** Mask for brute force attack (optional)
- **increment:** Enable increment mode (optional, default: false)
- **optimized:** Enable optimized kernels (optional, default: true)
- **additional_args:** Additional hashcat arguments (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "command": "hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt",
    "cracking_results": {
        "total_hashes": 5,
        "cracked_hashes": 3,
        "cracking_rate": 60.0,
        "cracked_passwords": [
            {
                "hash": "5d41402abc4b2a76b9719d911017c592",
                "password": "hello",
                "hash_type": "MD5"
            },
            {
                "hash": "098f6bcd4621d373cade4e832627b4f6",
                "password": "test",
                "hash_type": "MD5"
            }
        ],
        "performance": {
            "speed": "1234.5 MH/s",
            "progress": "100%",
            "time_estimated": "00:00:05"
        }
    },
    "raw_output": "hashcat (v6.2.5) starting...",
    "execution_time": 120.3,
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Hash File (400 Bad Request)
```json
{
    "error": "Hash file parameter is required"
}
```

#### Hash File Not Found (404 Not Found)
```json
{
    "error": "Hash file not found: {hash_file}"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Parameter Validation
```python
params = request.json
hash_file = params.get("hash_file", "")
attack_mode = params.get("attack_mode", 0)
hash_type = params.get("hash_type", 0)
wordlist = params.get("wordlist", "")
rules = params.get("rules", "")
mask = params.get("mask", "")
increment = params.get("increment", False)
optimized = params.get("optimized", True)
additional_args = params.get("additional_args", "")

if not hash_file:
    return jsonify({"error": "Hash file parameter is required"}), 400

if not os.path.exists(hash_file):
    return jsonify({"error": f"Hash file not found: {hash_file}"}), 404
```

### Command Construction
```python
# Base command
command = ["hashcat", "-m", str(hash_type), "-a", str(attack_mode)]

# Optimized kernels
if optimized:
    command.append("-O")

# Increment mode
if increment:
    command.append("--increment")

# Rules
if rules:
    command.extend(["-r", rules])

# Hash file
command.append(hash_file)

# Attack-specific parameters
if attack_mode == 0 and wordlist:  # Dictionary attack
    command.append(wordlist)
elif attack_mode == 3 and mask:  # Brute force attack
    command.append(mask)

# Output file for cracked hashes
output_file = f"/tmp/hashcat_output_{int(time.time())}.txt"
command.extend(["--outfile", output_file])

# Additional arguments
if additional_args:
    command.extend(additional_args.split())

# Convert to string
command_str = " ".join(command)
```

### Execution and Result Parsing
```python
start_time = time.time()
result = execute_command_with_recovery(command_str)
execution_time = time.time() - start_time

# Parse cracked passwords from output file
cracked_passwords = []
if os.path.exists(output_file):
    with open(output_file, "r") as f:
        for line in f:
            if ":" in line:
                parts = line.strip().split(":")
                if len(parts) >= 2:
                    hash_value = parts[0]
                    password = ":".join(parts[1:])
                    cracked_passwords.append({
                        "hash": hash_value,
                        "password": password,
                        "hash_type": get_hash_type_name(hash_type)
                    })

# Count total hashes
total_hashes = 0
with open(hash_file, "r") as f:
    total_hashes = sum(1 for line in f if line.strip())

cracking_results = {
    "total_hashes": total_hashes,
    "cracked_hashes": len(cracked_passwords),
    "cracking_rate": (len(cracked_passwords) / total_hashes * 100) if total_hashes > 0 else 0,
    "cracked_passwords": cracked_passwords,
    "performance": parse_hashcat_performance(result["output"])
}
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Hashcat execution access required

## Error Handling
- **Missing Parameters:** 400 error for missing hash file
- **File Not Found:** 404 error for non-existent hash file
- **Execution Errors:** Handled by execute_command_with_recovery
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Hash File Validation:** Ensure hash file is valid and authorized for cracking
- **Resource Management:** Manage GPU and CPU resources during intensive cracking
- **Responsible Use:** Emphasize responsible use of password cracking capabilities

## Use Cases and Applications

#### Password Security Testing
- **Password Strength Assessment:** Assess password strength against cracking
- **Hash Security Validation:** Validate hash security implementations
- **Security Policy Enforcement:** Enforce password policies through testing

#### Penetration Testing
- **Credential Recovery:** Recover credentials during penetration tests
- **Password Auditing:** Audit password security in organizations
- **Hash Analysis:** Analyze captured hashes for vulnerabilities

## Testing & Validation
- Command construction accuracy testing
- Parameter validation verification
- Result parsing accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute Hashcat for password cracking with enhanced logging"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        hash_type = params.get("hash_type", "")
        attack_mode = params.get("attack_mode", "0")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        mask = params.get("mask", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("🔐 Hashcat called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
            
        if not hash_type:
            logger.warning("🔐 Hashcat called without hash_type parameter")
            return jsonify({
                "error": "Hash type parameter is required"
            }), 400
        
        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"
        
        if attack_mode == "0" and wordlist:
            command += f" {wordlist}"
        elif attack_mode == "3" and mask:
            command += f" {mask}"
            
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
        result = execute_command(command)
        logger.info(f"📊 Hashcat attack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hashcat endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
