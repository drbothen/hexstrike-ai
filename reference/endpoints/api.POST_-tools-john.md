---
title: POST /api/tools/john
group: api
handler: john
module: __main__
line_range: [9276, 9312]
discovered_in_chunk: 9
---

# POST /api/tools/john

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Execute John the Ripper for password cracking

## Complete Signature & Definition
```python
@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with enhanced logging"""
```

## Purpose & Behavior
John the Ripper execution endpoint providing:
- **Password Cracking:** Crack password hashes using various methods
- **Hash Detection:** Automatically detect hash types
- **Dictionary Attacks:** Perform dictionary-based password attacks
- **Enhanced Logging:** Detailed logging of John operations

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/tools/john
- **Content-Type:** application/json

### Request Body
```json
{
    "target": {
        "hash_file": "string",        // Required: Path to hash file
        "hash_format": "string",      // Optional: Hash format specification
        "single_hash": "string"       // Optional: Single hash to crack
    },
    "attack_options": {
        "wordlist": "string",         // Optional: Wordlist file path
        "rules": "string",            // Optional: Rules to apply
        "incremental": "string",      // Optional: Incremental mode
        "single": boolean,            // Optional: Single crack mode
        "show": boolean,              // Optional: Show cracked passwords
        "test": boolean               // Optional: Test mode
    },
    "performance_options": {
        "fork": integer,              // Optional: Number of processes
        "session": "string",          // Optional: Session name
        "restore": "string",          // Optional: Restore session
        "max_run_time": integer       // Optional: Maximum runtime in seconds
    }
}
```

### Parameters
- **target:** Target hash information (required)
- **attack_options:** Attack configuration options (optional)
- **performance_options:** Performance tuning options (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "crack_info": {
        "hash_file": "/tmp/hashes.txt",
        "hash_format": "md5",
        "attack_mode": "dictionary",
        "execution_time": 1245.7,
        "passwords_cracked": 15
    },
    "crack_results": {
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
        "statistics": {
            "total_hashes": 100,
            "cracked_count": 15,
            "crack_rate": 0.15,
            "guesses_per_second": 1250000
        },
        "session_info": {
            "session_name": "crack_session_001",
            "progress": "100%",
            "time_elapsed": "20:45",
            "eta": "00:00"
        }
    },
    "performance_metrics": {
        "cpu_usage": 85.2,
        "memory_usage": 512.8,
        "processes_used": 4,
        "efficiency_score": 0.89
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Hash File (400 Bad Request)
```json
{
    "error": "Hash file or single hash is required"
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
target = params.get("target", {})
attack_options = params.get("attack_options", {})
performance_options = params.get("performance_options", {})

hash_file = target.get("hash_file", "")
single_hash = target.get("single_hash", "")

if not hash_file and not single_hash:
    return jsonify({"error": "Hash file or single hash is required"}), 400
```

### John Execution Logic
```python
# Build John command
cmd = ["john"]

# Add hash file or create temp file for single hash
if single_hash:
    hash_file = f"/tmp/single_hash_{int(time.time())}.txt"
    with open(hash_file, 'w') as f:
        f.write(single_hash)

cmd.append(hash_file)

# Add attack options
if attack_options.get("wordlist"):
    cmd.extend(["--wordlist", attack_options["wordlist"]])

if attack_options.get("rules"):
    cmd.extend(["--rules", attack_options["rules"]])

# Execute John
result = execute_command_with_recovery(cmd)
```

## AuthN/AuthZ
- **Authentication:** Not specified (appears to be open)
- **Authorization:** Password cracking access required

## Error Handling
- **Missing Parameters:** 400 error for missing hash data
- **Execution Errors:** Handle John execution failures
- **Server Errors:** 500 error with exception details

## Security Considerations
- **Authorized Use:** Ensure authorized use for legitimate security testing
- **Resource Limits:** Implement resource limits for cracking operations
- **Data Security:** Secure handling of password hashes and results

## Use Cases and Applications

#### Password Security Testing
- **Hash Cracking:** Crack password hashes for security assessment
- **Password Strength Testing:** Test password strength and policies
- **Security Auditing:** Audit password security in systems

#### Penetration Testing
- **Credential Recovery:** Recover passwords during penetration tests
- **Post-Exploitation:** Use cracked passwords for lateral movement
- **Security Validation:** Validate password security controls

## Testing & Validation
- Parameter validation accuracy testing
- John execution verification testing
- Password cracking accuracy testing
- Error handling behavior validation

## Code Reproduction
```python
@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", {})
        attack_options = params.get("attack_options", {})
        performance_options = params.get("performance_options", {})
        
        hash_file = target.get("hash_file", "")
        single_hash = target.get("single_hash", "")
        
        if not hash_file and not single_hash:
            return jsonify({"error": "Hash file or single hash is required"}), 400
        
        logger.info(f"🔓 Starting John the Ripper | Target: {hash_file or 'single hash'}")
        
        start_time = time.time()
        
        # Build John command
        cmd = ["john"]
        
        # Handle single hash
        if single_hash and not hash_file:
            hash_file = f"/tmp/single_hash_{int(time.time())}.txt"
            with open(hash_file, 'w') as f:
                f.write(single_hash)
        
        cmd.append(hash_file)
        
        # Add hash format if specified
        if target.get("hash_format"):
            cmd.extend(["--format", target["hash_format"]])
        
        # Add attack options
        if attack_options.get("wordlist"):
            cmd.extend(["--wordlist", attack_options["wordlist"]])
        
        if attack_options.get("rules"):
            cmd.extend(["--rules", attack_options["rules"]])
        
        if attack_options.get("incremental"):
            cmd.extend(["--incremental", attack_options["incremental"]])
        
        # Add performance options
        if performance_options.get("fork"):
            cmd.extend(["--fork", str(performance_options["fork"])])
        
        if performance_options.get("session"):
            cmd.extend(["--session", performance_options["session"]])
        
        # Execute John
        result = execute_command_with_recovery(cmd)
        
        execution_time = time.time() - start_time
        
        # Parse John output for cracked passwords
        cracked_passwords = []
        if result.stdout:
            # Parse John output format
            lines = result.stdout.split('\n')
            for line in lines:
                if ':' in line and not line.startswith('Loaded'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        cracked_passwords.append({
                            "hash": parts[1].strip() if len(parts) > 2 else "unknown",
                            "password": parts[0].strip(),
                            "hash_type": target.get("hash_format", "auto-detected")
                        })
        
        crack_info = {
            "hash_file": hash_file,
            "hash_format": target.get("hash_format", "auto-detected"),
            "attack_mode": "dictionary" if attack_options.get("wordlist") else "default",
            "execution_time": execution_time,
            "passwords_cracked": len(cracked_passwords)
        }
        
        crack_results = {
            "cracked_passwords": cracked_passwords,
            "statistics": {
                "total_hashes": result.stdout.count('\n') if result.stdout else 0,
                "cracked_count": len(cracked_passwords),
                "crack_rate": len(cracked_passwords) / max(1, result.stdout.count('\n')) if result.stdout else 0
            }
        }
        
        logger.info(f"🔓 John completed in {execution_time:.2f}s | Cracked: {len(cracked_passwords)} passwords")
        
        return jsonify({
            "success": True,
            "crack_info": crack_info,
            "crack_results": crack_results,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"💥 Error executing John: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
```
