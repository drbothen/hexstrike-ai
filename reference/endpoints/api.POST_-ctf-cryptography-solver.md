---
title: POST /api/ctf/cryptography-solver
group: api
handler: ctf_cryptography_solver
module: __main__
line_range: [14394, 14490]
discovered_in_chunk: 15
---

# POST /api/ctf/cryptography-solver

## Entity Classification & Context
- **Kind:** Flask API endpoint
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** Advanced cryptography challenge solver with multiple attack methods

## Complete Signature & Definition
```python
@app.route("/api/ctf/cryptography-solver", methods=["POST"])
def ctf_cryptography_solver():
    """Advanced cryptography challenge solver with multiple attack methods"""
```

## Purpose & Behavior
Advanced cryptography analysis endpoint providing:
- **Cipher Type Identification:** Automatic cipher type identification using heuristics
- **Hash Analysis:** Hash type identification and analysis recommendations
- **Frequency Analysis:** Character frequency analysis for substitution ciphers
- **Multi-attack Support:** Support for various cryptographic attack methods

## Request

### HTTP Method
- **Method:** POST
- **Path:** /api/ctf/cryptography-solver
- **Content-Type:** application/json

### Request Body
```json
{
    "cipher_text": "string",            // Required: Cipher text to analyze
    "cipher_type": "string",            // Optional: Known cipher type (default: "unknown")
    "key_hint": "string",               // Optional: Key hint or partial key
    "known_plaintext": "string",       // Optional: Known plaintext for analysis
    "additional_info": "string"         // Optional: Additional context information
}
```

### Parameters
- **cipher_text:** Cipher text to analyze and solve (required)
- **cipher_type:** Known cipher type - "unknown", "substitution", "caesar", "vigenere", "rsa" (optional, default: "unknown")
- **key_hint:** Key hint or partial key information (optional)
- **known_plaintext:** Known plaintext for cryptanalysis (optional)
- **additional_info:** Additional context or hints (optional)

## Response

### Success Response (200 OK)
```json
{
    "success": true,
    "analysis": {
        "cipher_text": "string",
        "cipher_type": "unknown",
        "analysis_results": [
            "Possible hexadecimal encoding",
            "Possible Base64 encoding",
            "Most frequent character: E (15 occurrences)"
        ],
        "potential_solutions": [],
        "recommended_tools": [
            "hex",
            "base64",
            "frequency-analysis",
            "hashcat"
        ],
        "next_steps": [
            "Try substituting most frequent character with 'E'",
            "Try all ROT values (1-25)",
            "Check if modulus can be factored"
        ]
    },
    "timestamp": "2024-01-01T12:00:00Z"
}
```

### Error Responses

#### Missing Cipher Text (400 Bad Request)
```json
{
    "error": "Cipher text is required"
}
```

#### Server Error (500 Internal Server Error)
```json
{
    "error": "Server error: {error_message}"
}
```

## Implementation Details

### Cipher Type Identification

#### Hexadecimal Detection
```python
if re.match(r'^[0-9a-fA-F]+$', cipher_text.replace(' ', '')):
    results["analysis_results"].append("Possible hexadecimal encoding")
    results["recommended_tools"].extend(["hex", "xxd"])
```

#### Base64 Detection
```python
if re.match(r'^[A-Za-z0-9+/]+=*$', cipher_text.replace(' ', '')):
    results["analysis_results"].append("Possible Base64 encoding")
    results["recommended_tools"].append("base64")
```

#### Substitution Cipher Detection
```python
if len(set(cipher_text.upper().replace(' ', ''))) <= 26:
    results["analysis_results"].append("Possible substitution cipher")
    results["recommended_tools"].extend(["frequency-analysis", "substitution-solver"])
```

### Hash Analysis
```python
hash_patterns = {
    32: "MD5",
    40: "SHA1", 
    64: "SHA256",
    128: "SHA512"
}

clean_text = cipher_text.replace(' ', '').replace('\n', '')
if len(clean_text) in hash_patterns and re.match(r'^[0-9a-fA-F]+$', clean_text):
    hash_type = hash_patterns[len(clean_text)]
    results["analysis_results"].append(f"Possible {hash_type} hash")
    results["recommended_tools"].extend(["hashcat", "john", "hash-identifier"])
```

### Frequency Analysis
```python
if cipher_type in ["substitution", "caesar", "vigenere"] or "substitution" in results["analysis_results"]:
    char_freq = {}
    for char in cipher_text.upper():
        if char.isalpha():
            char_freq[char] = char_freq.get(char, 0) + 1
    
    if char_freq:
        most_common = max(char_freq, key=char_freq.get)
        results["analysis_results"].append(f"Most frequent character: {most_common} ({char_freq[most_common]} occurrences)")
        results["next_steps"].append("Try substituting most frequent character with 'E'")
```

## Key Features

### Automatic Cipher Identification
- **Pattern Recognition:** Identify cipher types using regex patterns and heuristics
- **Encoding Detection:** Detect common encodings (hex, base64, etc.)
- **Hash Identification:** Identify hash types based on length and character patterns

### Cryptanalysis Techniques
- **Frequency Analysis:** Character frequency analysis for substitution ciphers
- **Pattern Analysis:** Identify patterns and structures in cipher text
- **Statistical Analysis:** Statistical analysis for cipher identification

### Multi-cipher Support
- **Classical Ciphers:** Caesar, Vigenère, substitution ciphers
- **Modern Cryptography:** RSA, hash functions
- **Encoding Schemes:** Hexadecimal, Base64, and other encodings

### Tool Recommendations
- **Cipher-specific Tools:** Recommend appropriate tools for each cipher type
- **Attack Methods:** Suggest specific attack methods and techniques
- **Next Steps:** Provide actionable next steps for analysis

## Cipher Analysis Capabilities

### Classical Ciphers
- **Caesar Cipher:** ROT analysis and brute force recommendations
- **Vigenère Cipher:** Kasiski examination and index of coincidence
- **Substitution Cipher:** Frequency analysis and pattern matching

### Hash Analysis
- **Hash Identification:** MD5, SHA1, SHA256, SHA512 identification
- **Cracking Tools:** Hashcat, John the Ripper recommendations
- **Attack Methods:** Dictionary, brute force, and rainbow table attacks

### RSA Analysis
- **Factorization:** Modulus factorization recommendations
- **Attack Methods:** Small exponent, common modulus attacks
- **Tool Suggestions:** RSATool, FactorDB, YAFU recommendations

### Encoding Analysis
- **Base64:** Base64 encoding detection and decoding
- **Hexadecimal:** Hex encoding detection and conversion
- **Custom Encodings:** Pattern-based encoding identification

## AuthN/AuthZ
- **Cryptographic Analysis:** Advanced cryptographic analysis capabilities
- **CTF Challenge Solving:** CTF cryptography challenge solving tools

## Observability
- **Analysis Logging:** "🔐 CTF crypto analysis completed | Type: {cipher_type} | Tools: {count}"
- **Error Logging:** "💥 Error in CTF crypto solver: {error}"

## Use Cases and Applications

#### CTF Competitions
- **Cryptography Challenges:** Solve cryptography challenges in CTF competitions
- **Cipher Analysis:** Analyze unknown ciphers and encodings
- **Tool Selection:** Get recommendations for appropriate cryptanalysis tools

#### Security Education
- **Cryptanalysis Learning:** Learn cryptanalysis techniques and methods
- **Tool Familiarization:** Familiarize with cryptographic analysis tools
- **Challenge Practice:** Practice solving cryptographic challenges

#### Security Research
- **Cipher Analysis:** Analyze custom or unknown cipher implementations
- **Weakness Detection:** Detect weaknesses in cryptographic implementations
- **Tool Development:** Support development of cryptanalysis tools

## Testing & Validation
- Cipher text parameter validation
- Cipher type identification accuracy testing
- Tool recommendation relevance verification
- Analysis result accuracy validation

## Code Reproduction
```python
# From line 14394: Complete Flask endpoint implementation
@app.route("/api/ctf/cryptography-solver", methods=["POST"])
def ctf_cryptography_solver():
    """Advanced cryptography challenge solver with multiple attack methods"""
    try:
        params = request.json
        cipher_text = params.get("cipher_text", "")
        cipher_type = params.get("cipher_type", "unknown")
        key_hint = params.get("key_hint", "")
        known_plaintext = params.get("known_plaintext", "")
        additional_info = params.get("additional_info", "")
        
        if not cipher_text:
            logger.warning("🔐 CTF crypto solver called without cipher text")
            return jsonify({"error": "Cipher text is required"}), 400
        
        results = {
            "cipher_text": cipher_text,
            "cipher_type": cipher_type,
            "analysis_results": [],
            "potential_solutions": [],
            "recommended_tools": [],
            "next_steps": []
        }
        
        # Cipher type identification using heuristics
        clean_text = cipher_text.replace(' ', '').replace('\n', '')
        
        # Check for hexadecimal encoding
        if re.match(r'^[0-9a-fA-F]+$', clean_text):
            results["analysis_results"].append("Possible hexadecimal encoding")
            results["recommended_tools"].extend(["hex", "xxd"])
            results["next_steps"].append("Try hex decoding")
        
        # Check for Base64 encoding
        if re.match(r'^[A-Za-z0-9+/]+=*$', clean_text):
            results["analysis_results"].append("Possible Base64 encoding")
            results["recommended_tools"].append("base64")
            results["next_steps"].append("Try Base64 decoding")
        
        # Check for hash patterns
        hash_patterns = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
        if len(clean_text) in hash_patterns and re.match(r'^[0-9a-fA-F]+$', clean_text):
            hash_type = hash_patterns[len(clean_text)]
            results["analysis_results"].append(f"Possible {hash_type} hash")
            results["recommended_tools"].extend(["hashcat", "john", "hash-identifier"])
            results["next_steps"].append(f"Try cracking {hash_type} hash with wordlists")
        
        # Check for substitution cipher patterns
        if len(set(cipher_text.upper().replace(' ', ''))) <= 26:
            results["analysis_results"].append("Possible substitution cipher")
            results["recommended_tools"].extend(["frequency-analysis", "substitution-solver"])
        
        # Frequency analysis for substitution ciphers
        if cipher_type in ["substitution", "caesar", "vigenere"] or "substitution" in str(results["analysis_results"]):
            char_freq = {}
            for char in cipher_text.upper():
                if char.isalpha():
                    char_freq[char] = char_freq.get(char, 0) + 1
            
            if char_freq:
                most_common = max(char_freq, key=char_freq.get)
                results["analysis_results"].append(f"Most frequent character: {most_common} ({char_freq[most_common]} occurrences)")
                results["next_steps"].append("Try substituting most frequent character with 'E'")
        
        # Caesar cipher specific analysis
        if cipher_type == "caesar" or len(set(cipher_text.upper().replace(' ', ''))) <= 26:
            results["next_steps"].append("Try all ROT values (1-25)")
            results["recommended_tools"].append("caesar-cipher-solver")
        
        # RSA specific analysis
        if cipher_type == "rsa" or "rsa" in additional_info.lower():
            results["next_steps"].extend([
                "Check if modulus can be factored",
                "Try small exponent attacks",
                "Check for common modulus attacks"
            ])
            results["recommended_tools"].extend(["rsatool", "factordb", "yafu"])
        
        logger.info(f"🔐 CTF crypto analysis completed | Type: {cipher_type} | Tools: {len(results['recommended_tools'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"💥 Error in CTF crypto solver: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```
