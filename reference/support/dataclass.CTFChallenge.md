---
title: dataclass.CTFChallenge
kind: dataclass
module: __main__
line_range: [2783, 2793]
discovered_in_chunk: 2
---

# CTFChallenge Dataclass

## Entity Classification & Context
- **Kind:** Dataclass
- **Scope:** Module-level
- **Module:** __main__ (reference-server.py)
- **Decorators:** @dataclass

## Complete Signature & Definition
```python
@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str  # web, crypto, pwn, forensics, rev, misc, osint
    description: str
    points: int = 0
    difficulty: str = "unknown"  # easy, medium, hard, insane
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)
```

## Purpose & Behavior
Comprehensive data structure for CTF (Capture The Flag) challenge information with:
- **Challenge Identification:** Name, category, and description
- **Scoring Information:** Points and difficulty classification
- **Resource Management:** Associated files and URLs
- **Assistance System:** Hints and guidance for solving

## Dependencies & Usage
- **Depends on:**
  - dataclasses.dataclass, field
  - typing.List
- **Used by:**
  - CTFWorkflowManager for challenge management
  - CTF competition automation systems
  - Challenge tracking and scoring systems

## Implementation Details

### Key Fields
- **name:** Challenge identifier and title
- **category:** Challenge type classification
- **description:** Detailed challenge description
- **points:** Scoring value (default: 0)
- **difficulty:** Complexity level (default: "unknown")
- **files:** Associated challenge files (default: empty list)
- **url:** Challenge URL if web-based (default: empty)
- **hints:** Available hints for solving (default: empty list)

### Category Classifications
- **web:** Web application security challenges
- **crypto:** Cryptography and encryption challenges
- **pwn:** Binary exploitation and reverse engineering
- **forensics:** Digital forensics and analysis
- **rev:** Reverse engineering challenges
- **misc:** Miscellaneous and mixed-category challenges
- **osint:** Open source intelligence gathering

### Difficulty Levels
- **easy:** Beginner-friendly challenges
- **medium:** Intermediate complexity
- **hard:** Advanced challenges requiring expertise
- **insane:** Expert-level challenges with extreme difficulty
- **unknown:** Unclassified difficulty (default)

## Testing & Validation
- Field validation and type checking
- Category classification accuracy
- Difficulty level consistency
- File and URL accessibility validation

## Code Reproduction
```python
@dataclass
class CTFChallenge:
    """CTF challenge information"""
    name: str
    category: str  # web, crypto, pwn, forensics, rev, misc, osint
    description: str
    points: int = 0
    difficulty: str = "unknown"  # easy, medium, hard, insane
    files: List[str] = field(default_factory=list)
    url: str = ""
    hints: List[str] = field(default_factory=list)
```
