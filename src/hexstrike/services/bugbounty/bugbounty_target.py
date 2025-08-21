"""
Bug bounty target data structures.

This module changes when target information structure changes.
"""

from typing import List
from dataclasses import dataclass

@dataclass
class BugBountyTarget:
    """Bug bounty target information"""
    domain: str
    scope: List[str]
    out_of_scope: List[str] = None
    program_type: str = "web"
    bounty_range: str = "unknown"
    technologies: List[str] = None
    priority_vulns: List[str] = None
