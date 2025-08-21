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
    out_of_scope: List[str]
    program_type: str
    bounty_range: str
    technologies: List[str]
