"""FROZEN CONTRACT: Verdict schema.

What every SecurityAgent returns from check(). Frozen.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class Label(str, Enum):
    PASS = "pass"
    FLAG = "flag"
    BLOCK = "block"


class Verdict(BaseModel):
    agent_name: str
    label: Label
    score: float = 0.0
    reason: str = ""
    redacted_content: Optional[str] = None
