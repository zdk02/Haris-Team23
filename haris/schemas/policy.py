"""FROZEN CONTRACT: Policy schema.

Relationship rules + thresholds + mode. `data_subject` is included now so
subject-aware authorization (patient-A vs patient-B) is not designed out --
you do not have to use it yet.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Mode(str, Enum):
    MONITOR = "monitor"   # log + flag only, never block (Phase 0 default)
    ENFORCE = "enforce"   # allowed to block; turn on later


class PolicyRule(BaseModel):
    sender: str
    receiver: str
    data_type: str
    action: str                         # e.g. "allow" | "deny" | "redact"
    data_subject: Optional[str] = None  # reserved for subject-aware authz


class Policy(BaseModel):
    rules: list[PolicyRule] = Field(default_factory=list)
    thresholds: dict[str, float] = Field(default_factory=dict)
    mode: Mode = Mode.MONITOR
