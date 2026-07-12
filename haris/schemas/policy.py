"""FROZEN CONTRACT: Policy schema.

Relationship rules + thresholds + mode + the default when no rule matches.
`data_subject` is reserved for subject-aware authorization (patient-A vs
patient-B); it is not used yet.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from haris.schemas.decision import Action

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
    default_action: Action = Action.BLOCK   # default-deny: no matching rule => block

