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
    # RESERVED, NOT ENFORCED. Nothing reads this field: haris/policy/engine.py consults
    # only `mode` and `thresholds`, and the relationship allow-list lives on
    # AuthorizationAgent(rules=..., default_allow=...) instead. Left in place because it is
    # part of the frozen contract, but it does NOT make the system default-deny -- see
    # THREAT_MODEL.md section 9, which used to claim otherwise.
    default_action: Action = Action.BLOCK