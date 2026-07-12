"""FROZEN CONTRACT: Decision + enforcement outcome.

Agents produce Verdicts (opinions). The policy engine resolves N verdicts into
exactly one Decision (an outcome). The orchestrator acts on the Decision.

Note: Verdict.label has no `redact` value. An agent asks for redaction by
setting `redacted_content` on its Verdict.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from haris.schemas.verdict import Verdict


class Action(str, Enum):
    """The single outcome for one message."""
    ALLOW = "allow"      # deliver unchanged
    LOG = "log"          # deliver unchanged, record it
    FLAG = "flag"        # deliver unchanged, record it, surface on dashboard
    REDACT = "redact"    # deliver Decision.final_content instead of the original
    BLOCK = "block"      # do not deliver


# Precedence: least -> most restrictive. Most restrictive wins.
ACTION_PRECEDENCE: list[Action] = [
    Action.ALLOW,
    Action.LOG,
    Action.FLAG,
    Action.REDACT,
    Action.BLOCK,
]


def rank(action: Action) -> int:
    """Position in the precedence order. Higher = more restrictive."""
    return ACTION_PRECEDENCE.index(action)


def most_restrictive(actions: list[Action]) -> Action:
    if not actions:
        return Action.ALLOW
    return max(actions, key=rank)


class Decision(BaseModel):
    """What the orchestrator was told to do, and why."""
    action: Action
    final_content: Optional[str] = None                    # set when action is REDACT
    verdicts: list[Verdict] = Field(default_factory=list)  # the evidence
    reason: str = ""
    enforced: bool = False   # False in monitor mode: decided, but not applied


class HarisBlocked(Exception):
    """Raised to the SENDER when a message is blocked in enforce mode."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason or "blocked by Haris")
        self.decision = decision