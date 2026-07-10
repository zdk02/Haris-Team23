"""Interception adapter: the seam between the host agent app and Haris.

Builds a Message, sends it through the orchestrator, and unwraps the Decision
into the content that should actually be delivered.

  allow / log / flag -> original content
  redact             -> Decision.final_content
  block (enforce)    -> HarisBlocked propagates to the sender
"""
from __future__ import annotations

from typing import Any, Optional

from haris.orchestrator.orchestrator import Orchestrator
from haris.schemas.decision import Action, Decision
from haris.schemas.message import Message


class InterceptionAdapter:
    def __init__(self, orchestrator: Orchestrator) -> None:
        self.orchestrator = orchestrator

    def intercept(
        self,
        session_id: str,
        sender: str,
        receiver: str,
        content: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[str, Decision]:
        """Return the content to deliver, plus the Decision that produced it."""
        message = Message(
            session_id=session_id,
            sender=sender,
            receiver=receiver,
            content=content,
            metadata=metadata or {},
        )
        decision = self.orchestrator.process(message)  # may raise HarisBlocked

        if decision.action is Action.REDACT and decision.final_content is not None:
            return decision.final_content, decision
        return message.content, decision