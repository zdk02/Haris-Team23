"""Interception adapter: the seam between the host agent app and Haris.

Every inter-agent message is built into a Message and routed through the
orchestrator. Returns whatever the orchestrator returns (unchanged in Phase 0).
"""
from __future__ import annotations

from typing import Any, Optional

from haris.orchestrator.orchestrator import Orchestrator
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
    ) -> Message:
        message = Message(
            session_id=session_id,
            sender=sender,
            receiver=receiver,
            content=content,
            metadata=metadata or {},
        )
        return self.orchestrator.process(message)
