"""Throwaway in-memory StateStore so nobody waits on the real store."""
from __future__ import annotations

from typing import Any

from haris.schemas.message import Message
from haris.state.base import StateStore


class InMemoryStateStore(StateStore):
    def __init__(self) -> None:
        self._flows: dict[str, list[Message]] = {}

    def get_context(self, session_id: str) -> dict[str, Any]:
        return {"history": list(self._flows.get(session_id, []))}

    def record_flow(self, message: Message) -> None:
        self._flows.setdefault(message.session_id, []).append(message)

    def get_lineage(self, session_id: str) -> list[Message]:
        return list(self._flows.get(session_id, []))
