"""FROZEN CONTRACT: StateStore interface.

Person B builds the real version; the in-memory one (memory.py) unblocks
everyone else in the meantime. Frozen.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from haris.schemas.message import Message


class StateStore(ABC):
    @abstractmethod
    def get_context(self, session_id: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def record_flow(self, message: Message) -> None:
        ...

    @abstractmethod
    def get_lineage(self, session_id: str) -> list[Message]:
        ...
