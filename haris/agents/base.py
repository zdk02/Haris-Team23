"""FROZEN CONTRACT: SecurityAgent interface.

All three MVP agents (Secrets & PII, Authorization, Information-flow) implement
this. Frozen.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from haris.schemas.message import Message
from haris.schemas.verdict import Verdict


class SecurityAgent(ABC):
    name: str = "base"

    @abstractmethod
    def check(self, message: Message, context: dict[str, Any]) -> Verdict:
        """Inspect a message given context and return a Verdict."""
        raise NotImplementedError
