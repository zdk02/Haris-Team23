"""FROZEN CONTRACT: Message schema.

Every message that moves through Haris is one of these. Do not change fields
without telling your teammate.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Message(BaseModel):
    session_id: str
    sender: str
    receiver: str
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
