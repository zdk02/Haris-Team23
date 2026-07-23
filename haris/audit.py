"""Security audit log — Haris's durable, app-agnostic record of every decision.

For a security tool the audit trail is half the product (the mentor's non-functional
note): you must be able to inspect, after the fact, who sent what to whom, what every
agent decided, and why. This log is that record, and it is deliberately GENERIC — it
stores session / sender / receiver / data_type / the per-agent verdicts / the final
action / latency / a content REFERENCE. Nothing here is hospital-specific, so it works
for ANY multi-agent app Haris protects; the hospital demo is just one producer.

Hardening ("how do you protect Haris itself?"): the log stores a SHA-256 hash of the
message content, not the raw content — so a breach of the log yields hashes, not raw
secrets. `store_delivered_content` keeps the delivered (post-redaction) form for the demo
dashboard; flip it off for a hardened deployment that retains only hashes + metadata.

Append-only by construction: `record()` appends, `records()` returns a copy, and there is
no update or delete. A real deployment swaps the in-memory list for a durable, tamper-
evident sink behind the same interface.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Optional

from haris.schemas.decision import Decision
from haris.schemas.message import Message


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    timestamp: str
    session_id: str
    sender: str
    receiver: str
    data_type: Optional[str]
    data_subject: Optional[str]
    recipient: Optional[str]
    action: str
    enforced: bool
    latency_ms: float
    verdicts: list[dict]          # {agent, label, score, reason, redacts}
    reason: str
    content_sha256: str           # reference to the original content, never the raw bytes
    delivered_content: Optional[str]   # sanitized/delivered form, or None if not retained

    def as_dict(self) -> dict:
        return asdict(self)


class AuditLog:
    """Append-only, app-agnostic decision log written by the Orchestrator."""

    def __init__(self, store_delivered_content: bool = True) -> None:
        self._records: list[AuditRecord] = []
        self.store_delivered_content = store_delivered_content

    def record(self, message: Message, decision: Decision, latency_ms: float) -> AuditRecord:
        md = message.metadata or {}
        delivered = (decision.final_content
                     if decision.final_content is not None else message.content)
        rec = AuditRecord(
            timestamp=message.timestamp.isoformat(),
            session_id=message.session_id,
            sender=message.sender,
            receiver=message.receiver,
            data_type=md.get("data_type"),
            data_subject=md.get("data_subject"),
            recipient=md.get("recipient"),
            action=decision.action.value,
            enforced=bool(decision.enforced),
            latency_ms=round(latency_ms, 3),
            verdicts=[{"agent": v.agent_name, "label": v.label.value,
                       "score": round(float(v.score), 3), "reason": v.reason,
                       "redacts": v.redacted_content is not None}
                      for v in decision.verdicts],
            reason=decision.reason,
            content_sha256=_sha256(message.content),
            delivered_content=(delivered if self.store_delivered_content else None),
        )
        self._records.append(rec)
        return rec

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)
