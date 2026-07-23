"""Tier 2 — the security audit log: Haris's durable, app-agnostic, tamper-evident record
of every decision.

For a security tool the audit trail is half the product (the mentor's non-functional
note): you must be able to inspect, after the fact, who sent what to whom, what every
agent decided, and why. This log is that record, and it is deliberately GENERIC — it
stores session / sender / receiver / data_type / the per-agent verdicts / the final
action / latency / a content REFERENCE. Nothing here is hospital-specific, so it works
for ANY multi-agent app Haris protects; the hospital demo is just one producer.

This is the SECURITY tier. The separate OPERATIONAL tier (errors, health, lifecycle) is
`haris/logging_config.py`; that one is for operators debugging Haris and logs only
metadata, never message bodies.

How this tier is protected (the mentor's "how do you protect Haris itself?"):
  * MINIMIZE WHAT IT HOLDS — it stores a SHA-256 hash of the message content, not the raw
    content, so a breach of the log yields hashes, not raw secrets. `store_delivered_content`
    keeps the delivered (post-redaction) form for the demo dashboard; flip it off for a
    hardened deployment that retains only hashes + metadata.
  * APPEND-ONLY + TAMPER-EVIDENT — every record carries the hash of the previous record
    (`prev_hash`) and a hash over itself (`entry_hash`), forming a chain. Editing or
    deleting any record breaks the chain, which `verify_chain()` detects — so an attacker
    who reaches the log can't quietly alter or erase their tracks without it showing.
  * DURABLE (optional) — pass `path=` and each record is also appended to a JSONL file as
    it is written (append-only on disk). `load_jsonl()` reads it back and re-verifies.

Access to read the log is controlled at the surface that exposes it (the dashboard's
operator gate). Full cryptographic signing / a WORM store is the deployment-era roadmap;
the hash chain is the honest MVP of the same property.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Optional

from haris.schemas.decision import Decision
from haris.schemas.message import Message


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _entry_hash(fields: dict, prev_hash: str) -> str:
    """Hash over a record's content fields plus the previous entry's hash — the chain link.
    Canonical (sorted keys) so the same record always hashes the same way."""
    payload = json.dumps({**fields, "prev_hash": prev_hash}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# The record's own semantic fields (everything except the two chain fields), in order.
_FIELD_KEYS = (
    "timestamp", "session_id", "sender", "receiver", "data_type", "data_subject",
    "recipient", "action", "enforced", "latency_ms", "verdicts", "reason",
    "content_sha256", "delivered_content",
)


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
    prev_hash: str = ""           # entry_hash of the previous record ("" for the first)
    entry_hash: str = ""          # hash over this record's fields + prev_hash (chain link)

    def as_dict(self) -> dict:
        return asdict(self)

    def _fields(self) -> dict:
        d = asdict(self)
        return {k: d[k] for k in _FIELD_KEYS}


class AuditLog:
    """Append-only, tamper-evident, app-agnostic decision log written by the Orchestrator."""

    def __init__(self, store_delivered_content: bool = True,
                 path: Optional[str] = None) -> None:
        self._records: list[AuditRecord] = []
        self.store_delivered_content = store_delivered_content
        # If set, each record is also appended to this JSONL file as it is written.
        self.path = path

    def record(self, message: Message, decision: Decision, latency_ms: float) -> AuditRecord:
        md = message.metadata or {}
        delivered = (decision.final_content
                     if decision.final_content is not None else message.content)
        fields = {
            "timestamp": message.timestamp.isoformat(),
            "session_id": message.session_id,
            "sender": message.sender,
            "receiver": message.receiver,
            "data_type": md.get("data_type"),
            "data_subject": md.get("data_subject"),
            "recipient": md.get("recipient"),
            "action": decision.action.value,
            "enforced": bool(decision.enforced),
            "latency_ms": round(latency_ms, 3),
            "verdicts": [{"agent": v.agent_name, "label": v.label.value,
                          "score": round(float(v.score), 3), "reason": v.reason,
                          "redacts": v.redacted_content is not None}
                         for v in decision.verdicts],
            "reason": decision.reason,
            "content_sha256": _sha256(message.content),
            "delivered_content": (delivered if self.store_delivered_content else None),
        }
        prev = self._records[-1].entry_hash if self._records else ""
        entry = _entry_hash(fields, prev)
        rec = AuditRecord(**fields, prev_hash=prev, entry_hash=entry)
        self._records.append(rec)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec.as_dict()) + "\n")
        return rec

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def verify_chain(self) -> bool:
        """True iff the hash chain is intact — no record has been edited, reordered, or
        deleted since it was written. Recomputes each link and checks it matches."""
        prev = ""
        for rec in self._records:
            if rec.prev_hash != prev:
                return False
            if _entry_hash(rec._fields(), prev) != rec.entry_hash:
                return False
            prev = rec.entry_hash
        return True

    @classmethod
    def load_jsonl(cls, path: str) -> "AuditLog":
        """Load a persisted audit log from its JSONL file. The caller can then call
        verify_chain() to confirm the file hasn't been tampered with on disk."""
        log = cls(path=None)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    log._records.append(AuditRecord(**json.loads(line)))
        return log

    def __len__(self) -> int:
        return len(self._records)
