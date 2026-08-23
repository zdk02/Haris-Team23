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
  * MINIMIZE WHAT IT HOLDS — every record stores a SHA-256 reference to the original
    message, never the original itself. A BLOCKED message keeps nothing but that hash:
    content Haris refused to deliver is never retained, whatever the settings. For messages
    that WERE delivered, `store_delivered_content` (OFF by default) keeps the delivered form
    — the post-redaction text for a REDACT, the original for an ALLOW — so a demo dashboard
    can show what actually reached the receiver. It is opt-in: by default the log retains
    only hashes + metadata, and a deployment has to ask for content explicitly.
  * APPEND-ONLY + TAMPER-EVIDENT — every record carries the hash of the previous record
    (`prev_hash`) and a hash over itself (`entry_hash`), forming a chain. With
    `HARIS_AUDIT_KEY` set the link is an HMAC, so an attacker who can write the log cannot
    recompute it: editing a record, rewriting the whole file, and appending a forged entry
    all fail `verify_chain()`. WITHOUT a key it degrades to a plain hash chain — evidence
    of accidental corruption, not of a deliberate rewrite. TRUNCATION is different again:
    dropping records off the END leaves a shorter but internally-consistent chain, so it is
    caught only by comparing against a head hash held OUTSIDE this log (`head()`, then
    `verify_chain(expected_head=..., expected_count=...)`). And an attacker with code
    execution in the Haris process can read the key — this resists offline tampering, not
    process compromise. A WORM store or external anchoring is the roadmap.
  * DURABLE (optional) — pass `path=` and each record is also appended to a JSONL file as
    it is written (append-only on disk). `load_jsonl()` reads it back and re-verifies.

Access to read the log is controlled at the surface that exposes it (the dashboard's
operator gate). Full cryptographic signing / a WORM store is the deployment-era roadmap;
the hash chain is the honest MVP of the same property.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import logging
import threading
from dataclasses import asdict, dataclass
from typing import Optional

from haris.schemas.decision import Action, Decision
from haris.schemas.message import Message


# Checkpoints go to the OPERATIONAL log stream, deliberately NOT to the audit log itself.
# That separation is the whole point: an attacker who can truncate the audit file cannot
# also reach the operator's log destination (CloudWatch, syslog, an SIEM), so the reference
# survives to be compared against.
# NOTE the logger NAME. `haris.*` is the operational tier (haris/logging_config.py,
# OPERATIONAL_LOGGER = "haris"), which `configure_logging()` sets up and an entry point
# calls. A checkpoint on a logger outside that tree, or below the configured level, is
# emitted into nothing -- which is what happened on the first attempt at this: the messages
# were produced, no handler existed, and THREAT_MODEL.md claimed a destination that did not
# exist. Verify with `python -m demo_app.hospital.haris_pipeline`, not by reading the code.
_checkpoint_logger = logging.getLogger("haris.audit.checkpoint")


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()

def _audit_key() -> bytes:
    """The chain key. Set HARIS_AUDIT_KEY in the environment to make the chain KEYED."""
    return os.environ.get("HARIS_AUDIT_KEY", "").encode("utf-8")

def _entry_hash(fields: dict, prev_hash: str, key: bytes = b"") -> str:
    """Chain link: a hash over this record's fields plus the previous entry's hash.
    Canonical (sorted keys) so the same record always hashes the same way.

    KEYED (HMAC) when a key is configured: an attacker who can write the log cannot
    recompute the chain without it, so silent rewrite and forged append are both
    detectable. Unkeyed it degrades to a plain SHA-256 chain, which is evidence of
    accidental corruption but not of a deliberate rewrite."""
    payload = json.dumps({**fields, "prev_hash": prev_hash}, sort_keys=True, default=str)
    data = payload.encode("utf-8")
    return (hmac.new(key, data, hashlib.sha256).hexdigest() if key
            else hashlib.sha256(data).hexdigest())

def _last_entry_hash(path: str) -> str:
    """entry_hash of the last record already on disk, or "" if the file is empty."""
    last = ""
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                last = line
    return json.loads(last)["entry_hash"] if last else ""


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

    def __init__(self, store_delivered_content: bool = False,
                 path: Optional[str] = None,
                 key: Optional[bytes] = None,
                 checkpoint_every: int = 100) -> None:
        self._records: list[AuditRecord] = []
        self.store_delivered_content = store_delivered_content
        # If set, each record is also appended to this JSONL file as it is written.
        self.path = path
        self._key = _audit_key() if key is None else key
        # Appending to an existing file must CONTINUE its chain. Without this, the first
        # record written after every restart carries prev_hash="" and the chain is broken
        # permanently — making a persisted audit log unverifiable after a single restart.
        self._prev_hash = _last_entry_hash(path) if path and os.path.exists(path) else ""
        # record() is a read-modify-append across _records and the file. Without a lock,
        # two threads can read the same tip, both link to it, and the chain forks.
        self._lock = threading.Lock()
        # How often to emit (head, count) to the operational log. Truncation leaves a
        # shorter but internally-consistent chain, so it is detectable ONLY against a
        # reference held outside this log -- see checkpoint(). 0 disables emission; the
        # method stays available for a deployment that persists it another way.
        self.checkpoint_every = checkpoint_every
        

    def record(self, message: Message, decision: Decision, latency_ms: float) -> AuditRecord:
        md = message.metadata or {}
        # What the receiver actually got. A BLOCKED message was never delivered, so the
        # log keeps only its hash reference - content Haris refused to pass on is never
        # retained. (The engine only yields BLOCK in enforce mode; monitor clamps it to
        # FLAG in policy/engine._apply_mode, so this can't discard a delivered message.)
        if decision.action is Action.BLOCK:
            delivered = None
        elif decision.final_content is not None:
            delivered = decision.final_content      # REDACT - the scrubbed form
        else:
            delivered = message.content             # ALLOW / LOG / FLAG - delivered as-is
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
        with self._lock:
            prev = self._records[-1].entry_hash if self._records else self._prev_hash
            entry = _entry_hash(fields, prev, self._key)
            rec = AuditRecord(**fields, prev_hash=prev, entry_hash=entry)
            self._records.append(rec)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec.as_dict()) + "\n")
            count = len(self._records)
            due = self.checkpoint_every and count % self.checkpoint_every == 0
            cp = {"head": rec.entry_hash, "count": count} if due else None
        # Emitted OUTSIDE the lock: logging can block on I/O and the chain must not wait.
        if cp is not None:
            self._emit_checkpoint(cp)
        return rec

    def checkpoint(self) -> dict:
        """The two values truncation detection needs: the chain's tip and its length.

        Store this somewhere the audit log's writer cannot reach. Dropping records off the
        END leaves a chain that still verifies internally, so no check inside the file can
        reveal the loss -- only a comparison against an outside reference can.
        """
        with self._lock:
            return {"head": self.head(), "count": len(self._records)}

    def _emit_checkpoint(self, cp: dict) -> None:
        _checkpoint_logger.info("HARIS audit checkpoint | count=%d | head=%s",
                                cp["count"], cp["head"])

    def verify_checkpoint(self, cp: dict) -> bool:
        """Verify the chain against a checkpoint taken earlier and held elsewhere."""
        return self.verify_chain(expected_head=cp.get("head"),
                                 expected_count=cp.get("count"))

    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def head(self) -> str:
        """The chain's current tip — the last record's entry_hash.

        Store this OUTSIDE the log's own storage. Comparing against it is the ONLY way to
        detect TRUNCATION: dropping records off the end leaves a shorter chain that is
        still internally consistent, so no check inside the file can reveal the loss."""
        return self._records[-1].entry_hash if self._records else self._prev_hash
    
    def verify_chain(self, expected_head: Optional[str] = None,
                     expected_count: Optional[int] = None) -> bool:
        """True iff the chain is intact — no record edited, reordered, or removed from the
        middle. Pass expected_head / expected_count (held outside this log) to also detect
        TRUNCATION, which an internal check cannot see."""
        prev = self._prev_hash
        for rec in self._records:
            if rec.prev_hash != prev:
                return False
            if _entry_hash(rec._fields(), prev, self._key) != rec.entry_hash:
                return False
            prev = rec.entry_hash
        if expected_head is not None and prev != expected_head:
            return False
        if expected_count is not None and len(self._records) != expected_count:
            return False
        return True

    @classmethod
    def load_jsonl(cls, path: str, key: Optional[bytes] = None) -> "AuditLog":
        """Load a persisted audit log from its JSONL file. The caller can then call
        verify_chain() to confirm the file hasn't been tampered with on disk."""
        log = cls(path=None, key=key)
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    log._records.append(AuditRecord(**json.loads(line)))
        return log

    def __len__(self) -> int:
        return len(self._records)